"""Device discovery: ARP table for MAC addresses, reverse DNS / NetBIOS / mDNS for names,
OUI prefixes for the maker, and a device-type guess (PC, phone, equipment...)."""
import random
import re
import socket
import struct
import threading
import time

from . import dnslib
from .util import run, now, norm_mac, mac_is_random

ARP_RE = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\S+)", re.M)

PHONE_WORDS = ("iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "xiaomi", "redmi", "huawei", "oppo",
               "vivo", "moto", "phone", "tablet", "tablette", "watch", "sm-")
PC_WORDS = ("macbook", "imac", "mac-", "desktop", "laptop", "portable", "pc-", "-pc", "win", "thinkpad",
            "latitude", "optiplex", "surface", "notebook", "srv")
EQUIP_VENDORS = ("brother", "canon", "epson", "zebra", "hikvision", "dahua", "lorex", "raspberry", "espressif",
                 "sonos", "axis", "honeywell", "lexmark", "xerox", "ricoh", "konica", "kyocera", "symbol")
NET_VENDORS = ("ubiquiti", "tp-link", "netgear", "cisco", "meraki", "aruba", "mikrotik", "d-link", "juniper",
               "fortinet", "zyxel", "asustek", "linksys", "bell", "videotron", "hitron", "sagemcom", "technicolor")
PHONE_VENDORS = ("samsung", "google", "xiaomi", "huawei", "oneplus", "motorola", "lg electronics", "oppo", "vivo",
                 "sony mobile", "htc", "zte", "tcl", "nokia", "fairphone")
PC_VENDORS = ("dell", "hewlett", "hp inc", "lenovo", "intel", "microsoft", "vmware", "acer", "micro-star",
              "gigabyte", "asrock", "toshiba", "fujitsu", "realtek", "azurewave", "liteon", "rivet", "framework")


def guess_kind(dev):
    if dev.get("agent_seen"):
        return "pc"
    h = (dev.get("hostname") or "").lower()
    v = (dev.get("vendor") or "").lower()
    mac = dev.get("mac") or ""
    if any(w in h for w in PHONE_WORDS):
        return "phone"
    if any(w in h for w in PC_WORDS):
        return "pc"
    if v:
        if any(w in v for w in EQUIP_VENDORS):
            return "equipment"
        if any(w in v for w in NET_VENDORS):
            return "network"
        if any(w in v for w in PHONE_VENDORS):
            return "phone"
        if "apple" in v:
            return "phone"
        if any(w in v for w in PC_VENDORS):
            return "pc"
    if mac and mac_is_random(mac):
        return "phone"
    return "unknown"


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def netbios_name(ip, timeout=1.0):
    """NBSTAT query (UDP 137): the computer name of a Windows PC, '' when it does not answer."""
    enc = "".join(chr(((b >> 4) & 0xF) + 0x41) + chr((b & 0xF) + 0x41) for b in b"*" + b"\x00" * 15)
    pkt = (struct.pack("!HHHHHH", random.randint(0, 65535), 0, 1, 0, 0, 0) + bytes([32]) + enc.encode("ascii")
           + b"\x00" + struct.pack("!HH", 0x21, 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(1024)
    except OSError:
        return ""
    finally:
        s.close()
    try:
        _, recs = dnslib.parse_records(data)
        for _, rtype, _, _, off, rdlen, _ in recs:
            if rtype != 0x21:
                continue
            n = data[off]
            p = off + 1
            for _ in range(n):
                entry = data[p:p + 18]
                p += 18
                if len(entry) < 18:
                    break
                flags = struct.unpack("!H", entry[16:18])[0]
                if entry[15] == 0x00 and not flags & 0x8000:
                    return entry[:15].decode("ascii", "replace").strip()
    except (dnslib.DnsError, IndexError, struct.error):
        pass
    return ""


def mdns_name(ip, timeout=1.0):
    """Reverse mDNS (unicast-response flag): Apple and Android devices often answer with their name."""
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    q = dnslib.build_query(rev, dnslib.TYPE_PTR, qclass=0x8001, rd=False)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.sendto(q, ("224.0.0.251", 5353))
        end = time.time() + timeout
        while time.time() < end:
            data, addr = s.recvfrom(2048)
            if addr[0] != ip:
                continue
            _, recs = dnslib.parse_records(data)
            for _, rtype, _, _, off, _, section in recs:
                if rtype == dnslib.TYPE_PTR and section == 0:
                    target = dnslib.parse_name(data, off)[0]
                    return target[:-6] if target.endswith(".local") else target
    except (OSError, dnslib.DnsError):
        pass
    finally:
        s.close()
    return ""


def resolve_name(ip):
    for fn in (reverse_dns, netbios_name, mdns_name):
        name = fn(ip)
        if name:
            return name
    return ""


class DeviceTracker(threading.Thread):
    def __init__(self, store, log, arp_interval=60, name_interval=300):
        super().__init__(name="nw-devices", daemon=True)
        self.store = store
        self.log = log
        self.arp_interval = arp_interval
        self.name_interval = name_interval
        self._stop = threading.Event()
        self.last_names = 0
        self.arp_entries = 0

    def stop(self):
        self._stop.set()

    def run(self):
        self._stop.wait(5)
        while not self._stop.is_set():
            try:
                self.refresh_arp()
            except Exception as e:
                self.log("warn", f"Lecture ARP : {e}")
            if time.time() - self.last_names >= self.name_interval:
                self.last_names = time.time()
                try:
                    self.resolve_some()
                except Exception as e:
                    self.log("warn", f"Résolution des noms : {e}")
            self._stop.wait(self.arp_interval)

    def refresh_arp(self):
        out = run(["arp", "-a"])
        n = 0
        for ip, mac, _ in ARP_RE.findall(out):
            mac = norm_mac(mac)
            if not mac or mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e") or ip.startswith("224.") \
                    or ip.endswith(".255") or ip.startswith("239."):
                continue
            self.store.set_mac(ip, mac)
            n += 1
        self.arp_entries = n

    def resolve_some(self, limit=10):
        for d in self.store.devices_needing_names(limit=limit):
            self.resolve_device(d)

    def resolve_device(self, d):
        fields = {"name_checked": now()}
        if not d.get("hostname") and d.get("kind_auto") != "server" and d.get("ip"):
            name = resolve_name(d["ip"])
            if name:
                fields["hostname"] = name.split(".")[0][:80] if not name.replace(".", "").isdigit() else name
        mac = d.get("mac") or ""
        if mac and not d.get("vendor"):
            v = "Adresse privée (aléatoire)" if mac_is_random(mac) else self.store.vendor_of(mac)
            if v:
                fields["vendor"] = v
        merged = {**d, **fields}
        if not d.get("kind") and d.get("kind_auto") != "server":
            fields["kind_auto"] = guess_kind(merged)
        self.store.update_device(d["id"], fields)
