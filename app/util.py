"""Small helpers shared by the NetWatch modules (standard library only)."""
import os
import re
import socket
import subprocess
import sys
import time

VERSION = "1.0.0"
IS_WIN = sys.platform.startswith("win")
_CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0


def now():
    return int(time.time())


def day_of(ts=None):
    return time.strftime("%Y-%m-%d", time.localtime(ts if ts is not None else time.time()))


def day_start(day=None):
    """Timestamp of local midnight for a YYYY-MM-DD day (today by default)."""
    day = day or day_of()
    return int(time.mktime(time.strptime(day, "%Y-%m-%d")))


def fmt_ts(ts):
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def local_ip():
    """LAN IPv4 of this machine (the one used to reach the default gateway)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def run(cmd, timeout=20):
    """Run a command without a console window and return its stdout ('' on failure)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=_CREATE_NO_WINDOW, encoding="utf-8", errors="replace")
        return p.stdout or ""
    except Exception:
        return ""


def powershell(script, timeout=30):
    if not IS_WIN:
        return ""
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)


_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def system_dns_servers():
    """DNS servers configured on this machine (IPv4), loopback excluded, order kept."""
    ips = []
    if IS_WIN:
        out = powershell("(Get-DnsClientServerAddress -AddressFamily IPv4 | "
                         "Where-Object { $_.ServerAddresses } | "
                         "Select-Object -ExpandProperty ServerAddresses) -join ','")
        ips = _IPV4.findall(out)
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        ips += _IPV4.findall(line)
        except OSError:
            pass
    out, seen = [], set()
    for ip in ips:
        if ip.startswith("127.") or ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def default_gateway():
    if not IS_WIN:
        return ""
    out = powershell("(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -AddressFamily IPv4 | "
                     "Sort-Object RouteMetric | Select-Object -First 1).NextHop")
    m = _IPV4.search(out)
    return m.group(1) if m else ""


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_-]+(\.[a-z0-9_-]+)*$")


def norm_domain(name):
    name = (name or "").strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return name


def is_valid_domain(name):
    return bool(name) and "." in name and bool(_DOMAIN_RE.match(name))


def norm_mac(mac):
    """Return aa:bb:cc:dd:ee:ff or '' when the text is not a MAC address."""
    s = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(s) != 12:
        return ""
    s = s.lower()
    return ":".join(s[i:i + 2] for i in range(0, 12, 2))


def mac_is_random(mac):
    """Locally administered bit set: a randomized (private) address, typical of phones."""
    try:
        return bool(int(mac[0:2], 16) & 0x02)
    except (ValueError, TypeError):
        return False


def app_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ca_bundle_path():
    return os.path.join(app_dir(), "seeds", "cacert.pem")


def ssl_context():
    """Certificate checks stay on. Trusts the Windows store plus the Mozilla root list shipped in
    seeds/cacert.pem (curl.se): servers like SRV-APP lack newer roots that browsers fetch on demand
    (HARICA for UT1, GlobalSign R46 for IEEE), and Python never triggers that fetch."""
    import ssl
    ctx = ssl.create_default_context()
    path = ca_bundle_path()
    if os.path.exists(path):
        try:
            ctx.load_verify_locations(cafile=path)
        except (ssl.SSLError, OSError):
            pass
    return ctx
