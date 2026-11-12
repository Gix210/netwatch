"""Wires everything together: config, store, classifier, DNS proxy, device tracker,
list updater, notifier and the maintenance thread."""
import os
import secrets
import socket
import threading
import time

from .alerts import Notifier
from .classify import Classifier
from .config import Config
from .devices import DeviceTracker
from .dnsproxy import DnsProxy
from .lists_update import ListUpdater
from .store import Store
from .util import VERSION, app_dir, local_ip, now, day_of, norm_domain, is_valid_domain, system_dns_servers, default_gateway

SEED_ADULT = "Intégré : adulte"
SEED_BYPASS = "Intégré : contournement"
SEED_KEYS = {SEED_ADULT: "seed-adult", SEED_BYPASS: "seed-bypass"}


class App:
    def __init__(self, base_dir=None, config_path=None, data_dir=None, dns_port=None, web_port=None,
                 dns_bind=None, blockpage=None):
        self.base = base_dir or app_dir()
        self.cfg = Config(config_path or os.path.join(self.base, "config.json"))
        self.data_dir = data_dir or os.path.join(self.base, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        if dns_port is not None:
            self.cfg.set(int(dns_port), "dns", "port")
        if dns_bind is not None:
            self.cfg.set(dns_bind, "dns", "bind")
        if web_port is not None:
            self.cfg.set(int(web_port), "web", "port")
        if blockpage is not None:
            self.cfg.set(bool(blockpage), "blockpage", "enabled")
        self.version = VERSION
        self.ip = local_ip()
        self.hostname = socket.gethostname()
        self.started = now()
        self.store = Store(os.path.join(self.data_dir, "netwatch.db"), local_ips={self.ip}, hostname=self.hostname)
        self.log = self.store.log
        self.secret = self._load_secret()
        self._load_seeds()
        self.classifier = Classifier(self.store)
        self.store.on_change = self.classifier.reload
        self.notifier = Notifier(self.cfg, self.store)
        self.proxy = DnsProxy(self.classifier, self.store, self.log, self.on_flag,
                              bind=self.cfg.get("dns", "bind"), port=int(self.cfg.get("dns", "port")))
        self.blockpage_ok = False
        self.apply_dns_config()
        self.tracker = DeviceTracker(self.store, self.log)
        self.updater = ListUpdater(self.cfg, self.store, self.classifier, self.log, self.data_dir)
        self._stop = threading.Event()

    # ---- setup ----------------------------------------------------------------
    def _load_secret(self):
        path = os.path.join(self.data_dir, "secret.key")
        try:
            with open(path, "rb") as f:
                s = f.read()
            if len(s) >= 32:
                return s
        except OSError:
            pass
        s = secrets.token_bytes(32)
        with open(path, "wb") as f:
            f.write(s)
        return s

    def _read_seed(self, name):
        path = os.path.join(self.base, "seeds", name)
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        yield line
        except OSError:
            return

    def _load_seeds(self):
        n = self.store.seed_listed(SEED_KEYS[SEED_ADULT], ((d, "adult") for d in map(norm_domain, self._read_seed("adult.txt")) if is_valid_domain(d)))
        m = self.store.seed_listed(SEED_KEYS[SEED_BYPASS], ((d, "bypass") for d in map(norm_domain, self._read_seed("bypass.txt")) if is_valid_domain(d)))
        if n or m:
            self.store.set_source(SEED_ADULT, "", "seed", status="OK", count=n, touched=True)
            self.store.set_source(SEED_BYPASS, "", "seed", status="OK", count=m, touched=True)
            self.log("info", f"Listes intégrées chargées : {n} domaines adultes, {m} domaines de contournement")
        if self.store.get_setting("keywords") is None:
            self.store.set_setting("keywords", list(self._read_seed("keywords.txt")))
        if self.store.oui_count() == 0:
            from .lists_update import iter_oui
            path = os.path.join(self.base, "seeds", "oui.csv")
            if os.path.exists(path):
                self.store.replace_oui(iter_oui(path))

    def upstreams(self):
        ups = [u for u in (self.cfg.get("dns", "upstreams") or []) if u]
        if ups:
            return ups
        auto = [ip for ip in system_dns_servers() if ip != self.ip]
        if not auto:
            gw = default_gateway()
            if gw:
                auto = [gw]
        if "1.1.1.1" not in auto:
            auto.append("1.1.1.1")
        return auto

    def effective_block_ip(self):
        b = (self.cfg.get("block_ip") or "auto").strip()
        if b and b != "auto":
            return b
        return self.ip if self.blockpage_ok else "0.0.0.0"

    def apply_dns_config(self):
        self.proxy.configure(upstreams=self.upstreams(), timeout=self.cfg.get("dns", "upstream_timeout"),
                             cache_max=self.cfg.get("dns", "cache_max"), log_local=self.cfg.get("dns", "log_local"),
                             block_ip=self.effective_block_ip())

    # ---- runtime ------------------------------------------------------------------
    def start(self):
        self.log("info", f"NetWatch {self.version} démarre sur {self.hostname} ({self.ip})")
        self.proxy.start()
        self.tracker.start()
        threading.Thread(target=self._maintenance, name="nw-maint", daemon=True).start()

    def stop(self):
        self._stop.set()
        self.proxy.stop()
        self.tracker.stop()
        self.updater.stop()
        self.classifier.close()
        self.store.close()

    def on_flag(self, ts, ip, name, qtype, res):
        eid, did = self.store.add_event(ts, ip, name, res["category"], res["action"], qtype, res.get("matched", ""))
        dev = self.store.device(did) or {"id": did, "ip": ip}
        self.notifier.on_event({"id": eid, "ts": ts, "device_id": did, "device": self.store.display_name(dev),
                                "ip": ip, "domain": name, "category": res["category"], "label": res["label"],
                                "action": res["action"]})

    def _maintenance(self):
        last_purge = 0
        last_checkpoint = 0
        while not self._stop.is_set():
            t = now()
            try:
                if t - last_purge > 3600:
                    self.store.purge(int(self.cfg.get("retention_days") or 90))
                    last_purge = t
                if t - last_checkpoint > 6 * 3600:
                    self.store.checkpoint()
                    last_checkpoint = t
                a = self.cfg.get("alerts") or {}
                if a.get("digest_enabled") and self.notifier.enabled():
                    today = day_of(t)
                    if time.localtime(t).tm_hour >= int(a.get("digest_hour") or 7) and self.store.get_setting("digest_day") != today:
                        self.store.set_setting("digest_day", today)
                        yesterday = day_of(t - 86400)
                        err = self.notifier.digest(yesterday)
                        self.log("info" if not err else "error", f"Rapport quotidien du {yesterday} : " + ("envoyé" if not err else err))
            except Exception as e:
                self.log("warn", f"Maintenance : {e}")
            self._stop.wait(300)

    def status(self):
        upd = self.updater.status()
        return {
            "version": self.version, "hostname": self.hostname, "ip": self.ip, "started": self.started,
            "uptime": now() - self.started, "dns": self.proxy.status(), "web_port": self.cfg.get("web", "port"),
            "blockpage": {"enabled": bool(self.cfg.get("blockpage", "enabled")), "port": self.cfg.get("blockpage", "port"),
                          "running": self.blockpage_ok},
            "block_ip": self.effective_block_ip(), "listed": self.store.listed_count(), "oui": self.store.oui_count(),
            "lists_update": upd, "db_size": self.store.db_size(), "arp_entries": self.tracker.arp_entries,
            "password_set": bool(self.cfg.get("web", "password_hash")), "email_enabled": self.notifier.enabled(),
            "site_name": self.cfg.get("site_name"),
        }
