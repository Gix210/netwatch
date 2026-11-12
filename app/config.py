"""config.json loading with defaults. Secrets (SMTP password, agent token) live here too,
like the other tools; the file is never served by the web UI."""
import copy
import json
import os
import secrets
import threading

from .util import app_dir

UT1_URL = "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"
STEVENBLACK_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# UT1 directory name -> NetWatch category key
UT1_MAP = {
    "adult": "adult", "mixed_adult": "mixed_adult", "lingerie": "lingerie",
    "sexual_education": "sexual_education", "dating": "dating", "gambling": "gambling",
    "arjel": "gambling", "drogue": "drogue", "agressif": "agressif",
    "dangerous_material": "dangerous_material", "sect": "sect", "malware": "malware",
    "phishing": "phishing", "cryptojacking": "cryptojacking", "ddos": "ddos",
    "stalkerware": "stalkerware", "hacking": "hacking", "warez": "warez", "doh": "doh",
    "vpn": "vpn", "redirector": "proxy", "residential-proxies": "proxy",
    "social_networks": "social_networks", "audio-video": "audio-video", "games": "games",
}

DEFAULTS = {
    "site_name": "Mon entreprise",
    "contact": "la direction",
    "dns": {
        "bind": "0.0.0.0",
        "port": 53,
        "upstreams": [],            # empty = the DNS servers of this machine, then 1.1.1.1
        "upstream_timeout": 2.5,
        "cache_max": 5000,
        "log_local": False,         # journal .local / .arpa / single-label names
    },
    "web": {"bind": "0.0.0.0", "port": 8795, "password_hash": "", "session_hours": 12},
    "blockpage": {"enabled": True, "port": 80},
    "block_ip": "auto",             # auto = this machine when the block page runs, else 0.0.0.0
    "retention_days": 90,
    "online_minutes": 10,
    "alerts": {
        "email_enabled": False,
        "to": "",
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "cooldown_min": 30,
        "digest_hour": 7,
        "digest_enabled": False,
    },
    "lists": {
        "auto_update_days": 7,
        "sources": [
            {"name": "UT1 Université Toulouse Capitole", "key": "ut1", "type": "ut1", "url": UT1_URL},
            {"name": "StevenBlack porn-only", "key": "sb", "type": "hosts", "url": STEVENBLACK_URL, "category": "adult"},
            {"name": "IEEE OUI (fabricants)", "key": "oui", "type": "oui", "url": OUI_URL},
        ],
    },
    "agent": {"token": ""},
}


def _merge(base, override):
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, path=None):
        self.path = path or os.path.join(app_dir(), "config.json")
        self.lock = threading.RLock()
        self.data = copy.deepcopy(DEFAULTS)
        self.load()

    def load(self):
        raw = {}
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
        with self.lock:
            self.data = _merge(DEFAULTS, raw)
            changed = False
            if not self.data["agent"].get("token"):
                self.data["agent"]["token"] = secrets.token_hex(16)
                changed = True
        if changed:
            self.save()

    def save(self):
        with self.lock:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)

    def get(self, *keys, default=None):
        with self.lock:
            cur = self.data
            for k in keys:
                if not isinstance(cur, dict) or k not in cur:
                    return default
                cur = cur[k]
            return copy.deepcopy(cur)

    def set(self, value, *keys):
        with self.lock:
            cur = self.data
            for k in keys[:-1]:
                cur = cur.setdefault(k, {})
            cur[keys[-1]] = value

    def update(self, patch):
        with self.lock:
            self.data = _merge(self.data, patch)
            self.save()
