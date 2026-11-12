"""Screenshots for the in-app manual (static/manuel/img/*.png), from a private demo copy of NetWatch.

    python qa/manual_shots.py [--skip-lists]

Demo data only: fictional devices and people, a clock set to 14:30 today so the day looks like a work day.
Nothing touches the real network: no DNS listener on port 53, no device discovery (ARP/NetBIOS probes are off),
upstream DNS pinned to DC01. The demo database is deleted at the end. --skip-lists keeps the 217 built-in
domains instead of downloading the full lists (~50 s, 26 MB)."""
import json
import os
import random
import shutil
import sys
import tempfile
import time
import urllib.request

QA = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(QA)
sys.path.insert(0, BASE)
sys.path.insert(0, QA)
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

IMG = os.path.join(BASE, "static", "manuel", "img")
PASSWORD = "demo-manuel-2026"

# ---- fake clock: 14:30 today ----------------------------------------------------------
_lt = time.localtime()
FAKE_NOW = int(time.mktime((_lt.tm_year, _lt.tm_mon, _lt.tm_mday, 14, 30, 0, 0, 0, -1)))
_OFFSET = FAKE_NOW - time.time()

from app import util  # noqa: E402

def _fake_now():
    return int(time.time() + _OFFSET)

util.now = _fake_now
import app.store, app.web, app.core, app.alerts, app.devices, app.lists_update, app.dnsproxy  # noqa: E402,E401
for _m in (app.store, app.web, app.core, app.alerts, app.devices, app.lists_update, app.dnsproxy):
    if hasattr(_m, "now"):
        _m.now = _fake_now
from app.core import App  # noqa: E402
from app.web import WebServer  # noqa: E402
from cdp import Chrome, free_port  # noqa: E402

PCS = [  # host, user, ip, mac, vendor, through NetWatch, DoH policy
    ("PC-RECEPTION", "accueil", "192.168.1.71", "b8:ca:3a:41:0a:11", "Dell", True, True),
    ("PC-PRODUCTION", "production", "192.168.1.72", "54:bf:64:22:9c:31", "Dell", True, True),
    ("PC-DIRECTION", "direction", "192.168.1.73", "28:d2:44:8e:10:52", "Lenovo", True, True),
    ("PC-EXPEDITION", "expedition", "192.168.1.74", "3c:d9:2b:5f:77:20", "Hewlett Packard", False, False),
]
OTHERS = [  # ip, mac, label, owner, kind, vendor
    ("192.168.1.101", "da:4f:91:2c:7e:03", "iPhone de Marc", "Marc (production)", "phone", "Adresse privée (aléatoire)"),
    ("192.168.1.102", "9e:12:b4:60:aa:5d", "Galaxy de Julie", "Julie (emballage)", "phone", "Adresse privée (aléatoire)"),
    ("192.168.1.103", "7a:c3:0e:91:42:b8", "", "", "phone", "Adresse privée (aléatoire)"),
    ("192.168.1.104", "8c:f5:a3:19:d2:44", "Tablette ligne 1", "Production", "phone", "Samsung Electronics"),
    ("192.168.1.120", "30:05:5c:a1:7b:09", "Imprimante bureau", "", "equipment", "Brother Industries"),
]
WORK = ["www.google.com", "outlook.office365.com", "login.microsoftonline.com", "teams.microsoft.com", "www.dropbox.com",
        "mail.google.com", "www.costco.ca", "meteo.gc.ca", "www.lapresse.ca", "www.amazon.ca", "ctldl.windowsupdate.com",
        "fonts.gstatic.com", "www.gstatic.com", "clients4.google.com", "drive.google.com", "docs.google.com", "www.canadapost-postescanada.ca"]
PHONE = ["www.google.com", "www.instagram.com", "www.facebook.com", "www.youtube.com", "open.spotify.com", "api.weather.com",
         "www.tiktok.com", "graph.facebook.com", "i.ytimg.com", "www.lapresse.ca", "gateway.icloud.com", "play.googleapis.com"]
# (device key, day offset, hour, minute, domain, how many minutes of activity)
FLAGS = [
    ("192.168.1.101", 0, 12, 7, "www.pornhub.com", 9), ("192.168.1.101", 0, 12, 8, "ei.phncdn.com", 8),
    ("192.168.1.101", 0, 9, 2, "mask.icloud.com", 1), ("192.168.1.101", 1, 12, 31, "stake.com", 4),
    ("192.168.1.74", 0, 10, 42, "stake.com", 6), ("192.168.1.74", 0, 13, 15, "suivi-colis-livraison.xyz", 1),
    ("192.168.1.102", 0, 11, 20, "dns.google", 2), ("192.168.1.103", 0, 13, 48, "nordvpn.com", 3),
    ("192.168.1.103", 2, 15, 5, "www.xvideos.com", 5),
]


def day_ts(offset, hour, minute):
    lt = time.localtime(FAKE_NOW - offset * 86400)
    return int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, minute, random.randint(0, 59), 0, 0, -1)))


def build(app, skip_lists):
    st = app.store
    if not skip_lists:
        print("Téléchargement des listes complètes…", flush=True)
        app.updater.run_all()
        print("  ", st.listed_count(), "domaines", flush=True)
    st.add_rule("suivi-colis-livraison.xyz", "phishing", "Courriel suspect reçu à l'expédition")
    st.add_rule("www.fournisseur-exemple.ca", "allow", "Fournisseur")
    app.classifier.reload()
    app.ip, app.hostname = "192.168.1.11", "SRV-APP"   # what the real install shows
    app.cfg.set(8795, "web", "port")
    # PCs with the agent
    for host, user, ip, mac, vendor, via, doh in PCS:
        did = st.agent_heartbeat({"host": host, "user": user, "ip": ip, "mac": mac, "os": "Microsoft Windows 11 Professionnel",
                                  "version": "1.0.0", "doh_policy": doh, "dns": ["192.168.1.11" if via else "192.168.1.10"], "ips": [ip]}, ip)
        st.update_device(did, {"vendor": vendor, "name_checked": FAKE_NOW})
    for ip, mac, label, owner, kind, vendor in OTHERS:
        did = st.device_id_for_ip(ip)
        st.set_mac(ip, mac)
        did = st.device_by_ip(ip)["id"]
        st.update_device(did, {"label": label, "owner": owner, "kind_auto": kind, "vendor": vendor, "name_checked": FAKE_NOW,
                               "ignored": 1 if kind == "equipment" else 0})
    # ordinary traffic, 7 days, office hours (today until 14:25)
    total = 0
    for offset in range(7):
        weekday = time.localtime(FAKE_NOW - offset * 86400).tm_wday
        if weekday >= 5:
            continue
        for host, user, ip, *_ in PCS:
            for dom in random.sample(WORK, 12):
                for _ in range(random.randint(8, 60)):
                    h = random.randint(8, 14 if offset == 0 else 16)
                    ts = day_ts(offset, h, random.randint(0, 25 if (offset == 0 and h == 14) else 59))
                    if ip == "192.168.1.74" and offset == 0 and ts > FAKE_NOW - 1800:
                        ts -= 3600  # the expedition PC went quiet at 13:50 (offline in the shots)
                    st.log_query(ts, ip, dom, cat(app, dom), False)
                    total += 1
        for ip, mac, label, owner, kind, vendor in OTHERS:
            pool = PHONE if kind == "phone" else ["ctldl.windowsupdate.com", "www.google.com"]
            for dom in random.sample(pool, min(8, len(pool))):
                for _ in range(random.randint(4, 40)):
                    h = random.randint(7, 14 if offset == 0 else 17)
                    ts = day_ts(offset, h, random.randint(0, 25 if (offset == 0 and h == 14) else 59))
                    st.log_query(ts, ip, dom, cat(app, dom), False)
                    total += 1
    # the flagged visits
    for ip, offset, hour, minute, dom, minutes in FLAGS:
        res = app.classifier.classify(dom)
        if not res or res["action"] not in ("alert", "block"):
            print("  (ignoré, non classé :", dom, ")")
            continue
        for k in range(minutes):
            ts = day_ts(offset, hour, min(59, minute + k))
            for _ in range(random.randint(3, 12)):
                st.log_query(ts, ip, dom, res["category"], res["action"] == "block")
                total += 1
            st.add_event(ts, ip, dom, res["category"], res["action"], 1, res.get("matched", ""))
    app.proxy.stats["queries"] = total
    while not st.q.empty():
        time.sleep(0.2)
    time.sleep(1.5)
    print("Données d'exemple :", total, "requêtes", flush=True)


_CAT = {}


def cat(app, dom):
    if dom not in _CAT:
        r = app.classifier.classify(dom)
        _CAT[dom] = r["category"] if r and r["action"] in ("log", "alert", "block") else ""
    return _CAT[dom]


SHOTS = [  # file, route, condition before the shot
    ("tableau-de-bord", "#/", "document.querySelectorAll('.kpi-card').length === 4 && document.querySelectorAll('#main tbody tr').length > 3"),
    ("appareils", "#/appareils", "document.querySelectorAll('#main tbody tr').length >= 8"),
    ("fiche-appareil", "#/appareils/{marc}", "document.querySelector('.tabs') && document.querySelectorAll('#main tbody tr').length > 0"),
    ("alertes", "#/alertes", "document.querySelectorAll('#main tbody tr').length > 5"),
    ("journal", "#/journal", "document.querySelectorAll('#main tbody tr').length > 10"),
    ("listes", "#/listes", "document.querySelectorAll('#main tbody tr').length > 15"),
    ("pc-agents", "#/pc", "document.querySelectorAll('#main tbody tr').length === 4"),
    ("reglages", "#/reglages", "document.querySelectorAll('#syslog div').length > 0"),
]
BROWSER_CLOCK = """(() => { const RD = Date, off = %d - RD.now();
  class D extends RD { constructor(...a) { if (a.length) super(...a); else super(RD.now() + off); } static now() { return RD.now() + off; } }
  window.Date = D; try { localStorage.setItem('nw-welcome-done', '1'); } catch (e) {} })();"""


def main():
    random.seed(20261029)
    skip_lists = "--skip-lists" in sys.argv
    tmp = tempfile.mkdtemp(prefix="nw-manual-")
    web_port = free_port()
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump({"site_name": "Entreprise Démo", "dns": {"bind": "127.0.0.1", "port": free_port(), "upstreams": ["192.168.1.10"]},
                   "web": {"bind": "127.0.0.1", "port": web_port}, "blockpage": {"enabled": False}, "lists": {"auto_update_days": 7}}, f)
    app = App(base_dir=BASE, config_path=cfg_path, data_dir=os.path.join(tmp, "data"))
    web = WebServer(app)
    app.proxy.start()          # no device tracker, no maintenance: nothing probes the real LAN
    web.start()
    chrome = None
    try:
        build(app, skip_lists)
        # show the settings an SRV-APP install has (display only: the demo keeps its private sockets)
        app.cfg.set([], "dns", "upstreams")
        app.cfg.set(53, "dns", "port")
        app.cfg.set("0.0.0.0", "dns", "bind")
        app.cfg.set(True, "blockpage", "enabled")
        app.upstreams = lambda: ["192.168.1.10", "1.1.1.1"]
        app.proxy.bind, app.proxy.port = "0.0.0.0", 53
        base = f"http://127.0.0.1:{web_port}"
        req = urllib.request.Request(base + "/api/setup", data=json.dumps({"password": PASSWORD}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
        marc = app.store.device_by_ip("192.168.1.101")["id"]
        os.makedirs(IMG, exist_ok=True)
        chrome = Chrome(1280, 800)
        chrome.cdp.send("Page.addScriptToEvaluateOnNewDocument", {"source": BROWSER_CLOCK % (FAKE_NOW * 1000)})
        chrome.goto(base + "/")
        chrome.wait("document.getElementById('loginForm')")
        status = chrome.eval("fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, "
                             "body: JSON.stringify({password: '%s'})}).then(r => r.status)" % PASSWORD)
        assert status == 200, status
        for i, (name, route, cond) in enumerate(SHOTS):
            chrome.goto(f"{base}/?s={i}{route.format(marc=marc)}")
            chrome.wait(cond, timeout=30)
            time.sleep(0.6)
            path = os.path.join(IMG, name + ".png")
            chrome.screenshot(path)
            print(f"  {name}.png  {os.path.getsize(path) // 1024} ko", flush=True)
        errs = chrome.eval("JSON.stringify(window.__nwErrors || [])")
        print("Captures terminées.", errs if errs != "[]" else "")
    finally:
        if chrome:
            chrome.stop()
        web.stop()
        app.stop()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
