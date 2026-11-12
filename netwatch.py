"""NetWatch launcher. Run: python netwatch.py  (options: --dns-port, --web-port, --data, --no-blockpage, --service)"""
import argparse
import os
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from app.core import App  # noqa: E402
from app.web import WebServer  # noqa: E402


def _redirect_logs(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, "netwatch.log")
    try:
        if os.path.exists(path) and os.path.getsize(path) > 5_000_000:
            os.replace(path, path + ".1")
    except OSError:
        pass
    f = open(path, "a", encoding="utf-8", buffering=1)
    sys.stdout = f
    sys.stderr = f


def main():
    p = argparse.ArgumentParser(description="NetWatch : surveillance DNS du réseau de l’entreprise")
    p.add_argument("--config", help="chemin de config.json")
    p.add_argument("--data", help="dossier des données (base, journal)")
    p.add_argument("--dns-port", type=int, help="port DNS (53 par défaut)")
    p.add_argument("--dns-bind", help="adresse d'écoute DNS (0.0.0.0 par défaut)")
    p.add_argument("--web-port", type=int, help="port de l'interface web (8795 par défaut)")
    p.add_argument("--no-blockpage", action="store_true", help="ne pas servir la page de blocage (port 80)")
    p.add_argument("--upstreams", help="serveurs DNS en amont, séparés par des virgules (remplace config.json)")
    p.add_argument("--service", action="store_true", help="mode tâche planifiée : journal dans data/netwatch.log")
    a = p.parse_args()
    data_dir = a.data or os.path.join(BASE, "data")
    if a.service:
        _redirect_logs(data_dir)
    elif sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    app = App(base_dir=BASE, config_path=a.config, data_dir=data_dir, dns_port=a.dns_port, dns_bind=a.dns_bind,
              web_port=a.web_port, blockpage=False if a.no_blockpage else None)
    if a.upstreams:
        app.cfg.set([u.strip() for u in a.upstreams.split(",") if u.strip()], "dns", "upstreams")
        app.apply_dns_config()
    web = WebServer(app)
    app.start()
    web.start()
    print(f"NetWatch {app.version} : interface http://{app.ip}:{app.cfg.get('web', 'port')}/  (Ctrl+C pour arrêter)", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        web.stop()
        app.stop()


if __name__ == "__main__":
    main()
