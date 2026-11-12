"""Download and import the block lists (UT1 categories, hosts files) and the IEEE OUI table.
Runs in a background thread; progress is exposed to the UI."""
import csv
import os
import re
import tarfile
import threading
import time
import urllib.request

from .config import UT1_MAP
from .util import norm_domain, is_valid_domain, now, ssl_context

UA = "NetWatch/1.0 (filtrage DNS interne)"
HOSTS_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
              "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"}


def iter_ut1(path, progress=None, mapping=UT1_MAP):
    with tarfile.open(path, "r|gz") as tar:
        for m in tar:
            if not m.isfile():
                continue
            parts = m.name.replace("\\", "/").split("/")
            if len(parts) < 2 or parts[-1] != "domains":
                continue
            cat = mapping.get(parts[-2])
            if not cat:
                continue
            if progress:
                progress(f"Import de la catégorie {parts[-2]}")
            f = tar.extractfile(m)
            if f is None:
                continue
            for raw in f:
                d = norm_domain(raw.decode("utf-8", "replace"))
                if is_valid_domain(d):
                    yield d, cat


def iter_hosts(path, category):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
                d = parts[1]
            elif len(parts) == 1:
                d = parts[0]
            else:
                continue
            d = norm_domain(d)
            if d in HOSTS_SKIP or not is_valid_domain(d):
                continue
            yield d, category


def iter_oui(path):
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 3 or row[0] == "Registry":
                continue
            prefix = re.sub(r"[^0-9A-Fa-f]", "", row[1]).upper()
            if len(prefix) == 6:
                yield prefix, row[2].strip()[:80]


class ListUpdater:
    def __init__(self, cfg, store, classifier, log, data_dir):
        self.cfg = cfg
        self.store = store
        self.classifier = classifier
        self.log = log
        self.tmp = os.path.join(data_dir, "tmp")
        self.lock = threading.Lock()
        self.state = {"running": False, "step": "", "message": "", "pct": 0, "started": 0, "finished": 0, "error": ""}
        self._stop = threading.Event()
        threading.Thread(target=self._scheduler, name="nw-lists", daemon=True).start()

    def status(self):
        with self.lock:
            st = dict(self.state)
        # only downloaded sources count: the built-in seeds must not make a fresh install look up to date
        srcs = [s for s in self.store.sources() if s["type"] in ("ut1", "hosts", "oui")]
        st["last_update"] = max([s["last_update"] or 0 for s in srcs] or [0])
        return st

    def _set(self, **kw):
        with self.lock:
            self.state.update(kw)

    def start(self):
        with self.lock:
            if self.state["running"]:
                return False
            self.state.update(running=True, started=now(), finished=0, error="", pct=0, step="", message="Démarrage")
        threading.Thread(target=self.run_all, name="nw-lists-run", daemon=True).start()
        return True

    def stop(self):
        self._stop.set()

    def _scheduler(self):
        self._stop.wait(60)
        while not self._stop.is_set():
            try:
                days = int(self.cfg.get("lists", "auto_update_days") or 0)
                if days > 0:
                    last = self.status()["last_update"]
                    if now() - last >= days * 86400:
                        self.log("info", "Mise à jour automatique des listes")
                        self.start()
            except Exception as e:
                self.log("warn", f"Planification des listes : {e}")
            self._stop.wait(1800)

    def run_all(self):
        errors = []
        try:
            os.makedirs(self.tmp, exist_ok=True)
            for src in self.cfg.get("lists", "sources") or []:
                if self._stop.is_set():
                    break
                try:
                    self._run_source(src)
                except Exception as e:
                    errors.append(f"{src.get('name')}: {e}")
                    self.store.set_source(src.get("name", "?"), src.get("url", ""), src.get("type", ""), status=f"Erreur : {e}")
                    self.log("error", f"Liste {src.get('name')} : {e}")
            self.classifier.reload()
            if self.store.db_size() > 150 * 1024 * 1024:
                self._set(step="Base de données", message="Compactage…", pct=100)
                t0 = time.time()
                try:
                    self.store.vacuum()
                    self.log("info", f"Base compactée en {time.time() - t0:.0f} s ({self.store.db_size() // 1048576} Mo)")
                except Exception as e:
                    self.log("warn", f"Compactage de la base : {e}")
        finally:
            self._set(running=False, finished=now(), pct=100, step="", message="Terminé" if not errors else "Terminé avec erreurs",
                      error="; ".join(errors))
            self.log("info", f"Listes : {self.store.listed_count()} domaines classés" + (f" ({len(errors)} erreur(s))" if errors else ""))

    def _download(self, url, dest, label):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=60, context=ssl_context()) as r, open(dest, "wb") as f:
            total = int(r.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = r.read(262144)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                pct = int(done * 100 / total) if total else 0
                self._set(step=label, message=f"Téléchargement {done // 1024} ko" + (f" / {total // 1024} ko" if total else ""), pct=pct)

    def _run_source(self, src):
        name, url, typ = src.get("name", "?"), src.get("url", ""), src.get("type", "")
        if not url or typ not in ("ut1", "hosts", "oui"):
            raise ValueError("source invalide")
        key = (src.get("key") or re.sub(r"[^a-z0-9]+", "", name.lower())[:12] or typ)
        self.store.set_source(name, url, typ, status="Téléchargement…")
        path = os.path.join(self.tmp, re.sub(r"[^A-Za-z0-9]+", "_", name) + ".dat")
        t0 = time.time()
        self._download(url, path, name)
        self._set(step=name, message="Import…", pct=0)
        self.store.set_source(name, url, typ, status="Import…")
        progress = lambda msg: self._set(step=name, message=msg)
        if typ == "ut1":
            n = self.store.replace_listed(key, iter_ut1(path, progress))
        elif typ == "hosts":
            n = self.store.replace_listed(key, iter_hosts(path, src.get("category") or "adult"))
        else:
            n = self.store.replace_oui(iter_oui(path))
            with self.store.tx() as cur:
                cur.execute("UPDATE devices SET name_checked=0 WHERE vendor='' AND mac<>''")
        try:
            os.remove(path)
        except OSError:
            pass
        self.store.set_source(name, url, typ, status="OK", count=n, touched=True)
        self.log("info", f"Liste {name} : {n} entrées en {time.time() - t0:.0f} s")
