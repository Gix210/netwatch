"""SQLite storage: devices, per-day query counts, flagged events, block lists, rules,
categories, sources, settings and the system journal. One connection, one lock,
plus a background writer that batches the DNS journal."""
import contextlib
import json
import os
import queue
import sqlite3
import threading
import time

from .util import now, day_of, day_start, norm_mac

# key, label, default action, block mode, severity
CATEGORIES = [
    ("adult", "Contenu explicite (adulte)", "alert", "ip", 3),
    ("mixed_adult", "Contenu adulte mixte", "alert", "ip", 3),
    ("lingerie", "Lingerie / suggestif", "log", "ip", 1),
    ("sexual_education", "Éducation sexuelle", "log", "ip", 1),
    ("dating", "Rencontres", "alert", "ip", 2),
    ("gambling", "Jeux d'argent", "alert", "ip", 2),
    ("drogue", "Drogues", "alert", "ip", 2),
    ("agressif", "Haine / violence", "alert", "ip", 3),
    ("dangerous_material", "Matériel dangereux", "alert", "ip", 3),
    ("sect", "Sectes", "log", "ip", 1),
    ("malware", "Logiciel malveillant", "block", "ip", 3),
    ("phishing", "Hameçonnage", "block", "ip", 3),
    ("cryptojacking", "Minage caché (cryptojacking)", "block", "ip", 3),
    ("ddos", "Outils d'attaque (DDoS)", "block", "ip", 3),
    ("stalkerware", "Logiciel espion", "block", "ip", 3),
    ("hacking", "Piratage", "alert", "ip", 2),
    ("warez", "Piratage de logiciels", "alert", "ip", 2),
    ("bypass", "Contournement du filtre", "block", "nx", 2),
    ("doh", "Contournement du filtre (DNS chiffré)", "block", "nx", 2),
    ("vpn", "VPN", "alert", "ip", 2),
    ("proxy", "Proxy / anonymiseur", "alert", "ip", 2),
    ("keyword", "Mot-clé suspect", "alert", "ip", 2),
    ("custom", "Règle manuelle", "alert", "ip", 2),
    ("blocked", "Bloqué manuellement", "block", "ip", 2),
    ("social_networks", "Réseaux sociaux", "log", "ip", 0),
    ("audio-video", "Vidéo / streaming", "log", "ip", 0),
    ("games", "Jeux", "log", "ip", 0),
]
ACTIONS = ("ignore", "log", "alert", "block")
KINDS = ("pc", "phone", "server", "equipment", "network", "unknown")

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT DEFAULT '', mac TEXT DEFAULT '', hostname TEXT DEFAULT '', label TEXT DEFAULT '',
  owner TEXT DEFAULT '', kind TEXT DEFAULT '', kind_auto TEXT DEFAULT '', vendor TEXT DEFAULT '',
  ignored INTEGER DEFAULT 0, first_seen INTEGER, last_seen INTEGER, queries_total INTEGER DEFAULT 0,
  agent_host TEXT DEFAULT '', agent_user TEXT DEFAULT '', agent_seen INTEGER DEFAULT 0,
  agent_info TEXT DEFAULT '', name_checked INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS devices_mac ON devices(mac);
CREATE TABLE IF NOT EXISTS queries(
  day TEXT, device_id INTEGER, domain TEXT, category TEXT DEFAULT '',
  count INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, first_ts INTEGER, last_ts INTEGER,
  PRIMARY KEY(day, device_id, domain)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS queries_dev ON queries(device_id, day);
CREATE INDEX IF NOT EXISTS queries_cat ON queries(category, day);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, device_id INTEGER, domain TEXT,
  category TEXT, action TEXT, qtype INTEGER, matched TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_dev ON events(device_id, ts);
CREATE TABLE IF NOT EXISTS listed(domain TEXT, category TEXT, source TEXT,
  PRIMARY KEY(domain, category)) WITHOUT ROWID;
DROP INDEX IF EXISTS listed_source;
CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE,
  category TEXT, note TEXT DEFAULT '', created INTEGER);
CREATE TABLE IF NOT EXISTS categories(key TEXT PRIMARY KEY, label TEXT, action TEXT, mode TEXT,
  severity INTEGER, count INTEGER DEFAULT 0, sort INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sources(name TEXT PRIMARY KEY, url TEXT, type TEXT,
  last_update INTEGER DEFAULT 0, status TEXT DEFAULT '', count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS syslog(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, level TEXT, msg TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS oui(prefix TEXT PRIMARY KEY, vendor TEXT);
"""


def _dict(row):
    return dict(row) if row is not None else None


class Store:
    def __init__(self, path, local_ips=(), hostname=""):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.lock = threading.RLock()
        self.conn = self._connect()
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        self.local_ips = set(local_ips) | {"127.0.0.1", "::1"}
        self.hostname = hostname
        self.ip_map = {}
        self.q = queue.Queue()
        self._stop = threading.Event()
        self.on_change = None  # callback when lists/rules/categories change
        self.ensure_categories()
        self.writer = threading.Thread(target=self._writer, name="nw-writer", daemon=True)
        self.writer.start()

    def _connect(self):
        c = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA temp_store=MEMORY")
        return c

    def reader(self):
        """A separate read connection for hot paths (the classifier)."""
        return self._connect()

    @contextlib.contextmanager
    def tx(self):
        with self.lock:
            cur = self.conn.cursor()
            try:
                yield cur
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
            finally:
                cur.close()

    def rows(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        with self.lock:
            return _dict(self.conn.execute(sql, args).fetchone())

    def close(self):
        self._stop.set()
        self.writer.join(timeout=5)
        with self.lock:
            self.conn.close()

    # ---- system journal -------------------------------------------------
    def log(self, level, msg):
        try:
            print(f"{time.strftime('%H:%M:%S')} [{level}] {msg}", flush=True)
        except (UnicodeEncodeError, OSError, ValueError):
            pass
        try:
            with self.tx() as cur:
                cur.execute("INSERT INTO syslog(ts, level, msg) VALUES(?,?,?)", (now(), level, msg))
        except sqlite3.Error:
            pass

    def syslog(self, limit=200):
        return self.rows("SELECT * FROM syslog ORDER BY id DESC LIMIT ?", (limit,))

    # ---- settings ----------------------------------------------------------
    def get_setting(self, key, default=None):
        r = self.one("SELECT value FROM settings WHERE key=?", (key,))
        if r is None:
            return default
        try:
            return json.loads(r["value"])
        except ValueError:
            return default

    def set_setting(self, key, value):
        with self.tx() as cur:
            cur.execute("INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, json.dumps(value, ensure_ascii=False)))

    # ---- categories / rules / lists -------------------------------------
    def ensure_categories(self):
        with self.tx() as cur:
            for i, (key, label, action, mode, sev) in enumerate(CATEGORIES):
                cur.execute("INSERT OR IGNORE INTO categories(key, label, action, mode, severity, sort) VALUES(?,?,?,?,?,?)",
                            (key, label, action, mode, sev, i))
                cur.execute("UPDATE categories SET label=?, mode=?, severity=?, sort=? WHERE key=?", (label, mode, sev, i, key))

    def categories(self):
        return self.rows("SELECT * FROM categories ORDER BY sort")

    def set_category_action(self, key, action):
        if action not in ACTIONS:
            raise ValueError("action")
        with self.tx() as cur:
            cur.execute("UPDATE categories SET action=? WHERE key=?", (action, key))
        self._changed()

    def refresh_category_counts(self):
        with self.tx() as cur:
            cur.execute("UPDATE categories SET count=0")
            for r in cur.execute("SELECT category, COUNT(*) c FROM listed GROUP BY category").fetchall():
                cur.execute("UPDATE categories SET count=? WHERE key=?", (r["c"], r["category"]))

    def listed_count(self):
        r = self.one("SELECT COUNT(*) c FROM listed")
        return r["c"] if r else 0

    def rules(self):
        return self.rows("SELECT * FROM rules ORDER BY created DESC")

    def add_rule(self, domain, category, note=""):
        with self.tx() as cur:
            cur.execute("INSERT INTO rules(domain, category, note, created) VALUES(?,?,?,?) "
                        "ON CONFLICT(domain) DO UPDATE SET category=excluded.category, note=excluded.note, created=excluded.created",
                        (domain, category, note, now()))
        self._changed()

    def delete_rule(self, rule_id):
        with self.tx() as cur:
            cur.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        self._changed()

    def sources(self):
        return self.rows("SELECT * FROM sources ORDER BY name")

    def set_source(self, name, url, stype, status=None, count=None, touched=False):
        with self.tx() as cur:
            cur.execute("INSERT OR IGNORE INTO sources(name, url, type) VALUES(?,?,?)", (name, url, stype))
            cur.execute("UPDATE sources SET url=?, type=? WHERE name=?", (url, stype, name))
            if status is not None:
                cur.execute("UPDATE sources SET status=? WHERE name=?", (status, name))
            if count is not None:
                cur.execute("UPDATE sources SET count=? WHERE name=?", (count, name))
            if touched:
                cur.execute("UPDATE sources SET last_update=? WHERE name=?", (now(), name))

    def replace_listed(self, source, rows_iter, batch=20000):
        """Replace every row of a source with rows_iter yielding (domain, category). Returns the count.
        Loads into a staging table in small transactions so the DNS journal keeps flowing."""
        with self.tx() as cur:
            cur.execute("DROP TABLE IF EXISTS listed_new")
            cur.execute("CREATE TABLE listed_new(domain TEXT, category TEXT, PRIMARY KEY(domain, category)) WITHOUT ROWID")
        total = 0
        chunk = []
        for item in rows_iter:
            chunk.append(item)
            if len(chunk) >= batch:
                total += self._insert_chunk(chunk)
                chunk = []
        if chunk:
            total += self._insert_chunk(chunk)
        with self.tx() as cur:
            # a listed parent already covers www.parent: drop the redundant rows
            cur.execute("DELETE FROM listed_new WHERE domain LIKE 'www.%' AND EXISTS "
                        "(SELECT 1 FROM listed_new p WHERE p.domain=substr(listed_new.domain, 5) AND p.category=listed_new.category)")
            total -= cur.rowcount if cur.rowcount > 0 else 0
            cur.execute("DELETE FROM listed WHERE source=?", (source,))
            cur.execute("INSERT OR IGNORE INTO listed(domain, category, source) SELECT domain, category, ? FROM listed_new", (source,))
            cur.execute("DROP TABLE listed_new")
        self.refresh_category_counts()
        self._changed()
        return total

    def vacuum(self):
        with self.lock:
            self.conn.execute("VACUUM")

    def _insert_chunk(self, chunk):
        with self.tx() as cur:
            cur.executemany("INSERT OR IGNORE INTO listed_new(domain, category) VALUES(?,?)", chunk)
            return cur.rowcount if cur.rowcount >= 0 else len(chunk)

    def seed_listed(self, source, rows):
        """Load built-in seed rows only when that source has never been loaded."""
        r = self.one("SELECT COUNT(*) c FROM listed WHERE source=?", (source,))
        if r and r["c"]:
            return 0
        return self.replace_listed(source, rows)

    def replace_oui(self, rows_iter, batch=5000):
        total = 0
        chunk = []
        with self.tx() as cur:
            cur.execute("DROP TABLE IF EXISTS oui_new")
            cur.execute("CREATE TABLE oui_new(prefix TEXT PRIMARY KEY, vendor TEXT)")
        for item in rows_iter:
            chunk.append(item)
            if len(chunk) >= batch:
                with self.tx() as cur:
                    cur.executemany("INSERT OR IGNORE INTO oui_new VALUES(?,?)", chunk)
                total += len(chunk)
                chunk = []
        if chunk:
            with self.tx() as cur:
                cur.executemany("INSERT OR IGNORE INTO oui_new VALUES(?,?)", chunk)
            total += len(chunk)
        with self.tx() as cur:
            cur.execute("DELETE FROM oui")
            cur.execute("INSERT OR IGNORE INTO oui SELECT * FROM oui_new")
            cur.execute("DROP TABLE oui_new")
        return total

    def oui_count(self):
        r = self.one("SELECT COUNT(*) c FROM oui")
        return r["c"] if r else 0

    def vendor_of(self, mac):
        if not mac:
            return ""
        prefix = mac.replace(":", "").upper()[:6]
        r = self.one("SELECT vendor FROM oui WHERE prefix=?", (prefix,))
        return r["vendor"] if r else ""

    def _changed(self):
        if self.on_change:
            try:
                self.on_change()
            except Exception:
                pass

    # ---- DNS journal (batched) ----------------------------------------------
    def log_query(self, ts, ip, domain, category, blocked):
        self.q.put((ts, ip, domain, category, 1 if blocked else 0))

    def _writer(self):
        while not self._stop.is_set():
            try:
                first = self.q.get(timeout=1.0)
            except queue.Empty:
                continue
            batch = [first]
            while len(batch) < 5000:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            try:
                self._flush(batch)
            except Exception as e:  # never let the journal kill the writer
                print("journal flush error:", e, flush=True)

    def _flush(self, batch):
        agg = {}
        dev_seen = {}
        dev_first = {}
        for ts, ip, domain, category, blocked in batch:
            dev_first[ip] = min(dev_first.get(ip, ts), ts)
            key = (day_of(ts), ip, domain)
            a = agg.get(key)
            if a is None:
                agg[key] = [1, blocked, category, ts, ts]
            else:
                a[0] += 1
                a[1] += blocked
                if category:
                    a[2] = category
                a[4] = max(a[4], ts)
            d = dev_seen.get(ip)
            dev_seen[ip] = (max(d[0], ts) if d else ts, (d[1] if d else 0) + 1)
        with self.tx() as cur:
            ids = {}
            for ip, (ts, n) in dev_seen.items():
                did = self._device_id_for_ip(cur, ip, ts)
                ids[ip] = did
                cur.execute("UPDATE devices SET last_seen=MAX(COALESCE(last_seen,0),?), queries_total=queries_total+?, "
                            "first_seen=MIN(COALESCE(first_seen,?),?) WHERE id=?", (ts, n, dev_first[ip], dev_first[ip], did))
            for (day, ip, domain), (count, blocked, category, first_ts, last_ts) in agg.items():
                cur.execute(
                    "INSERT INTO queries(day, device_id, domain, category, count, blocked, first_ts, last_ts) VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(day, device_id, domain) DO UPDATE SET count=count+excluded.count, blocked=blocked+excluded.blocked, "
                    "last_ts=MAX(last_ts, excluded.last_ts), category=CASE WHEN excluded.category<>'' THEN excluded.category ELSE category END",
                    (day, ids[ip], domain, category, count, blocked, first_ts, last_ts))

    def _device_id_for_ip(self, cur, ip, ts):
        did = self.ip_map.get(ip)
        if did:
            return did
        r = cur.execute("SELECT id FROM devices WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
        if r:
            did = r["id"]
        else:
            kind_auto = "server" if ip in self.local_ips else ""
            host = self.hostname if ip in self.local_ips else ""
            cur.execute("INSERT INTO devices(ip, hostname, kind_auto, first_seen, last_seen) VALUES(?,?,?,?,?)",
                        (ip, host, kind_auto, ts, ts))
            did = cur.lastrowid
        self.ip_map[ip] = did
        return did

    def device_id_for_ip(self, ip):
        with self.tx() as cur:
            return self._device_id_for_ip(cur, ip, now())

    # ---- events ---------------------------------------------------------------
    def add_event(self, ts, ip, domain, category, action, qtype, matched=""):
        with self.tx() as cur:
            did = self._device_id_for_ip(cur, ip, ts)
            cur.execute("INSERT INTO events(ts, device_id, domain, category, action, qtype, matched) VALUES(?,?,?,?,?,?,?)",
                        (ts, did, domain, category, action, qtype, matched))
            return cur.lastrowid, did

    # ---- devices -------------------------------------------------------------
    @staticmethod
    def display_name(d):
        return d.get("label") or d.get("agent_host") or d.get("hostname") or d.get("ip") or f"appareil {d.get('id')}"

    def devices(self):
        return self.rows("SELECT * FROM devices ORDER BY COALESCE(last_seen,0) DESC")

    def device(self, did):
        return self.one("SELECT * FROM devices WHERE id=?", (did,))

    def device_by_ip(self, ip):
        return self.one("SELECT * FROM devices WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ip,))

    def update_device(self, did, fields):
        allowed = {"label", "owner", "kind", "ignored", "hostname", "vendor", "kind_auto", "name_checked"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        if "kind" in sets and sets["kind"] not in KINDS + ("",):
            raise ValueError("kind")
        with self.tx() as cur:
            cur.execute("UPDATE devices SET " + ", ".join(f"{k}=?" for k in sets) + " WHERE id=?",
                        tuple(sets.values()) + (did,))

    def delete_device(self, did):
        with self.tx() as cur:
            cur.execute("DELETE FROM queries WHERE device_id=?", (did,))
            cur.execute("DELETE FROM events WHERE device_id=?", (did,))
            cur.execute("DELETE FROM devices WHERE id=?", (did,))
        self.ip_map = {ip: i for ip, i in self.ip_map.items() if i != did}

    def set_mac(self, ip, mac):
        """Attach the MAC seen in the ARP table to the device using that IP (handles IP reuse)."""
        mac = norm_mac(mac)
        if not mac or ip in self.local_ips:
            return
        with self.tx() as cur:
            dev = _dict(cur.execute("SELECT * FROM devices WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone())
            other = _dict(cur.execute("SELECT * FROM devices WHERE mac=? ORDER BY id LIMIT 1", (mac,)).fetchone())
            if dev is None:
                if other:
                    cur.execute("UPDATE devices SET ip=? WHERE id=?", (ip, other["id"]))
                    self.ip_map[ip] = other["id"]
                return
            if not dev["mac"]:
                if other and other["id"] != dev["id"]:
                    self._merge(cur, dev, other, ip)
                else:
                    cur.execute("UPDATE devices SET mac=? WHERE id=?", (mac, dev["id"]))
            elif dev["mac"] != mac:
                cur.execute("UPDATE devices SET ip='' WHERE id=?", (dev["id"],))
                if other:
                    cur.execute("UPDATE devices SET ip=? WHERE id=?", (ip, other["id"]))
                    self.ip_map[ip] = other["id"]
                else:
                    cur.execute("INSERT INTO devices(ip, mac, first_seen, last_seen) VALUES(?,?,?,?)", (ip, mac, now(), now()))
                    self.ip_map[ip] = cur.lastrowid

    def _merge(self, cur, src, dst, ip):
        """Fold device src into dst (same MAC); dst keeps its identity and takes the IP."""
        cur.execute(
            "INSERT INTO queries(day, device_id, domain, category, count, blocked, first_ts, last_ts) "
            "SELECT day, ?, domain, category, count, blocked, first_ts, last_ts FROM queries WHERE device_id=? "
            "ON CONFLICT(day, device_id, domain) DO UPDATE SET count=count+excluded.count, blocked=blocked+excluded.blocked, "
            "last_ts=MAX(last_ts, excluded.last_ts), first_ts=MIN(first_ts, excluded.first_ts)", (dst["id"], src["id"]))
        cur.execute("DELETE FROM queries WHERE device_id=?", (src["id"],))
        cur.execute("UPDATE events SET device_id=? WHERE device_id=?", (dst["id"], src["id"]))
        cur.execute("UPDATE devices SET ip=?, last_seen=MAX(COALESCE(last_seen,0),?), queries_total=queries_total+?, "
                    "hostname=CASE WHEN hostname='' THEN ? ELSE hostname END, label=CASE WHEN label='' THEN ? ELSE label END WHERE id=?",
                    (ip, src["last_seen"] or 0, src["queries_total"] or 0, src["hostname"] or "", src["label"] or "", dst["id"]))
        cur.execute("DELETE FROM devices WHERE id=?", (src["id"],))
        self.ip_map = {k: v for k, v in self.ip_map.items() if v != src["id"]}
        self.ip_map[ip] = dst["id"]

    def agent_heartbeat(self, data, remote_ip):
        ip = (data.get("ip") or remote_ip or "").strip()
        mac = norm_mac(data.get("mac", ""))
        if mac and ip:
            self.set_mac(ip, mac)
        with self.tx() as cur:
            dev = None
            if mac:
                dev = _dict(cur.execute("SELECT * FROM devices WHERE mac=? ORDER BY id LIMIT 1", (mac,)).fetchone())
            if dev is None and ip:
                dev = _dict(cur.execute("SELECT * FROM devices WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone())
            if dev is None:
                cur.execute("INSERT INTO devices(ip, mac, first_seen, last_seen) VALUES(?,?,?,?)", (ip, mac, now(), now()))
                dev = {"id": cur.lastrowid}
                if ip:
                    self.ip_map[ip] = dev["id"]
            info = {k: data.get(k) for k in ("os", "uptime_min", "dns", "version", "doh_policy", "ips") if k in data}
            cur.execute("UPDATE devices SET agent_host=?, agent_user=?, agent_seen=?, agent_info=?, kind_auto='pc', "
                        "hostname=CASE WHEN hostname='' THEN ? ELSE hostname END WHERE id=?",
                        (str(data.get("host", ""))[:80], str(data.get("user", ""))[:80], now(),
                         json.dumps(info, ensure_ascii=False), str(data.get("host", ""))[:80], dev["id"]))
            return dev["id"]

    def agents(self):
        return self.rows("SELECT * FROM devices WHERE agent_seen>0 ORDER BY agent_seen DESC")

    def devices_needing_names(self, limit=10, recheck_after=6 * 3600):
        t = now()
        return self.rows("SELECT * FROM devices WHERE ip<>'' AND last_seen>? AND name_checked<? ORDER BY last_seen DESC LIMIT ?",
                         (t - 3600, t - recheck_after, limit))

    # ---- reporting ---------------------------------------------------------------
    def dashboard(self, days=14, online_minutes=10):
        t = now()
        today = day_of(t)
        start_today = day_start(today)
        k = {}
        k["active_devices"] = self.one("SELECT COUNT(*) c FROM devices WHERE ignored=0 AND (last_seen>=? OR agent_seen>=?)",
                                       (t - online_minutes * 60, t - online_minutes * 60))["c"]
        k["devices_total"] = self.one("SELECT COUNT(*) c FROM devices WHERE ignored=0")["c"]
        k["queries_today"] = self.one("SELECT COALESCE(SUM(count),0) c FROM queries WHERE day=?", (today,))["c"]
        k["alerts_today"] = self.one("SELECT COUNT(*) c FROM events WHERE ts>=? AND action='alert'", (start_today,))["c"]
        k["blocks_today"] = self.one("SELECT COUNT(*) c FROM events WHERE ts>=? AND action='block'", (start_today,))["c"]
        first_day = day_of(t - (days - 1) * 86400)
        per_day = {day_of(t - i * 86400): {"day": day_of(t - i * 86400), "queries": 0, "alerts": 0, "blocks": 0}
                   for i in range(days)}
        for r in self.rows("SELECT day, SUM(count) c FROM queries WHERE day>=? GROUP BY day", (first_day,)):
            if r["day"] in per_day:
                per_day[r["day"]]["queries"] = r["c"]
        for r in self.rows("SELECT ts, action FROM events WHERE ts>=?", (day_start(first_day),)):
            d = per_day.get(day_of(r["ts"]))
            if d:
                d["alerts" if r["action"] == "alert" else "blocks"] += 1
        latest = self.rows(
            "SELECT e.*, d.label, d.hostname, d.agent_host, d.ip, d.owner FROM events e LEFT JOIN devices d ON d.id=e.device_id "
            "ORDER BY e.ts DESC, e.id DESC LIMIT 50")
        for e in latest:
            e["device"] = self.display_name(e)
        top_devices = self.rows(
            "SELECT e.device_id, d.label, d.hostname, d.agent_host, d.ip, d.owner, "
            "SUM(e.action='alert') alerts, SUM(e.action='block') blocks FROM events e LEFT JOIN devices d ON d.id=e.device_id "
            "WHERE e.ts>=? GROUP BY e.device_id ORDER BY alerts+blocks DESC LIMIT 10", (start_today,))
        for d in top_devices:
            d["device"] = self.display_name(d)
        top_domains = self.rows(
            "SELECT domain, category, COUNT(*) n, SUM(action='block') blocks FROM events WHERE ts>=? GROUP BY domain "
            "ORDER BY n DESC LIMIT 10", (start_today,))
        return {"kpi": k, "per_day": sorted(per_day.values(), key=lambda x: x["day"]), "latest": latest,
                "top_devices": top_devices, "top_domains": top_domains}

    def device_list(self, online_minutes=10):
        t = now()
        today = day_of(t)
        devs = self.devices()
        q_today = {r["device_id"]: r for r in self.rows(
            "SELECT device_id, SUM(count) c, SUM(blocked) b FROM queries WHERE day=? GROUP BY device_id", (today,))}
        e_today = {r["device_id"]: r["n"] for r in self.rows(
            "SELECT device_id, COUNT(*) n FROM events WHERE ts>=? GROUP BY device_id", (day_start(today),))}
        for d in devs:
            d["name"] = self.display_name(d)
            d["online"] = bool((d["last_seen"] or 0) >= t - online_minutes * 60 or (d["agent_seen"] or 0) >= t - online_minutes * 60)
            d["queries_today"] = (q_today.get(d["id"]) or {}).get("c", 0) or 0
            d["blocked_today"] = (q_today.get(d["id"]) or {}).get("b", 0) or 0
            d["flagged_today"] = e_today.get(d["id"], 0)
            d["kind_eff"] = d["kind"] or d["kind_auto"] or "unknown"
            try:
                d["agent_info"] = json.loads(d["agent_info"]) if d["agent_info"] else {}
            except ValueError:
                d["agent_info"] = {}
        return devs

    def device_detail(self, did, days=7):
        d = self.device(did)
        if not d:
            return None
        d["name"] = self.display_name(d)
        d["kind_eff"] = d["kind"] or d["kind_auto"] or "unknown"
        try:
            d["agent_info"] = json.loads(d["agent_info"]) if d["agent_info"] else {}
        except ValueError:
            d["agent_info"] = {}
        since = day_of(now() - (days - 1) * 86400)
        d["top_domains"] = self.rows(
            "SELECT domain, category, SUM(count) c, SUM(blocked) b, MAX(last_ts) last_ts FROM queries "
            "WHERE device_id=? AND day>=? GROUP BY domain ORDER BY c DESC LIMIT 200", (did, since))
        # blocked and alert categories first (what matters), then journal-only ones; newest first within each
        d["flagged"] = self.rows(
            "SELECT q.domain, q.category, SUM(q.count) c, SUM(q.blocked) b, MAX(q.last_ts) last_ts, "
            "MIN(CASE k.action WHEN 'block' THEN 0 WHEN 'alert' THEN 1 ELSE 2 END) rank FROM queries q "
            "LEFT JOIN categories k ON k.key=q.category "
            "WHERE q.device_id=? AND q.day>=? AND q.category<>'' GROUP BY q.domain ORDER BY rank, last_ts DESC LIMIT 200", (did, since))
        d["events"] = self.rows("SELECT * FROM events WHERE device_id=? ORDER BY ts DESC, id DESC LIMIT 100", (did,))
        d["days"] = self.rows("SELECT day, SUM(count) c, SUM(blocked) b FROM queries WHERE device_id=? AND day>=? GROUP BY day ORDER BY day",
                              (did, since))
        return d

    def events(self, device_id=None, category=None, q=None, ts_from=None, ts_to=None, action=None, limit=200, offset=0):
        where, args = [], []
        if device_id:
            where.append("e.device_id=?")
            args.append(device_id)
        if category:
            where.append("e.category=?")
            args.append(category)
        if action:
            where.append("e.action=?")
            args.append(action)
        if q:
            where.append("e.domain LIKE ?")
            args.append(f"%{q}%")
        if ts_from:
            where.append("e.ts>=?")
            args.append(ts_from)
        if ts_to:
            where.append("e.ts<?")
            args.append(ts_to)
        sql = ("SELECT e.*, d.label, d.hostname, d.agent_host, d.ip, d.owner FROM events e LEFT JOIN devices d ON d.id=e.device_id "
               + ("WHERE " + " AND ".join(where) if where else "") + " ORDER BY e.ts DESC, e.id DESC LIMIT ? OFFSET ?")
        rows = self.rows(sql, tuple(args) + (limit, offset))
        for e in rows:
            e["device"] = self.display_name(e)
        return rows

    def journal(self, device_id=None, category=None, q=None, day_from=None, day_to=None, flagged=False, limit=500, offset=0):
        where, args = [], []
        if device_id:
            where.append("q.device_id=?")
            args.append(device_id)
        if category:
            where.append("q.category=?")
            args.append(category)
        elif flagged:
            where.append("q.category<>''")
        if q:
            where.append("q.domain LIKE ?")
            args.append(f"%{q}%")
        if day_from:
            where.append("q.day>=?")
            args.append(day_from)
        if day_to:
            where.append("q.day<=?")
            args.append(day_to)
        sql = ("SELECT q.*, d.label, d.hostname, d.agent_host, d.ip, d.owner FROM queries q LEFT JOIN devices d ON d.id=q.device_id "
               + ("WHERE " + " AND ".join(where) if where else "") + " ORDER BY q.day DESC, q.count DESC LIMIT ? OFFSET ?")
        rows = self.rows(sql, tuple(args) + (limit, offset))
        for r in rows:
            r["device"] = self.display_name(r)
        return rows

    def digest_data(self, day):
        start, end = day_start(day), day_start(day) + 86400
        rows = self.rows(
            "SELECT e.device_id, d.label, d.hostname, d.agent_host, d.ip, d.owner, e.category, e.domain, e.action, COUNT(*) n "
            "FROM events e LEFT JOIN devices d ON d.id=e.device_id WHERE e.ts>=? AND e.ts<? "
            "GROUP BY e.device_id, e.category, e.domain, e.action ORDER BY e.device_id, n DESC", (start, end))
        for r in rows:
            r["device"] = self.display_name(r)
        return rows

    # ---- maintenance --------------------------------------------------------------
    def purge(self, retention_days):
        cutoff_day = day_of(now() - retention_days * 86400)
        cutoff_ts = day_start(cutoff_day)
        with self.tx() as cur:
            cur.execute("DELETE FROM queries WHERE day<?", (cutoff_day,))
            cur.execute("DELETE FROM events WHERE ts<?", (cutoff_ts,))
            cur.execute("DELETE FROM syslog WHERE ts<?", (now() - 30 * 86400,))

    def checkpoint(self):
        with self.lock:
            try:
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass

    def db_size(self):
        try:
            size = os.path.getsize(self.path)
            wal = self.path + "-wal"
            if os.path.exists(wal):
                size += os.path.getsize(wal)
            return size
        except OSError:
            return 0
