"""Web UI + JSON API (password protected) and the optional HTTP block page."""
import csv
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from .store import ACTIONS, KINDS
from .util import now, day_start, day_of, norm_domain, is_valid_domain, fmt_ts

KIND_LABELS = {"pc": "PC", "phone": "Téléphone / tablette", "server": "Serveur", "equipment": "Équipement",
               "network": "Réseau", "unknown": "Inconnu"}
MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
        ".md": "text/plain; charset=utf-8", ".ps1": "text/plain; charset=utf-8", ".txt": "text/plain; charset=utf-8"}


def hash_password(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), 200000).hex()
    return f"pbkdf2${salt}${h}"


def check_password(pw, stored):
    parts = (stored or "").split("$")
    if len(parts) != 3 or parts[0] != "pbkdf2":
        return False
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(parts[1]), 200000).hex()
    return hmac.compare_digest(h, parts[2])


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, web):
        self.web = web
        super().__init__(addr, handler)

    def handle_error(self, request, client_address):
        # a browser closing its connection is normal: keep tracebacks out of netwatch.log
        import sys
        if isinstance(sys.exc_info()[1], (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError)):
            return
        super().handle_error(request, client_address)


class WebServer:
    def __init__(self, app):
        self.app = app
        self.httpd = None
        self.block = None
        self.fail = {}
        self.fail_lock = threading.Lock()

    def start(self):
        cfg = self.app.cfg
        bind, port = cfg.get("web", "bind") or "0.0.0.0", int(cfg.get("web", "port"))
        self.httpd = _Server((bind, port), ApiHandler, self)
        threading.Thread(target=self.httpd.serve_forever, name="nw-web", daemon=True).start()
        self.app.log("info", f"Interface web : http://{self.app.ip}:{port}/")
        if cfg.get("blockpage", "enabled"):
            bport = int(cfg.get("blockpage", "port") or 80)
            try:
                self.block = _Server(("0.0.0.0", bport), BlockHandler, self)
                threading.Thread(target=self.block.serve_forever, name="nw-block", daemon=True).start()
                self.app.blockpage_ok = True
                self.app.apply_dns_config()
                self.app.log("info", f"Page de blocage sur le port {bport} ; les sites bloqués pointent vers {self.app.ip}")
            except OSError as e:
                self.app.blockpage_ok = False
                self.app.apply_dns_config()
                self.app.log("warn", f"Page de blocage : port {bport} indisponible ({e}) ; les sites bloqués répondront 0.0.0.0")

    def stop(self):
        for s in (self.httpd, self.block):
            if s:
                s.shutdown()
                s.server_close()

    # ---- sessions ---------------------------------------------------------------
    def make_token(self):
        exp = now() + int(self.app.cfg.get("web", "session_hours") or 12) * 3600
        sig = hmac.new(self.app.secret, str(exp).encode(), hashlib.sha256).hexdigest()
        return f"{exp}.{sig}"

    def check_token(self, tok):
        try:
            exp, sig = tok.split(".", 1)
            good = hmac.new(self.app.secret, exp.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(good, sig) and int(exp) > now()
        except (ValueError, AttributeError):
            return False

    def login_blocked(self, ip):
        with self.fail_lock:
            cnt, until = self.fail.get(ip, (0, 0))
            return until > time.time()

    def login_failed(self, ip):
        with self.fail_lock:
            cnt, until = self.fail.get(ip, (0, 0))
            cnt += 1
            self.fail[ip] = (cnt, time.time() + 30 if cnt >= 5 else 0)

    def login_ok(self, ip):
        with self.fail_lock:
            self.fail.pop(ip, None)


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "NetWatch"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # ---- helpers -------------------------------------------------------------------
    @property
    def app(self):
        return self.server.web.app

    @property
    def web(self):
        return self.server.web

    def client_ip(self):
        return self.client_address[0]

    def send_json(self, obj, status=200, headers=None):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_bytes(self, data, ctype, status=200, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_file(self, root, rel):
        rel = urllib.parse.unquote(rel).replace("\\", "/")
        path = os.path.normpath(os.path.join(root, rel))
        if not path.startswith(os.path.normpath(root) + os.sep) or not os.path.isfile(path):
            return self.send_json({"error": "introuvable"}, 404)
        with open(path, "rb") as f:
            data = f.read()
        ext = os.path.splitext(path)[1].lower()
        self.send_bytes(data, MIME.get(ext, "application/octet-stream"))

    def read_body(self):
        ln = int(self.headers.get("Content-Length") or 0)
        if ln <= 0:
            return {}
        if ln > 1_000_000:
            raise ValueError("corps trop volumineux")
        raw = self.rfile.read(ln)
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise ValueError("JSON invalide")
        return data if isinstance(data, dict) else {}

    def authed(self):
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "nw" and self.web.check_token(v):
                return True
        return False

    def cookie_header(self, token, max_age):
        return {"Set-Cookie": f"nw={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"}

    # ---- dispatch ---------------------------------------------------------------------
    def do_GET(self):
        self.dispatch("GET")

    def do_HEAD(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_DELETE(self):
        self.dispatch("DELETE")

    ROUTES = []

    def dispatch(self, method):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        try:
            if method == "GET" and not path.startswith("/api/"):
                return self.serve_static(path)
            for m, pattern, func, needs_auth in self.ROUTES:
                if m != method:
                    continue
                mt = re.fullmatch(pattern, path)
                if not mt:
                    continue
                if needs_auth and not self.authed():
                    return self.send_json({"error": "non authentifié"}, 401)
                body = self.read_body() if method in ("POST", "DELETE") else {}
                return func(self, mt, q, body)
            self.send_json({"error": "introuvable"}, 404)
        except ValueError as e:
            self.send_json({"error": str(e)}, 400)
        except Exception as e:
            self.app.log("error", f"API {method} {path} : {e}")
            try:
                self.send_json({"error": f"erreur interne : {e}"}, 500)
            except OSError:
                pass

    def serve_static(self, path):
        base = self.app.base
        if path in ("/", "/index.html"):
            return self.send_file(os.path.join(base, "static"), "index.html")
        if path == "/favicon.ico":
            return self.send_bytes(b"", "image/x-icon", 204)
        if path.startswith("/static/"):
            return self.send_file(os.path.join(base, "static"), path[len("/static/"):])
        if path.startswith("/agent/"):
            return self.send_file(os.path.join(base, "agent"), path[len("/agent/"):])
        if path.startswith("/docs/"):
            if not self.authed():
                return self.send_json({"error": "non authentifié"}, 401)
            name = path[len("/docs/"):]
            root = base if name in ("README.md", "README.fr.md") else os.path.join(base, "docs")
            return self.send_file(root, name)
        self.send_json({"error": "introuvable"}, 404)

    # ---- auth ------------------------------------------------------------------------
    def api_me(self, m, q, body):
        authed = self.authed()
        out = {"auth": authed, "setup_needed": not bool(self.app.cfg.get("web", "password_hash")),
               "site_name": self.app.cfg.get("site_name"), "version": self.app.version}
        if authed:
            out["categories"] = self.app.store.categories()
            out["kinds"] = KIND_LABELS
        self.send_json(out)

    def api_setup(self, m, q, body):
        if self.app.cfg.get("web", "password_hash"):
            raise ValueError("un mot de passe existe déjà")
        pw = str(body.get("password") or "")
        if len(pw) < 8:
            raise ValueError("8 caractères minimum")
        self.app.cfg.update({"web": {"password_hash": hash_password(pw)}})
        self.app.log("info", f"Mot de passe administrateur défini depuis {self.client_ip()}")
        tok = self.web.make_token()
        self.send_json({"ok": True}, headers=self.cookie_header(tok, 12 * 3600))

    def api_login(self, m, q, body):
        ip = self.client_ip()
        if self.web.login_blocked(ip):
            return self.send_json({"error": "trop d'essais, patientez 30 secondes"}, 429)
        if check_password(str(body.get("password") or ""), self.app.cfg.get("web", "password_hash")):
            self.web.login_ok(ip)
            tok = self.web.make_token()
            return self.send_json({"ok": True}, headers=self.cookie_header(tok, int(self.app.cfg.get("web", "session_hours") or 12) * 3600))
        self.web.login_failed(ip)
        self.app.log("warn", f"Mot de passe refusé depuis {ip}")
        self.send_json({"error": "mot de passe incorrect"}, 401)

    def api_logout(self, m, q, body):
        self.send_json({"ok": True}, headers=self.cookie_header("x", 0))

    # ---- status / dashboard -----------------------------------------------------------
    def api_status(self, m, q, body):
        self.send_json(self.app.status())

    def api_dashboard(self, m, q, body):
        days = max(1, min(60, int(q.get("days") or 14)))
        self.send_json(self.app.store.dashboard(days, int(self.app.cfg.get("online_minutes") or 10)))

    # ---- devices ----------------------------------------------------------------------
    def api_devices(self, m, q, body):
        self.send_json({"devices": self.app.store.device_list(int(self.app.cfg.get("online_minutes") or 10))})

    def api_device(self, m, q, body):
        days = max(1, min(90, int(q.get("days") or 7)))
        d = self.app.store.device_detail(int(m.group(1)), days)
        if not d:
            return self.send_json({"error": "appareil inconnu"}, 404)
        self.send_json(d)

    def api_device_update(self, m, q, body):
        did = int(m.group(1))
        fields = {}
        for k in ("label", "owner"):
            if k in body:
                fields[k] = str(body[k] or "").strip()[:80]
        if "kind" in body:
            kind = str(body["kind"] or "")
            if kind and kind not in KINDS:
                raise ValueError("type invalide")
            fields["kind"] = kind
        if "ignored" in body:
            fields["ignored"] = 1 if body["ignored"] else 0
        self.app.store.update_device(did, fields)
        self.send_json({"ok": True})

    def api_device_delete(self, m, q, body):
        self.app.store.delete_device(int(m.group(1)))
        self.send_json({"ok": True})

    # ---- events / journal ---------------------------------------------------------------
    def _range(self, q):
        ts_from = day_start(q["from"]) if q.get("from") else None
        ts_to = day_start(q["to"]) + 86400 if q.get("to") else None
        return ts_from, ts_to

    def api_events(self, m, q, body):
        ts_from, ts_to = self._range(q)
        rows = self.app.store.events(device_id=int(q["device"]) if q.get("device") else None, category=q.get("cat") or None,
                                     q=q.get("q") or None, ts_from=ts_from, ts_to=ts_to, action=q.get("action") or None,
                                     limit=max(1, min(1000, int(q.get("limit") or 200))), offset=int(q.get("offset") or 0))
        self.send_json({"events": rows})

    def _journal_rows(self, q, limit):
        return self.app.store.journal(device_id=int(q["device"]) if q.get("device") else None, category=q.get("cat") or None,
                                      q=q.get("q") or None, day_from=q.get("from") or None, day_to=q.get("to") or None,
                                      flagged=q.get("flagged") in ("1", "true"), limit=limit, offset=int(q.get("offset") or 0))

    def api_journal(self, m, q, body):
        rows = self._journal_rows(q, max(1, min(2000, int(q.get("limit") or 500))))
        self.send_json({"rows": rows})

    def api_journal_csv(self, m, q, body):
        rows = self._journal_rows(q, 200000)
        labels = {c["key"]: c["label"] for c in self.app.store.categories()}
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
        w.writerow(["Jour", "Appareil", "IP", "Propriétaire", "Domaine", "Catégorie", "Requêtes", "Bloquées", "Dernière"])
        for r in rows:
            w.writerow([r["day"], r["device"], r["ip"] or "", r["owner"] or "", r["domain"], labels.get(r["category"], r["category"] or ""),
                        r["count"], r["blocked"], fmt_ts(r["last_ts"])])
        data = ("﻿" + buf.getvalue()).encode("utf-8")
        self.send_bytes(data, "text/csv; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename=netwatch-journal-{day_of()}.csv"})

    # ---- lists / rules ----------------------------------------------------------------------
    def api_lists(self, m, q, body):
        st = self.app.store
        self.send_json({"categories": st.categories(), "sources": st.sources(), "update": self.app.updater.status(),
                        "keywords": st.get_setting("keywords", []), "rules": st.rules(), "listed": st.listed_count(),
                        "auto_update_days": self.app.cfg.get("lists", "auto_update_days")})

    def api_category(self, m, q, body):
        key, action = str(body.get("key") or ""), str(body.get("action") or "")
        if action not in ACTIONS:
            raise ValueError("action invalide")
        self.app.store.set_category_action(key, action)
        self.app.log("info", f"Catégorie {key} : action « {action} »")
        self.send_json({"ok": True})

    def api_lists_update(self, m, q, body):
        started = self.app.updater.start()
        self.send_json({"ok": True, "started": started})

    def api_lists_test(self, m, q, body):
        d = norm_domain(q.get("domain") or "")
        if not is_valid_domain(d):
            raise ValueError("domaine invalide")
        res = self.app.classifier.classify(d)
        cands = self.app.classifier.candidates(d)
        listed = self.app.store.rows("SELECT domain, category, source FROM listed WHERE domain IN (%s)" % ",".join("?" * len(cands)), tuple(cands))
        rules = self.app.store.rows("SELECT domain, category, note FROM rules WHERE domain IN (%s)" % ",".join("?" * len(cands)), tuple(cands))
        self.send_json({"domain": d, "result": res, "listed": listed, "rules": rules})

    def api_rule_add(self, m, q, body):
        d = norm_domain(body.get("domain") or "")
        if not is_valid_domain(d):
            raise ValueError("domaine invalide")
        cat = str(body.get("category") or "custom")
        keys = {c["key"] for c in self.app.store.categories()}
        if cat != "allow" and cat not in keys:
            raise ValueError("catégorie invalide")
        self.app.store.add_rule(d, cat, str(body.get("note") or "")[:200])
        self.app.log("info", f"Règle : {d} → {cat}")
        self.send_json({"ok": True})

    def api_rule_delete(self, m, q, body):
        self.app.store.delete_rule(int(m.group(1)))
        self.send_json({"ok": True})

    def api_keywords(self, m, q, body):
        kws = body.get("keywords")
        if isinstance(kws, str):
            kws = kws.replace(",", "\n").split("\n")
        if not isinstance(kws, list):
            raise ValueError("liste attendue")
        clean = sorted({str(k).strip().lower() for k in kws if str(k).strip() and len(str(k).strip()) >= 3})
        self.app.store.set_setting("keywords", clean)
        self.app.classifier.reload()
        self.send_json({"ok": True, "keywords": clean})

    # ---- agents ----------------------------------------------------------------------------
    def api_agents(self, m, q, body):
        token = self.app.cfg.get("agent", "token")
        port = self.app.cfg.get("web", "port")
        url = f"http://{self.app.ip}:{port}/agent/Install-NetWatchAgent.ps1"
        cmd = (f"powershell -NoProfile -ExecutionPolicy Bypass -Command \"iwr {url} -OutFile $env:TEMP\\nw-agent.ps1; "
               f"& $env:TEMP\\nw-agent.ps1 -Server {self.app.ip} -Port {port} -Token {token}\"")
        agents = self.app.store.agents()
        for a in agents:
            a["name"] = self.app.store.display_name(a)
            try:
                a["agent_info"] = json.loads(a["agent_info"]) if a["agent_info"] else {}
            except ValueError:
                a["agent_info"] = {}
            dns = a["agent_info"].get("dns") or []
            a["via_netwatch"] = self.app.ip in dns if dns else None
        self.send_json({"agents": agents, "install": {"url": url, "command": cmd, "token": token, "server": self.app.ip, "port": port}})

    def api_heartbeat(self, m, q, body):
        tok = self.headers.get("X-NetWatch-Token") or str(body.get("token") or "")
        if not hmac.compare_digest(tok, self.app.cfg.get("agent", "token") or ""):
            return self.send_json({"error": "jeton invalide"}, 401)
        did = self.app.store.agent_heartbeat(body, self.client_ip())
        self.send_json({"ok": True, "device_id": did, "server_ip": self.app.ip})

    # ---- settings -------------------------------------------------------------------------
    def _settings_view(self):
        c = self.app.cfg
        a = c.get("alerts") or {}
        return {"site_name": c.get("site_name"), "contact": c.get("contact"),
                "dns": {"upstreams": c.get("dns", "upstreams"), "upstreams_auto": self.app.upstreams(), "port": c.get("dns", "port"),
                        "bind": c.get("dns", "bind"), "log_local": c.get("dns", "log_local"), "upstream_timeout": c.get("dns", "upstream_timeout")},
                "blockpage": c.get("blockpage"), "block_ip": c.get("block_ip"), "retention_days": c.get("retention_days"),
                "online_minutes": c.get("online_minutes"),
                "alerts": {k: v for k, v in a.items() if k != "smtp_password"} | {"has_password": bool(a.get("smtp_password"))},
                "lists": {"auto_update_days": c.get("lists", "auto_update_days")}, "agent_token": c.get("agent", "token"),
                "web": {"port": c.get("web", "port"), "session_hours": c.get("web", "session_hours")}}

    def api_settings(self, m, q, body):
        self.send_json(self._settings_view())

    def api_settings_save(self, m, q, body):
        c = self.app.cfg
        patch = {}
        if "site_name" in body:
            patch["site_name"] = str(body["site_name"] or "Mon entreprise").strip()[:60]
        if "contact" in body:
            patch["contact"] = str(body["contact"] or "").strip()[:120]
        dns = body.get("dns") or {}
        if dns:
            p = {}
            if "upstreams" in dns:
                ups = dns["upstreams"]
                if isinstance(ups, str):
                    ups = re.split(r"[\s,;]+", ups)
                clean = [u.strip() for u in ups if u and u.strip()]
                for u in clean:
                    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?", u):
                        raise ValueError(f"serveur DNS invalide : {u}")
                p["upstreams"] = clean
            if "log_local" in dns:
                p["log_local"] = bool(dns["log_local"])
            if "upstream_timeout" in dns:
                p["upstream_timeout"] = max(0.5, min(10.0, float(dns["upstream_timeout"])))
            if "port" in dns:
                p["port"] = max(1, min(65535, int(dns["port"])))
            if "bind" in dns:
                p["bind"] = str(dns["bind"] or "0.0.0.0").strip()
            patch["dns"] = p
        bp = body.get("blockpage") or {}
        if bp:
            patch["blockpage"] = {k: (bool(bp[k]) if k == "enabled" else max(1, min(65535, int(bp[k])))) for k in ("enabled", "port") if k in bp}
        if "block_ip" in body:
            b = str(body["block_ip"] or "auto").strip()
            if b != "auto" and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", b):
                raise ValueError("adresse de blocage invalide")
            patch["block_ip"] = b
        if "retention_days" in body:
            patch["retention_days"] = max(7, min(3650, int(body["retention_days"])))
        if "online_minutes" in body:
            patch["online_minutes"] = max(1, min(1440, int(body["online_minutes"])))
        al = body.get("alerts") or {}
        if al:
            p = {}
            for k in ("email_enabled", "digest_enabled"):
                if k in al:
                    p[k] = bool(al[k])
            for k in ("to", "smtp_host", "smtp_user"):
                if k in al:
                    p[k] = str(al[k] or "").strip()[:200]
            if "smtp_port" in al:
                p["smtp_port"] = max(1, min(65535, int(al["smtp_port"] or 587)))
            if "cooldown_min" in al:
                p["cooldown_min"] = max(1, min(1440, int(al["cooldown_min"] or 30)))
            if "digest_hour" in al:
                p["digest_hour"] = max(0, min(23, int(al["digest_hour"] or 7)))
            if al.get("smtp_password"):
                p["smtp_password"] = str(al["smtp_password"])
            patch["alerts"] = p
        li = body.get("lists") or {}
        if "auto_update_days" in li:
            patch["lists"] = {"auto_update_days": max(0, min(365, int(li["auto_update_days"] or 0)))}
        before = (c.get("dns", "port"), c.get("dns", "bind"), c.get("blockpage"), c.get("web", "port"))
        c.update(patch)
        after = (c.get("dns", "port"), c.get("dns", "bind"), c.get("blockpage"), c.get("web", "port"))
        self.app.apply_dns_config()
        self.app.log("info", f"Réglages enregistrés depuis {self.client_ip()}")
        out = self._settings_view()
        out["restart_needed"] = before != after
        self.send_json(out)

    def api_password(self, m, q, body):
        if not check_password(str(body.get("current") or ""), self.app.cfg.get("web", "password_hash")):
            raise ValueError("mot de passe actuel incorrect")
        pw = str(body.get("new") or "")
        if len(pw) < 8:
            raise ValueError("8 caractères minimum")
        self.app.cfg.update({"web": {"password_hash": hash_password(pw)}})
        self.app.log("info", "Mot de passe administrateur modifié")
        self.send_json({"ok": True})

    def api_test_email(self, m, q, body):
        if not self.app.notifier.enabled():
            raise ValueError("activez les courriels et remplissez le serveur SMTP d'abord")
        err = self.app.notifier.test()
        if err:
            raise ValueError(f"envoi impossible : {err}")
        self.send_json({"ok": True})

    def api_syslog(self, m, q, body):
        self.send_json({"rows": self.app.store.syslog(max(1, min(1000, int(q.get("limit") or 200))))})


ApiHandler.ROUTES = [
    ("GET", r"/api/me", ApiHandler.api_me, False),
    ("POST", r"/api/setup", ApiHandler.api_setup, False),
    ("POST", r"/api/login", ApiHandler.api_login, False),
    ("POST", r"/api/logout", ApiHandler.api_logout, False),
    ("POST", r"/api/agent/heartbeat", ApiHandler.api_heartbeat, False),
    ("GET", r"/api/status", ApiHandler.api_status, True),
    ("GET", r"/api/dashboard", ApiHandler.api_dashboard, True),
    ("GET", r"/api/devices", ApiHandler.api_devices, True),
    ("GET", r"/api/devices/(\d+)", ApiHandler.api_device, True),
    ("POST", r"/api/devices/(\d+)", ApiHandler.api_device_update, True),
    ("DELETE", r"/api/devices/(\d+)", ApiHandler.api_device_delete, True),
    ("GET", r"/api/events", ApiHandler.api_events, True),
    ("GET", r"/api/journal", ApiHandler.api_journal, True),
    ("GET", r"/api/journal\.csv", ApiHandler.api_journal_csv, True),
    ("GET", r"/api/lists", ApiHandler.api_lists, True),
    ("POST", r"/api/lists/categories", ApiHandler.api_category, True),
    ("POST", r"/api/lists/update", ApiHandler.api_lists_update, True),
    ("GET", r"/api/lists/test", ApiHandler.api_lists_test, True),
    ("POST", r"/api/rules", ApiHandler.api_rule_add, True),
    ("DELETE", r"/api/rules/(\d+)", ApiHandler.api_rule_delete, True),
    ("POST", r"/api/keywords", ApiHandler.api_keywords, True),
    ("GET", r"/api/agents", ApiHandler.api_agents, True),
    ("GET", r"/api/settings", ApiHandler.api_settings, True),
    ("POST", r"/api/settings", ApiHandler.api_settings_save, True),
    ("POST", r"/api/settings/password", ApiHandler.api_password, True),
    ("POST", r"/api/settings/test-email", ApiHandler.api_test_email, True),
    ("GET", r"/api/syslog", ApiHandler.api_syslog, True),
]


BLOCK_PAGE = """<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Site bloqué</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#f3f4f6;color:#111827;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}}
.card{{background:#fff;border-radius:14px;padding:32px 36px;max-width:520px;box-shadow:0 10px 30px rgba(0,0,0,.08);margin:16px}}
h1{{font-size:22px;margin:0 0 12px}} .host{{font-family:Consolas,monospace;background:#f3f4f6;padding:4px 8px;border-radius:6px}}
.tag{{display:inline-block;background:#fee2e2;color:#991b1b;padding:3px 10px;border-radius:999px;font-size:13px}}
p{{line-height:1.5}} .small{{color:#6b7280;font-size:13px}}</style></head><body><div class="card">
<h1>Accès bloqué</h1><p>Le site <span class="host">{host}</span> est classé <span class="tag">{label}</span>
et n'est pas accessible depuis le réseau de {site}.</p>
<p class="small">L'utilisation du réseau est journalisée conformément à la politique d'utilisation du Wi-Fi.
Si vous pensez qu'il s'agit d'une erreur, contactez {contact}.</p></div></body></html>"""


class BlockHandler(BaseHTTPRequestHandler):
    server_version = "NetWatch"
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        app = self.server.web.app
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        res = app.classifier.classify(host) if host else None
        label = res["label"] if res and res.get("action") in ("block", "alert", "log") else "non autorisé"
        page = BLOCK_PAGE.format(host=html.escape(host or "?"), label=html.escape(label),
                                 site=html.escape(app.cfg.get("site_name") or ""), contact=html.escape(app.cfg.get("contact") or "la direction"))
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    do_POST = do_GET
    do_HEAD = do_GET
