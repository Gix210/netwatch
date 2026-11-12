"""End-to-end tests: a fake upstream DNS, the real NetWatch app on high ports, DNS + HTTP checks.
Run:  python qa/test_netwatch.py"""
import http.cookiejar
import io
import json
import os
import random
import shutil
import socket
import struct
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from app import dnslib  # noqa: E402
from app.core import App  # noqa: E402
from app.web import WebServer  # noqa: E402
from app.lists_update import iter_hosts, iter_ut1, iter_oui  # noqa: E402
from app.classify import Classifier  # noqa: E402


def free_port():
    for _ in range(50):
        p = random.randint(20000, 50000)
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.bind(("127.0.0.1", p))
            u.close()
            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t.bind(("127.0.0.1", p))
            t.close()
            return p
        except OSError:
            continue
    raise RuntimeError("no free port")


class FakeUpstream:
    """Answers A 93.184.216.34 (TTL 120) for everything, NXDOMAIN for names containing 'nxdomain'."""

    def __init__(self, port):
        self.port = port
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", port))
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1", port))
        self.tcp.listen(5)
        self.hits = 0
        self.running = True
        threading.Thread(target=self._udp, daemon=True).start()
        threading.Thread(target=self._tcp, daemon=True).start()

    def answer(self, data):
        self.hits += 1
        name, qtype, qclass, _ = dnslib.parse_question(data)
        if "nxdomain" in name:
            return dnslib.build_response(data, rcode=dnslib.RCODE_NXDOMAIN)
        if qtype == dnslib.TYPE_A:
            return dnslib.build_response(data, answers=[(dnslib.TYPE_A, socket.inet_aton("93.184.216.34"))], ttl=120)
        return dnslib.build_response(data)

    def _udp(self):
        while self.running:
            try:
                data, addr = self.udp.recvfrom(4096)
                self.udp.sendto(self.answer(data), addr)
            except OSError:
                break

    def _tcp(self):
        while self.running:
            try:
                c, _ = self.tcp.accept()
                ln = struct.unpack("!H", c.recv(2))[0]
                data = c.recv(ln)
                resp = self.answer(data)
                c.sendall(struct.pack("!H", len(resp)) + resp)
                c.close()
            except OSError:
                break

    def stop(self):
        self.running = False
        self.udp.close()
        self.tcp.close()


class NetWatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="nwtest-")
        cls.up_port = free_port()
        cls.upstream = FakeUpstream(cls.up_port)
        cls.dns_port = free_port()
        cls.web_port = free_port()
        cfg_path = os.path.join(cls.tmp, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({"dns": {"upstreams": [f"127.0.0.1:{cls.up_port}"], "port": cls.dns_port, "bind": "127.0.0.1"},
                       "web": {"port": cls.web_port, "bind": "127.0.0.1"}, "blockpage": {"enabled": False},
                       "lists": {"auto_update_days": 0}}, f)
        cls.app = App(base_dir=BASE, config_path=cfg_path, data_dir=os.path.join(cls.tmp, "data"))
        cls.web = WebServer(cls.app)
        cls.app.start()
        cls.web.start()
        time.sleep(0.5)
        assert cls.app.proxy.listening, cls.app.proxy.error
        cls.cj = http.cookiejar.CookieJar()
        cls.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cls.cj))

    @classmethod
    def tearDownClass(cls):
        cls.web.stop()
        cls.app.stop()
        cls.upstream.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- helpers ----
    def query(self, name, qtype=dnslib.TYPE_A, tcp=False):
        q = dnslib.build_query(name, qtype)
        if tcp:
            with socket.create_connection(("127.0.0.1", self.dns_port), timeout=5) as s:
                s.sendall(struct.pack("!H", len(q)) + q)
                ln = struct.unpack("!H", s.recv(2))[0]
                resp = b""
                while len(resp) < ln:
                    resp += s.recv(ln - len(resp))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(q, ("127.0.0.1", self.dns_port))
            resp, _ = s.recvfrom(4096)
            s.close()
        self.assertEqual(resp[:2], q[:2])
        hdr, recs = dnslib.parse_records(resp)
        answers = [(r[1], resp[r[4]:r[4] + r[5]]) for r in recs if r[6] == 0]
        return hdr["rcode"], answers

    def http(self, path, body=None, method=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{self.web_port}{path}", data=data, method=method or ("POST" if data else "GET"),
                                     headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=10) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if r.headers.get("Content-Type", "").startswith("application/json") else raw)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw

    def wait_journal(self, domain, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            rows = self.app.store.rows("SELECT * FROM queries WHERE domain=?", (domain,))
            if rows:
                return rows
            time.sleep(0.1)
        return []

    def events(self, domain, timeout=3.0):
        """Events are recorded in the background: wait for them (returns [] after the timeout)."""
        end = time.time() + timeout
        while True:
            rows = self.app.store.rows("SELECT * FROM events WHERE domain=? ORDER BY id", (domain,))
            if rows or time.time() >= end:
                return rows
            time.sleep(0.05)

    # ---- DNS ----
    def test_01_forward(self):
        rcode, answers = self.query("example.com")
        self.assertEqual(rcode, 0)
        self.assertEqual(answers, [(dnslib.TYPE_A, socket.inet_aton("93.184.216.34"))])
        rows = self.wait_journal("example.com")
        self.assertTrue(rows)
        self.assertEqual(rows[0]["category"], "")
        self.assertEqual(rows[0]["blocked"], 0)

    def test_02_cache(self):
        before = self.app.proxy.stats["cache_hits"]
        hits = self.upstream.hits
        self.query("example.com")
        self.assertEqual(self.app.proxy.stats["cache_hits"], before + 1)
        self.assertEqual(self.upstream.hits, hits)

    def test_03_nxdomain_passthrough(self):
        rcode, answers = self.query("foo.nxdomain.test")
        self.assertEqual(rcode, 3)
        self.assertEqual(answers, [])

    def test_04_adult_alert_not_blocked(self):
        rcode, answers = self.query("www.pornhub.com")
        self.assertEqual(rcode, 0)
        self.assertEqual(answers[0][0], dnslib.TYPE_A)
        ev = self.events("www.pornhub.com")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["category"], ev[0]["action"]), ("adult", "alert"))
        rows = self.wait_journal("www.pornhub.com")
        self.assertEqual(rows[0]["category"], "adult")
        self.query("www.pornhub.com")  # within a minute: no second event
        time.sleep(0.5)
        self.assertEqual(len(self.events("www.pornhub.com")), 1)

    def test_05_bypass_nxdomain(self):
        rcode, answers = self.query("use-application-dns.net")
        self.assertEqual(rcode, 3)
        ev = self.events("use-application-dns.net")
        self.assertEqual((ev[0]["category"], ev[0]["action"]), ("bypass", "block"))
        rcode, _ = self.query("mask.icloud.com", dnslib.TYPE_HTTPS)
        self.assertEqual(rcode, 3)

    def test_06_manual_block_rule(self):
        self.app.store.add_rule("evil.test", "malware")
        rcode, answers = self.query("x.evil.test")
        self.assertEqual(rcode, 0)
        self.assertEqual(answers, [(dnslib.TYPE_A, socket.inet_aton("0.0.0.0"))])
        rcode, answers = self.query("x.evil.test", dnslib.TYPE_AAAA)
        self.assertEqual((rcode, answers), (0, []))
        ev = self.events("x.evil.test")
        self.assertEqual((ev[0]["category"], ev[0]["action"]), ("malware", "block"))
        rows = self.wait_journal("x.evil.test")
        self.assertGreaterEqual(rows[0]["blocked"], 1)

    def test_07_allow_rule_wins(self):
        self.app.store.add_rule("pornhub.com", "allow")
        res = self.app.classifier.classify("fr.pornhub.com")
        self.assertEqual(res["action"], "allow")
        self.query("fr.pornhub.com")
        self.assertEqual(self.events("fr.pornhub.com", timeout=1.0), [])

    def test_08_keyword(self):
        rcode, answers = self.query("freeporntube.test")
        self.assertEqual(rcode, 0)
        ev = self.events("freeporntube.test")
        self.assertEqual((ev[0]["category"], ev[0]["action"], ev[0]["matched"]), ("keyword", "alert", "freeporntube"))
        self.assertIsNone(self.app.classifier.classify("sussex.ac.uk"))
        self.assertIsNone(self.app.classifier.classify("middlesex.edu"))
        self.assertEqual(self.app.classifier.classify("sex.test")["category"], "keyword")

    def test_09_tcp(self):
        rcode, answers = self.query("tcp.example.net", tcp=True)
        self.assertEqual(rcode, 0)
        self.assertEqual(answers[0][0], dnslib.TYPE_A)

    def test_10_local_names_not_journaled(self):
        rcode, _ = self.query("dc01.corp.example.local")
        self.assertEqual(rcode, 0)
        time.sleep(1.5)
        self.assertEqual(self.app.store.rows("SELECT * FROM queries WHERE domain LIKE '%.local'"), [])
        rcode, _ = self.query("64.5.168.192.in-addr.arpa", dnslib.TYPE_PTR)
        self.assertEqual(rcode, 0)

    # ---- web ----
    def test_11_web_setup_and_api(self):
        self.assertEqual(self.http("/api/status")[0], 401)
        st, me = self.http("/api/me")
        self.assertTrue(me["setup_needed"])
        self.assertEqual(self.http("/api/setup", {"password": "court"})[0], 400)
        self.assertEqual(self.http("/api/setup", {"password": "motdepasse1"})[0], 200)
        st, status = self.http("/api/status")
        self.assertEqual(st, 200)
        self.assertTrue(status["dns"]["listening"])
        self.assertGreater(status["listed"], 100)
        st, devs = self.http("/api/devices")
        me = [d for d in devs["devices"] if d["ip"] == "127.0.0.1"]
        self.assertEqual(len(me), 1)
        self.assertGreater(me[0]["queries_today"], 0)
        self.assertEqual(me[0]["kind_eff"], "server")
        did = me[0]["id"]
        self.assertEqual(self.http(f"/api/devices/{did}", {"label": "Poste test", "owner": "QA", "kind": "pc"})[0], 200)
        st, det = self.http(f"/api/devices/{did}?days=7")
        self.assertEqual((det["label"], det["owner"], det["kind"]), ("Poste test", "QA", "pc"))
        self.assertTrue(any(r["domain"] == "www.pornhub.com" for r in det["flagged"]))
        st, dash = self.http("/api/dashboard?days=3")
        self.assertGreaterEqual(dash["kpi"]["alerts_today"], 2)
        self.assertEqual(len(dash["per_day"]), 3)
        st, csv_data = self.http("/api/journal.csv?flagged=1")
        self.assertEqual(st, 200)
        self.assertIn("www.pornhub.com", csv_data.decode("utf-8"))
        st, ev = self.http("/api/events?action=block")
        self.assertTrue(all(e["action"] == "block" for e in ev["events"]))
        st, t = self.http("/api/lists/test?domain=xvideos.com")
        self.assertEqual((t["result"]["category"], t["result"]["action"]), ("adult", "alert"))
        st, t = self.http("/api/lists/test?domain=pornhub.com")
        self.assertEqual(t["result"]["action"], "allow")

    def test_12_rules_and_categories_via_api(self):
        st, _ = self.http("/api/rules", {"domain": "casino.test", "category": "gambling", "note": "test"})
        self.assertEqual(st, 200)
        st, lists = self.http("/api/lists")
        self.assertTrue(any(r["domain"] == "casino.test" for r in lists["rules"]))
        self.assertEqual(self.http("/api/rules", {"domain": "x", "category": "gambling"})[0], 400)
        self.assertEqual(self.http("/api/lists/categories", {"key": "adult", "action": "block"})[0], 200)
        rcode, answers = self.query("www.xnxx.com")
        self.assertEqual(answers, [(dnslib.TYPE_A, socket.inet_aton("0.0.0.0"))])
        self.assertEqual(self.http("/api/lists/categories", {"key": "adult", "action": "alert"})[0], 200)
        rcode, answers = self.query("www.xhamster.com")
        self.assertEqual(answers[0][1], socket.inet_aton("93.184.216.34"))
        st, kw = self.http("/api/keywords", {"keywords": "porn\nxxx\nab\n"})
        self.assertEqual(kw["keywords"], ["porn", "xxx"])
        self.assertIsNone(self.app.classifier.classify("hentai.test"))
        self.http("/api/keywords", {"keywords": self.app.store.get_setting("keywords") + ["hentai"]})

    def test_13_agent_heartbeat(self):
        body = {"host": "PC-TEST", "user": "marc", "ip": "127.0.0.1", "mac": "AA-BB-CC-DD-EE-01", "dns": ["192.168.1.10"],
                "os": "Windows 11 Pro", "version": "1.0.0", "doh_policy": True}
        st, _ = self.http("/api/agent/heartbeat", {**body, "token": "wrong"})
        self.assertEqual(st, 401)
        req = urllib.request.Request(f"http://127.0.0.1:{self.web_port}/api/agent/heartbeat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", "X-NetWatch-Token": self.app.cfg.get("agent", "token")})
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 200)
        st, ag = self.http("/api/agents")
        a = [x for x in ag["agents"] if x["agent_host"] == "PC-TEST"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["agent_user"], "marc")
        self.assertIs(a[0]["via_netwatch"], False)
        self.assertIn("-Token", ag["install"]["command"])

    def test_14_settings_and_password(self):
        self.assertEqual(self.http("/api/settings", {"dns": {"upstreams": "pas-une-ip"}})[0], 400)
        st, s = self.http("/api/settings", {"retention_days": 30, "online_minutes": 5, "dns": {"upstreams": f"127.0.0.1:{self.up_port}"}})
        self.assertEqual(st, 200)
        self.assertEqual(self.app.cfg.get("retention_days"), 30)
        self.assertFalse(s["restart_needed"])
        self.assertEqual(self.http("/api/settings/password", {"current": "faux", "new": "nouveaumdp1"})[0], 400)
        self.assertEqual(self.http("/api/settings/password", {"current": "motdepasse1", "new": "nouveaumdp1"})[0], 200)
        self.http("/api/logout", {})
        self.assertEqual(self.http("/api/status")[0], 401)
        self.assertEqual(self.http("/api/login", {"password": "motdepasse1"})[0], 401)
        self.assertEqual(self.http("/api/login", {"password": "nouveaumdp1"})[0], 200)
        self.assertEqual(self.http("/api/status")[0], 200)
        self.assertEqual(self.http("/docs/README.fr.md")[0], 200)
        self.assertEqual(self.http("/static/../config.json")[0], 404)

    # ---- parsers ----
    def test_15_parsers(self):
        hosts = os.path.join(self.tmp, "hosts.txt")
        with open(hosts, "w", encoding="utf-8") as f:
            f.write("# comment\n127.0.0.1 localhost\n0.0.0.0 Bad.Example.COM # trailing\n0.0.0.0 0.0.0.0\n\nplain.example.net\n")
        self.assertEqual(list(iter_hosts(hosts, "adult")), [("bad.example.com", "adult"), ("plain.example.net", "adult")])
        tar_path = os.path.join(self.tmp, "bl.tar.gz")
        with tarfile.open(tar_path, "w:gz") as tar:
            for cat, content in (("adult", "a.test\nb.test\n"), ("unknown_cat", "c.test\n"), ("doh", "doh.test\n")):
                data = content.encode()
                info = tarfile.TarInfo(f"blacklists/{cat}/domains")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
                info = tarfile.TarInfo(f"blacklists/{cat}/urls")
                info.size = 0
                tar.addfile(info, io.BytesIO(b""))
        self.assertEqual(sorted(iter_ut1(tar_path)), [("a.test", "adult"), ("b.test", "adult"), ("doh.test", "doh")])
        oui = os.path.join(self.tmp, "oui.csv")
        with open(oui, "w", encoding="utf-8") as f:
            f.write('Registry,Assignment,Organization Name,Organization Address\nMA-L,3C22FB,"Apple, Inc.",Cupertino\nMA-L,bad,X,Y\n')
        self.assertEqual(list(iter_oui(oui)), [("3C22FB", "Apple, Inc.")])
        n = self.app.store.replace_listed("Test source", iter_ut1(tar_path))
        self.assertEqual(n, 3)
        self.assertEqual(self.app.classifier.classify("www.a.test")["category"], "adult")
        self.assertEqual(self.app.classifier.classify("doh.test")["mode"], "nx")
        self.assertEqual(self.app.store.vendor_of("3c:22:fb:00:00:01"), "Apple")

    def test_16_device_mac_merge(self):
        st = self.app.store
        st.set_mac("10.9.9.9", "aa:bb:cc:00:00:09")  # unknown IP, unknown MAC: nothing created
        self.assertIsNone(st.device_by_ip("10.9.9.9"))
        d1 = st.device_id_for_ip("10.9.9.1")
        st.set_mac("10.9.9.1", "aa-bb-cc-00-00-01")
        self.assertEqual(st.device(d1)["mac"], "aa:bb:cc:00:00:01")
        d2 = st.device_id_for_ip("10.9.9.2")
        st.set_mac("10.9.9.2", "aa:bb:cc:00:00:01")  # same MAC moved to a new IP: merged into d1
        self.assertIsNone(st.device(d2))
        self.assertEqual(st.device(d1)["ip"], "10.9.9.2")
        st.set_mac("10.9.9.2", "aa:bb:cc:00:00:02")  # IP reused by another physical device
        self.assertEqual(st.device(d1)["ip"], "")
        self.assertEqual(st.device_by_ip("10.9.9.2")["mac"], "aa:bb:cc:00:00:02")

    def test_18_non_query_relayed_uncached(self):
        q = bytearray(dnslib.build_query("corp.test", dnslib.TYPE_SOA))
        q[2] = (q[2] & 0x87) | (5 << 3)  # opcode UPDATE
        hits = self.upstream.hits
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(bytes(q), ("127.0.0.1", self.dns_port))
            resp, _ = s.recvfrom(4096)
            s.close()
            self.assertEqual(resp[:2], bytes(q[:2]))
        self.assertEqual(self.upstream.hits, hits + 2)
        time.sleep(1.5)
        self.assertEqual(self.app.store.rows("SELECT * FROM queries WHERE domain='corp.test'"), [])
        rcode, answers = self.query("corp.test", dnslib.TYPE_SOA)
        self.assertEqual(rcode, 0)
        self.assertEqual(self.upstream.hits, hits + 3)

    def test_19_seeds_do_not_count_as_downloaded(self):
        self.assertTrue(any(s["type"] == "seed" and s["last_update"] for s in self.app.store.sources()))
        self.assertEqual(self.app.updater.status()["last_update"], 0)

    def test_20_ca_bundle_loaded(self):
        import ssl
        from app.util import ssl_context, ca_bundle_path
        self.assertTrue(os.path.exists(ca_bundle_path()))
        bare = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        bare.load_verify_locations(cafile=ca_bundle_path())
        self.assertGreaterEqual(bare.cert_store_stats()["x509_ca"], 100)
        ctx = ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertGreaterEqual(ctx.cert_store_stats()["x509_ca"], 100)

    def test_21_busy_database_does_not_delay_answers(self):
        with self.app.store.lock:  # simulate a long import / VACUUM holding the database
            t0 = time.time()
            rcode, answers = self.query(f"busy{random.randint(0, 10**9)}.pornhub.com")
            elapsed = time.time() - t0
        self.assertEqual(rcode, 0)
        self.assertLess(elapsed, 1.0)

    def test_22_flagged_order_and_first_seen(self):
        st = self.app.store
        t = int(time.time())
        st.log_query(t - 3600, "10.7.7.7", "x.pornhub.test", "adult", False)       # older, but an alert category
        st.log_query(t - 60, "10.7.7.7", "feed.social.test", "social_networks", False)  # newer, journal only
        end = time.time() + 5
        while time.time() < end and len(st.rows("SELECT * FROM queries q JOIN devices d ON d.id=q.device_id WHERE d.ip='10.7.7.7'")) < 2:
            time.sleep(0.05)
        did = st.device_by_ip("10.7.7.7")["id"]
        flagged = st.device_detail(did, days=2)["flagged"]
        self.assertEqual([r["domain"] for r in flagged], ["x.pornhub.test", "feed.social.test"])
        self.assertLessEqual(st.device(did)["first_seen"], t - 3600)
        st.add_event(t - 10, "10.7.7.7", "late.test", "adult", "alert", 1)
        st.add_event(t - 7200, "10.7.7.7", "early.test", "adult", "alert", 1)   # written last, happened first
        evs = [e["domain"] for e in st.events(device_id=did)]
        self.assertEqual(evs[:2], ["late.test", "early.test"])

    def test_17_dnslib(self):
        q = dnslib.build_query("Example.COM", dnslib.TYPE_A, qid=7)
        name, qtype, qclass, end = dnslib.parse_question(q)
        self.assertEqual((name, qtype, qclass, end), ("Example.COM", 1, 1, len(q)))
        r = dnslib.build_response(q, answers=[(1, b"\x01\x02\x03\x04")], ttl=77)
        hdr, recs = dnslib.parse_records(r)
        self.assertEqual((hdr["id"], hdr["rcode"], hdr["an"]), (7, 0, 1))
        self.assertEqual(recs[0][0], "Example.COM")
        self.assertEqual(dnslib.response_ttl(r), 77)
        self.assertEqual(dnslib.response_ttl(r, cap=50), 50)
        self.assertTrue(dnslib.is_response(r))
        self.assertFalse(dnslib.is_response(q))
        with self.assertRaises(dnslib.DnsError):
            dnslib.parse_question(b"\x00" * 5)
        self.assertEqual(Classifier.candidates("a.b.c.com"), ["a.b.c.com", "b.c.com", "c.com"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
