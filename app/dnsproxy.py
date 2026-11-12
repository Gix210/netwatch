"""The DNS forwarder: every device on the Wi-Fi sends its lookups here. Each query is
classified, journaled, answered from cache or forwarded upstream, or sinkholed."""
import queue
import socket
import socketserver
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import dnslib
from .util import now

NOISE_SUFFIXES = (".arpa", ".local", ".localdomain", ".lan", ".home", ".internal", ".localhost",
                  ".corp", ".intranet", ".workgroup")


def parse_upstream(text):
    text = (text or "").strip()
    if not text:
        return None
    if ":" in text:
        host, port = text.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return None
    return text, 53


class _TcpServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 32

    def __init__(self, addr, proxy):
        self.proxy = proxy
        super().__init__(addr, _TcpHandler)


class _TcpHandler(socketserver.BaseRequestHandler):
    def _readn(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return buf
            buf += chunk
        return buf

    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                hdr = self._readn(2)
                if len(hdr) < 2:
                    break
                (ln,) = struct.unpack("!H", hdr)
                data = self._readn(ln)
                if len(data) < ln:
                    break
                resp = self.server.proxy.handle(data, self.client_address[0], "tcp")
                if resp is None:
                    break
                self.request.sendall(struct.pack("!H", len(resp)) + resp)
        except (OSError, struct.error):
            pass


class DnsProxy:
    def __init__(self, classifier, store, log, on_flag, bind="0.0.0.0", port=53):
        self.classifier = classifier
        self.store = store
        self.log = log
        self.on_flag = on_flag
        self.bind = bind
        self.port = port
        self.upstreams = [("1.1.1.1", 53)]
        self.timeout = 2.5
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.cache_max = 5000
        self.block_ip = "0.0.0.0"
        self.log_local = False
        self.stats = {"queries": 0, "blocked": 0, "flagged": 0, "cache_hits": 0, "upstream_timeouts": 0,
                      "servfail": 0, "started": now()}
        self.listening = False
        self.error = ""
        self.pool = ThreadPoolExecutor(max_workers=48, thread_name_prefix="nw-dns")
        self.recent = {}
        self.recent_lock = threading.Lock()
        self.udp = None
        self.tcp = None
        self._stop = threading.Event()
        # alerts are recorded off the answer path: a busy database (list import, VACUUM) never delays DNS
        self.flag_q = queue.Queue(maxsize=20000)
        threading.Thread(target=self._flag_loop, name="nw-flags", daemon=True).start()

    def configure(self, upstreams=None, timeout=None, cache_max=None, log_local=None, block_ip=None):
        if upstreams is not None:
            ups = [u for u in (parse_upstream(x) for x in upstreams) if u]
            self.upstreams = ups or [("1.1.1.1", 53)]
        if timeout is not None:
            self.timeout = max(0.5, float(timeout))
        if cache_max is not None:
            self.cache_max = max(100, int(cache_max))
        if log_local is not None:
            self.log_local = bool(log_local)
        if block_ip is not None:
            self.block_ip = block_ip
        with self.cache_lock:
            self.cache.clear()

    # ---- lifecycle ----------------------------------------------------------------
    def start(self):
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind((self.bind, self.port))
            if hasattr(socket, "SIO_UDP_CONNRESET"):
                try:
                    udp.ioctl(socket.SIO_UDP_CONNRESET, False)
                except OSError:
                    pass
            self.udp = udp
            self.tcp = _TcpServer((self.bind, self.port), self)
        except OSError as e:
            self.error = str(e)
            self.listening = False
            self.log("error", f"Impossible d'écouter sur {self.bind}:{self.port} (DNS) : {e}")
            if self.udp:
                self.udp.close()
                self.udp = None
            return False
        self.error = ""
        self.listening = True
        threading.Thread(target=self._udp_loop, name="nw-udp", daemon=True).start()
        threading.Thread(target=self.tcp.serve_forever, name="nw-tcp", daemon=True).start()
        self.log("info", f"DNS en écoute sur {self.bind}:{self.port}, relais vers "
                         + ", ".join(f"{h}:{p}" for h, p in self.upstreams))
        return True

    def stop(self):
        self._stop.set()
        self.listening = False
        if self.udp:
            try:
                self.udp.close()
            except OSError:
                pass
        if self.tcp:
            self.tcp.shutdown()
            self.tcp.server_close()
        self.pool.shutdown(wait=False)

    def _udp_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(65535)
            except ConnectionResetError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                time.sleep(0.05)
                continue
            self.pool.submit(self._udp_task, data, addr)

    def _udp_task(self, data, addr):
        try:
            resp = self.handle(data, addr[0], "udp")
            if resp:
                if len(resp) > 4096:
                    resp = resp[:12]
                    resp = resp[:2] + bytes([resp[2] | 0x02, resp[3]]) + resp[4:6] + b"\x00\x00\x00\x00\x00\x00"
                self.udp.sendto(resp, addr)
        except Exception as e:
            self.log("warn", f"Requête DNS de {addr[0]} : {e}")

    # ---- the decision ------------------------------------------------------------
    def handle(self, data, client_ip, proto):
        if len(data) < 12 or dnslib.is_response(data):
            return None
        opcode = (data[2] >> 3) & 0xF
        if opcode != 0:
            # dynamic update, notify, status...: relay untouched, never cached, never classified
            resp = self._forward_tcp(data) if proto == "tcp" else self._forward_udp(data)
            if resp is None:
                return data[:2] + struct.pack("!HHHHH", 0x8000 | (opcode << 11) | dnslib.RCODE_SERVFAIL, 0, 0, 0, 0)
            return resp
        try:
            qname, qtype, qclass, qend = dnslib.parse_question(data)
        except dnslib.DnsError:
            return None
        self.stats["queries"] += 1
        name = qname.lower().rstrip(".")
        ts = now()
        noise = (not name or "." not in name or qtype == dnslib.TYPE_PTR or name.endswith(NOISE_SUFFIXES))
        res = None if noise else self.classifier.classify(name)
        action = res["action"] if res else "none"
        category = res["category"] if res and action in ("log", "alert", "block") else ""
        if action == "block":
            resp = self._sinkhole(data, qtype, res.get("mode", "ip"))
            self.stats["blocked"] += 1
        else:
            resp = self._resolve(data, qname, qtype, qclass, proto, len(data) > qend)
        if not noise or self.log_local:
            self.store.log_query(ts, client_ip, name, category, action == "block")
        if action in ("alert", "block"):
            self.stats["flagged"] += 1
            if self._throttle(client_ip, name, ts):
                try:
                    self.flag_q.put_nowait((ts, client_ip, name, qtype, res))
                except queue.Full:
                    pass
        return resp

    def _flag_loop(self):
        while not self._stop.is_set():
            try:
                item = self.flag_q.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self.on_flag(*item)
            except Exception as e:
                self.log("warn", f"Événement non enregistré : {e}")

    def _throttle(self, ip, name, ts):
        key = (ip, name)
        with self.recent_lock:
            if ts - self.recent.get(key, 0) < 60:
                return False
            self.recent[key] = ts
            if len(self.recent) > 5000:
                self.recent = {k: v for k, v in self.recent.items() if ts - v < 60}
        return True

    def _sinkhole(self, data, qtype, mode):
        if mode == "nx":
            return dnslib.build_response(data, rcode=dnslib.RCODE_NXDOMAIN)
        if qtype in (dnslib.TYPE_A, dnslib.TYPE_ANY):
            return dnslib.build_response(data, answers=[(dnslib.TYPE_A, socket.inet_aton(self.block_ip))], ttl=30)
        return dnslib.build_response(data)

    # ---- cache + forwarding ----------------------------------------------------------
    def _resolve(self, data, qname, qtype, qclass, proto, has_extra):
        key = (qname, qtype, qclass, has_extra)
        t = time.time()
        with self.cache_lock:
            hit = self.cache.get(key)
        if hit and hit[0] > t:
            self.stats["cache_hits"] += 1
            return data[:2] + hit[1][2:]
        resp = self._forward_tcp(data) if proto == "tcp" else self._forward_udp(data)
        if resp is None:
            self.stats["servfail"] += 1
            return dnslib.build_response(data, rcode=dnslib.RCODE_SERVFAIL)
        rcode = dnslib.rcode_of(resp)
        if rcode in (dnslib.RCODE_OK, dnslib.RCODE_NXDOMAIN) and not dnslib.is_truncated(resp):
            ttl = dnslib.response_ttl(resp) if rcode == dnslib.RCODE_OK else 30
            with self.cache_lock:
                if len(self.cache) >= self.cache_max:
                    self._evict(t)
                self.cache[key] = (t + ttl, resp)
        return resp

    def _evict(self, t):
        self.cache = {k: v for k, v in self.cache.items() if v[0] > t}
        if len(self.cache) >= self.cache_max:
            for k in list(self.cache)[: self.cache_max // 5]:
                del self.cache[k]

    def _forward_udp(self, data):
        for host, port in self.upstreams:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.sendto(data, (host, port))
                deadline = time.time() + self.timeout
                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise socket.timeout()
                    s.settimeout(remaining)
                    resp, _ = s.recvfrom(65535)
                    if len(resp) >= 12 and resp[:2] == data[:2]:
                        return resp
            except (socket.timeout, OSError):
                self.stats["upstream_timeouts"] += 1
                continue
            finally:
                s.close()
        return None

    def _forward_tcp(self, data):
        for host, port in self.upstreams:
            try:
                with socket.create_connection((host, port), timeout=self.timeout) as s:
                    s.sendall(struct.pack("!H", len(data)) + data)
                    hdr = b""
                    while len(hdr) < 2:
                        chunk = s.recv(2 - len(hdr))
                        if not chunk:
                            raise OSError("closed")
                        hdr += chunk
                    (ln,) = struct.unpack("!H", hdr)
                    buf = b""
                    while len(buf) < ln:
                        chunk = s.recv(ln - len(buf))
                        if not chunk:
                            raise OSError("closed")
                        buf += chunk
                    return buf
            except (socket.timeout, OSError):
                self.stats["upstream_timeouts"] += 1
                continue
        return None

    def status(self):
        with self.cache_lock:
            n = len(self.cache)
        return {"listening": self.listening, "error": self.error, "bind": self.bind, "port": self.port,
                "upstreams": [f"{h}:{p}" for h, p in self.upstreams], "cache_entries": n,
                "block_ip": self.block_ip, "stats": dict(self.stats)}
