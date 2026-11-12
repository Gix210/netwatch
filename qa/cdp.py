"""Headless Chrome over the DevTools protocol, standard library only.
Used by qa/manual_shots.py to take the manual's screenshots."""
import base64
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

CHROME = os.environ.get("NW_CHROME") or r"C:\Program Files\Google\Chrome\Application\chrome.exe"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class WebSocket:
    """Client WebSocket: HTTP upgrade, masked text frames, fragmented replies, pings answered."""

    def __init__(self, url, timeout=60):
        m = re.match(r"^ws://([^/:]+):(\d+)(/.*)?$", url)
        if not m:
            raise ValueError("bad ws url: %s" % url)
        host, port, path = m.group(1), int(m.group(2)), m.group(3) or "/"
        self.sock = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        self.sock.sendall(("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key)).encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("websocket upgrade: connection closed")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise ConnectionError("websocket upgrade refused")
        self.buf = rest

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise ConnectionError("websocket closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send_text(self, text):
        payload = text.encode("utf-8")
        mask = os.urandom(4)
        n = len(payload)
        head = bytes([0x81])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", n)
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def recv_text(self):
        message, opcode = b"", None
        while True:
            b0, b1 = self._read(2)
            fin, op, masked, n = b0 & 0x80, b0 & 0x0F, b1 & 0x80, b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            mask = self._read(4) if masked else None
            data = self._read(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if op == 0x9:
                self.sock.sendall(bytes([0x8A, 0x80 | min(len(data), 125)]) + b"\x00\x00\x00\x00" + data[:125])
                continue
            if op == 0xA:
                continue
            if op == 0x8:
                raise ConnectionError("websocket closed by peer")
            if op in (0x1, 0x2):
                opcode, message = op, data
            elif op == 0x0:
                message += data
            if fin and opcode is not None:
                return message.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.sendall(bytes([0x88, 0x80]) + b"\x00\x00\x00\x00")
            self.sock.close()
        except OSError:
            pass


class CDP:
    def __init__(self, ws_url, timeout=60):
        self.ws = WebSocket(ws_url, timeout)
        self.next_id = 0
        self.lock = threading.Lock()

    def send(self, method, params=None, timeout=60):
        with self.lock:
            self.next_id += 1
            msg_id = self.next_id
            self.ws.send_text(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
            deadline = time.time() + timeout
            while time.time() < deadline:
                msg = json.loads(self.ws.recv_text())
                if msg.get("id") == msg_id:
                    if "error" in msg:
                        raise RuntimeError("CDP %s: %s" % (method, msg["error"]))
                    return msg.get("result", {})
            raise TimeoutError("CDP %s: no answer" % method)

    def close(self):
        self.ws.close()


class Chrome:
    """Headless Chrome on a free debugging port with one desktop tab (Page)."""

    def __init__(self, width=1280, height=800):
        if not os.path.exists(CHROME):
            raise RuntimeError("Chrome not found at %s (set NW_CHROME)" % CHROME)
        self.port = free_port()
        self.profile = tempfile.mkdtemp(prefix="nw-chrome-")
        self.proc = subprocess.Popen([CHROME, "--headless=new", "--remote-debugging-port=%d" % self.port,
                                      "--user-data-dir=%s" % self.profile, "--no-first-run", "--no-default-browser-check", "--no-sandbox",
                                      "--disable-gpu", "--disable-extensions", "--disable-background-networking",
                                      "--disable-component-update", "--disable-sync", "--metrics-recording-only",
                                      "--window-size=%d,%d" % (width, height), "--hide-scrollbars", "about:blank"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.time()
        while time.time() - t0 < 30:
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/json/version" % self.port, timeout=2):
                    break
            except Exception:
                time.sleep(0.2)
        else:
            self.stop()
            raise RuntimeError("Chrome did not open its debugging port")
        endpoint = "http://127.0.0.1:%d/json/new?about:blank" % self.port
        try:
            with urllib.request.urlopen(urllib.request.Request(endpoint, method="PUT"), timeout=5) as r:
                target = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError:
            with urllib.request.urlopen(endpoint, timeout=5) as r:
                target = json.loads(r.read().decode("utf-8"))
        self.cdp = CDP(target["webSocketDebuggerUrl"])
        self.cdp.send("Page.enable")
        self.cdp.send("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": False})

    def eval(self, expr, await_promise=True):
        r = self.cdp.send("Runtime.evaluate", {"expression": expr, "awaitPromise": await_promise, "returnByValue": True})
        if "exceptionDetails" in r:
            raise RuntimeError("JS error: %s" % r["exceptionDetails"].get("text"))
        return r.get("result", {}).get("value")

    def goto(self, url):
        self.cdp.send("Page.navigate", {"url": url})

    def wait(self, expr, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            try:
                if self.eval("!!(%s)" % expr):
                    return True
            except RuntimeError:
                pass
            time.sleep(0.25)
        raise TimeoutError("page condition not met: %s" % expr)

    def screenshot(self, path):
        data = self.cdp.send("Page.captureScreenshot", {"format": "png"})["data"]
        with open(path, "wb") as f:
            f.write(base64.b64decode(data))

    def stop(self):
        try:
            self.cdp.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        shutil.rmtree(self.profile, ignore_errors=True)
