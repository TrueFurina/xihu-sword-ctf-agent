"""本地 mock 靶机：模拟 CTF web 赛题靶机，用于 M5 离线演练。

提供三种可达性场景（对应决赛 web 题真实拓扑）：
  1) HTTP 靶机      —— 直接 http://host:port/ 可达
  2) HTTPS 靶机     —— 自签证书，httpx verify=False 可达
  3) 正向代理       —— 靶机需经 HTTP 代理访问（决赛平台常见 proxy 端口）

页面内埋 `DASCTF{...}` 线索，用于验证 web_target_interact 的 flag_hints 提取。

用法:
    .venv/Scripts/python.exe scripts/_mock_web_target.py          #  standalone：起三服务并打印地址
    from scripts._mock_web_target import MockTarget; t = MockTarget(); t.start()  # 测试用
"""

from __future__ import annotations

import http.server
import ssl
import subprocess
import tempfile
import threading
import urllib.request
from pathlib import Path

# 模拟一个 CMS 登录页 + 藏 flag 线索（审计/交互应能在正文拿到）
PAGE_HTML = b"""<!DOCTYPE html>
<html><head><title>Login - MockCTF</title></head>
<body>
  <h1>Admin Login</h1>
  <form action="/login" method="post">
    <input name="user" /><input name="pass" type="password" />
    <input type="hidden" name="csrf" value="deadbeef" />
  </form>
  <!-- debug hint leaked in html comment: DASCTF{mock_web_target_flag_2026} -->
  <a href="/admin">admin panel</a>
  <a href="/robots.txt">robots</a>
</body></html>
"""

FLAG_HINT = b"DASCTF{mock_web_target_flag_2026}"


class _Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, body: bytes, ctype: str = "text/html") -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/robots.txt":
            self._send(b"User-agent: *\nDisallow: /admin\n")
        else:
            self._send(PAGE_HTML)

    def do_POST(self):
        self._send(b'{"ok":false,"msg":"invalid credentials"}', "application/json")

    def log_message(self, *a):  # 静默
        pass


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    """极简 HTTP 正向代理：仅转发 GET（覆盖 http 靶机经代理场景）。"""

    def do_GET(self):
        try:
            with urllib.request.urlopen(self.path, timeout=5) as r:
                data = r.read()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:  # noqa: BLE001
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, *a):
        pass


def _gen_cert() -> tuple[str, str]:
    d = tempfile.mkdtemp(prefix="mocktls_")
    cert = str(Path(d) / "cert.pem")
    key = str(Path(d) / "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return cert, key


class MockTarget:
    """起 HTTP / HTTPS / 代理 三个本地服务，用完 stop()。"""

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self._http = None
        self._https = None
        self._proxy = None
        self._threads = []

    def start(self) -> dict:
        # HTTP
        self._http = http.server.ThreadingHTTPServer((self.host, 0), _Handler)
        # HTTPS（自签）
        cert, key = _gen_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self._https = http.server.ThreadingHTTPServer((self.host, 0), _Handler)
        self._https.socket = ctx.wrap_socket(self._https.socket, server_side=True)
        # 代理
        self._proxy = http.server.ThreadingHTTPServer((self.host, 0), _ProxyHandler)

        for srv in (self._http, self._https, self._proxy):
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._threads.append(t)

        addrs = {
            "http": f"http://{self.host}:{self._http.server_address[1]}/",
            "https": f"https://{self.host}:{self._https.server_address[1]}/",
            "proxy": f"http://{self.host}:{self._proxy.server_address[1]}/",
        }
        self.addrs = addrs
        return addrs

    def stop(self) -> None:
        for srv in (self._http, self._https, self._proxy):
            if srv:
                srv.shutdown()
                srv.server_close()


def _standalone() -> None:
    t = MockTarget()
    addrs = t.start()
    print("MockTarget 已启动：")
    for k, v in addrs.items():
        print(f"  {k:6s}: {v}")
    print(f"  页面含 flag 线索: {FLAG_HINT.decode()}")
    print("按 Ctrl+C 退出")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        t.stop()


if __name__ == "__main__":
    _standalone()
