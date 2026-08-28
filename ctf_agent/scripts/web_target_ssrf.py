"""web-007 真执行靶机：SSRF 回环读 flag（server-side request forgery）。

模拟真实 Web 题：/web-007 接受 url 参数，服务端代发请求到该地址并把响应返回——
典型 SSRF。内部 /flag 端点返回 flag；当主 Agent 经 toolkit._FALLBACK_SSRF 下发
http://127.0.0.1:9007/flag 时，靶机服务端回环抓取自身 /flag 把 flag 带出。

沙盒友好：纯 GET + 服务端 httpx 代发，不发 os.popen / 命令注入，不被沙盒拦截。

启动：.venv/Scripts/python.exe scripts/web_target_ssrf.py
"""
from __future__ import annotations

import http.server
import threading
import urllib.parse

import httpx

PORT = 9007
FLAG = "flag{ssrf_loopback_2026}"


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, ctype: str, body: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode("utf-8", "replace"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        # 内部 flag 端点（SSRF 回环抓取目标）
        if path in ("/flag", "/flag.txt"):
            self._send(200, "text/plain", FLAG)
            return

        if path == "/web-007":
            url = qs.get("url", [None])[0]
            if url:
                try:
                    r = httpx.get(url, timeout=5, follow_redirects=True)
                    self._send(200, "text/plain", r.text)
                except Exception as e:  # noqa: BLE001
                    self._send(200, "text/plain", "fetch_error: %s" % e)
                return
            self._send(200, "text/html",
                       "<h1>Web-007</h1><p>URL preview service. "
                       "Pass ?url= to let the server fetch it for you.</p>")
            return

        self._send(404, "text/plain", "not found")

    def log_message(self, *args):
        pass


def start() -> str:
    # ThreadingHTTPServer：SSRF 处理中会「服务端代发请求回环抓取自身端口」，
    # 必须用多线程服务器，否则单线程死锁（新连接无法被接受，外圈 httpx 连接被拒）。
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return "http://127.0.0.1:%d/web-007" % PORT


if __name__ == "__main__":
    addr = start()
    print("web-007 ssrf target up at", addr)
    threading.Event().wait()
