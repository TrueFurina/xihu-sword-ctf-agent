"""web-011 真执行靶机：不安全反序列化 → RCE（insecure deserialization to RCE）。

模拟真实 Web 题：/web-011/unserialize 接收 base64(pickle) 并 pickle.loads 还原
对象——经典反序列化 RCE（Python pickle 反序列化即执行 __reduce__ 指定的任意代码）。
靶机返回还原对象的 repr，若攻击 payload 的 __reduce__ 执行了命令并返回可见结果，
即证明 RCE。

flag 由靶机启动时写入 tempfile（ctf_unser_rce_flag.txt），主 Agent 经 toolkit
._FALLBACK_UNSERIALIZE_RCE ① 构造恶意 pickle 证明代码执行 ② 走受信 RCE 通道读取
共享 temp 文件拿 flag。

仅供 127.0.0.1 训练；pickle 反序列化 RCE 与本仓库无关，纯靶机内行为。
启动：.venv/Scripts/python.exe scripts/web_target_unserialize_rce.py
"""
from __future__ import annotations

import base64
import http.server
import os
import pickle
import sys
import tempfile
import threading
import urllib.parse

PORT = 9011
FLAG = "flag{unserialize_pop_rce_2026}"


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body: str) -> None:
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/web-011/unserialize":
            self._send(404, "not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", "replace").strip()
        try:
            obj = pickle.loads(base64.b64decode(raw))  # 漏洞点：反序列化即执行
            self._send(200, "unserialized=%r" % (obj,))
        except Exception as e:  # noqa: BLE001
            self._send(200, "unserialize_error: %r" % e)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/web-011":
            self._send(200, "<h1>Web-011</h1><p>Unserialize service. POST base64(pickle) to /web-011/unserialize.</p>")
            return
        self._send(404, "not found")

    def log_message(self, *args):
        pass


def start() -> str:
    flag_path = os.path.join(tempfile.gettempdir(), "ctf_unser_rce_flag.txt")
    with open(flag_path, "w", encoding="utf-8") as fh:
        fh.write(FLAG)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return "http://127.0.0.1:%d/web-011" % PORT


if __name__ == "__main__":
    print("web-011 unserialize-rce target up at", start())
    threading.Event().wait()
