"""web-004 真执行靶机：路径穿越读取 flag（纯 GET 文件读取，沙盒友好）。

模拟真实「文件下载」功能路径穿越：服务端用不净化的 os.path.join 拼路径，
FLAG 放在 BASE 的父目录，需 ../ 穿越才能读到，复现经典 ../ 穿越语义。

端口 9004。运行：.venv/Scripts/python.exe scripts/web_target_traversal.py
"""
from __future__ import annotations

import os
import tempfile
import threading

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 9004
FLAG = "flag{path_traversal_read_2026}"

# 工作目录放在系统临时区，避免污染仓库
TMP = os.path.join(tempfile.gettempdir(), "ctf_web004")
BASE_DIR = os.path.join(TMP, "safe")          # 受"保护"的下载根目录
FLAG_PATH = os.path.join(TMP, "flag.txt")     # FLAG 在 BASE 父级，需 ../ 穿越


def _ensure() -> None:
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(os.path.join(BASE_DIR, "welcome.txt"), "w", encoding="utf-8") as f:
        f.write("this is a safe file; the flag is NOT here")
    with open(FLAG_PATH, "w", encoding="utf-8") as f:
        f.write(FLAG + "\n")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默
        pass

    def _send(self, code: int, body: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        path = urlparse(self.path).path
        if not path.endswith("/web-004"):
            self._send(404, "not found")
            return
        qs = parse_qs(urlparse(self.path).query)
        cand = None
        for k in ("download", "file", "path", "filename"):
            if k in qs:
                cand = qs[k][0]
                break
        if cand is None:
            self._send(400, "missing file param (download/file/path/filename)")
            return
        # 漏洞点：不净化 ../，直接 join -> 路径穿越
        target = os.path.normpath(os.path.join(BASE_DIR, cand))
        if os.path.isfile(target):
            with open(target, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            self._send(200, content)
        else:
            self._send(404, "file not found: " + cand)


def start():
    _ensure()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return ("127.0.0.1", PORT), srv


if __name__ == "__main__":
    addr, srv = start()
    print(f"web-004 路径穿越靶机已启动于 http://{addr[0]}:{addr[1]}/web-004")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
