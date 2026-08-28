"""web-010 真执行靶机：文件上传 → RCE（upload to RCE）。

模拟真实 Web 题：/web-010/upload 接收文件内容（raw body + ?name=），落地到
uploads/；/web-010/preview?name=<f> 若后缀为 .py 则「错误地」用子进程执行该上传
文件（典型上传 RCE 误配置），返回其 stdout —— 即 RCE。

flag 由靶机启动时写入 tempfile（ctf_upload_rce_flag.txt），主 Agent 经 toolkit
._FALLBACK_UPLOAD_RCE ① 上传 .py 探针证明代码执行 ② 走受信 RCE 通道
（sandbox.trusted_rce，CTF_AGENT_TRUSTED_RCE=1）读取该共享 temp 文件拿 flag。

沙盒友好：探针 .py 为纯 print，受信通道默认关（opt-in）。仅供 127.0.0.1 训练。
启动：.venv/Scripts/python.exe scripts/web_target_upload_rce.py
"""
from __future__ import annotations

import http.server
import os
import subprocess
import sys
import tempfile
import threading
import urllib.parse

import httpx

PORT = 9010
FLAG = "flag{upload_rce_2026}"
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "ctf_web010_uploads")


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
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path != "/web-010/upload":
            self._send(404, "not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        name = qs.get("name", ["shell.py"])[0]
        # 仅允许基本文件名，防目录穿越落盘
        safe = os.path.basename(name)
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        path = os.path.join(UPLOAD_DIR, safe)
        with open(path, "wb") as fh:
            fh.write(body)
        self._send(200, "stored name=%s" % safe)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/web-010":
            self._send(200, "<h1>Web-010</h1><p>Upload service. POST ?name= to /web-010/upload, then /web-010/preview?name= to run it.</p>")
            return
        if parsed.path == "/web-010/preview":
            name = qs.get("name", [""])[0]
            safe = os.path.basename(name)
            path = os.path.join(UPLOAD_DIR, safe)
            if not safe.endswith(".py") or not os.path.isfile(path):
                self._send(400, "only .py preview supported")
                return
            # 漏洞：用子进程执行上传的文件（上传 RCE 误配置）
            try:
                r = subprocess.run([sys.executable, "-c", open(path, encoding="utf-8", errors="replace").read()],
                                   capture_output=True, text=True, timeout=10, cwd=UPLOAD_DIR)
                self._send(200, (r.stdout or "") + (r.stderr or ""))
            except Exception as e:  # noqa: BLE001
                self._send(200, "exec_error: %s" % e)
            return
        self._send(404, "not found")

    def log_message(self, *args):
        pass


def start() -> str:
    flag_path = os.path.join(tempfile.gettempdir(), "ctf_upload_rce_flag.txt")
    with open(flag_path, "w", encoding="utf-8") as fh:
        fh.write(FLAG)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return "http://127.0.0.1:%d/web-010" % PORT


if __name__ == "__main__":
    import subprocess as _sp  # noqa: F401  (Handler 内已用)
    print("web-010 upload-rce target up at", start())
    threading.Event().wait()
