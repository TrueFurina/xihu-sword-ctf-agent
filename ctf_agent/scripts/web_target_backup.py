"""web-006 真执行靶机：备份文件源码泄露（backup disclosure）。

模拟真实 Web 题：站点存在可访问的源码备份文件（.bak），其中含 flag。
主 Agent 走 toolkit._FALLBACK_BACKUP（GET 探测 index.php.bak / flag.php.bak 等），
脚本打印命中文件正文，extract_flag 从中抓出 flag{...}。

沙盒友好：纯 GET 静态文件读取，不发 os.popen / 命令注入，不被沙盒拦截。

启动：.venv/Scripts/python.exe scripts/web_target_backup.py
"""
from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.parse

PORT = 9006
FLAG = "flag{backup_leak_2026}"

# 备份文件内容（模拟泄露的源码快照，内含 flag）
BACKUPS = {
    "index.php.bak": "<?php\n// index.php (开发备份，未删)\n$secret = '%s';\nfunction check() { return $secret; }\n" % FLAG,
    "flag.php.bak": "<?php\n// flag.php 备份\n$flag = '%s';\n" % FLAG,
    "www.zip": "PK\x03\x04 fake-archive-bytes-not-flag",
    "db.sql": "-- db dump (no flag)\nINSERT INTO users VALUES (1, 'admin', 'x');\n",
}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, ctype: str, body: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode("utf-8", "replace"))

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/web-006", "/web-006/"):
            self._send(200, "text/html",
                       "<h1>Web-006</h1><p>Backup disclosure challenge. "
                       "Maybe a source backup is still reachable?</p>")
            return
        if path.startswith("/web-006/"):
            fname = path[len("/web-006/"):]
            if fname in BACKUPS:
                self._send(200, "text/plain", BACKUPS[fname])
                return
        self._send(404, "text/plain", "not found")

    def log_message(self, *args):
        pass


def start() -> str:
    httpd = socketserver.TCPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return "http://127.0.0.1:%d/web-006" % PORT


if __name__ == "__main__":
    addr = start()
    print("web-006 backup target up at", addr)
    threading.Event().wait()
