"""web-005 真执行靶机：JWT 弱密钥伪造（HS256 验签，secret='secret'）。

模拟真实 JWT 鉴权接口：GET 读 Authorization: Bearer <token>，用弱密钥验签，
role==admin 返回 flag。secret='secret' 落在 toolkit 弱密钥爆破表中，可自动伪造。

端口 9005。运行：.venv/Scripts/python.exe scripts/web_target_jwt.py
手写 base64url + hmac 验签，零第三方依赖。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT = 9005
SECRET = "secret"
FLAG = "flag{jwt_weak_key_2026}"


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


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
        if not path.endswith("/web-005"):
            self._send(404, "not found")
            return
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._send(401, "missing bearer token")
            return
        token = auth[7:].strip()
        parts = token.split(".")
        if len(parts) != 3:
            self._send(400, "malformed token")
            return
        header_b64, payload_b64, sig_b64 = parts
        # 用弱密钥重算签名
        expected = hmac.new(SECRET.encode(), f"{header_b64}.{payload_b64}".encode(),
                             hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode()
        if not hmac.compare_digest(expected_b64, sig_b64):
            self._send(403, "invalid signature")
            return
        try:
            payload = json.loads(_b64url_decode(payload_b64))
        except Exception:
            self._send(400, "bad payload")
            return
        if payload.get("role") == "admin":
            self._send(200, f"admin access granted: {FLAG}")
        else:
            self._send(200, "normal user, no flag for you")


def start():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return ("127.0.0.1", PORT), srv


if __name__ == "__main__":
    addr, srv = start()
    print(f"web-005 JWT 弱密钥靶机已启动于 http://{addr[0]}:{addr[1]}/web-005")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
