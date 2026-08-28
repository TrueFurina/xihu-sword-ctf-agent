"""web-003 真执行靶机：PHP 反序列化 __destruct 读 flag 模拟。

仅本地训练用：GET 接收 base64 的 PHP 序列化对象（WebToolkit._FALLBACK_UNSERIALIZE 发到
data/token/input/file 参数），检测到 "file" 键指向 flag 路径时模拟 __destruct 读 flag 返回 FLAG。
self_authored_training，不计入任何 KPI；用于验证主 Agent 在反序列化类 web 题上的路由泛化。

用法：
    .venv/Scripts/python.exe scripts/web_target_unserialize.py        # 起服务（默认 9003）
"""
from __future__ import annotations

import base64
import http.server
import re
import threading
import urllib.parse

PORT = 9003
FLAG = "flag{unserialize_destruct_2026}"

_PROBE = ['data', 'token', 'input', 'file']
# 匹配 PHP 序列化：O:..: "Class":1:{ s:4:"file"; s:9:"/flag.txt"; }
_FILE_RE = re.compile(r's:\d+:"file";s:\d+:"([^"]*)"')


def _check(payload_b64: str) -> str | None:
    """解码 base64 序列化对象，模拟 __destruct 读取 file 指向的 flag。"""
    try:
        raw = base64.b64decode(payload_b64).decode("utf-8", "replace")
    except Exception:
        return None
    m = _FILE_RE.search(raw)
    if m and "flag" in m.group(1).lower():
        return FLAG
    if "flag" in raw.lower():  # 宽松匹配：任何指向 flag 的序列化载荷都模拟命中
        return FLAG
    return None


class _Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, body, ctype: str = "text/html", status: int = 200) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        for key in _PROBE:
            if key in qs and qs[key]:
                flag = _check(qs[key][0])
                if flag:
                    self._send(flag)  # 干净输出 flag{...}
                    return
        self._send(
            "<!DOCTYPE html><html><head><title>Unserialize Demo</title></head>"
            "<body><h1>Object Restore</h1>"
            "<p>hint: submit a base64 PHP serialized object with a 'file' property.</p>"
            "</body></html>"
        )

    def log_message(self, *args):  # 静默
        return


class UnserializeWebTarget:
    """起真执行 web-003 反序列化靶机。"""

    def __init__(self, host: str = "127.0.0.1", port: int = PORT) -> None:
        self.host = host
        self.port = port
        self._server = None
        self._thread = None

    def start(self) -> str:
        self._server = http.server.ThreadingHTTPServer((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        addr = f"http://{self.host}:{self.port}/"
        self.addr = addr
        return addr

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()


def _standalone() -> None:
    import time

    t = UnserializeWebTarget()
    addr = t.start()
    print(f"web-003 反序列化真执行靶机已启动: {addr}")
    print(f"  预期 flag: {FLAG}")
    print("按 Ctrl+C 退出")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        t.stop()


if __name__ == "__main__":
    _standalone()
