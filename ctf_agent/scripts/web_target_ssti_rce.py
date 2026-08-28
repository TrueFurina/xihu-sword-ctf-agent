"""web-008：SSTI RCE 真靶机（self_authored_training，不计 KPI）。

设计要点
--------
- 模板渲染 `{{ expr }}`：`{{7*7}}` -> 49（证明存在代码执行）；`{{ FLAG }}` 仅返回
  **诱饵**（flag{ssti_leak_decoy_2026}），真实 flag **不在模板上下文里**。
- 真实 flag 由靶机启动时写入 `tempfile.gettempdir()/ctf_ssti_rce_flag.txt`，
  代表「靶机文件系统上的文件」。要拿到它，agent 必须**经 RCE 后渗透读文件**——
  这正对应真实 SSTI RCE 题的利用链（模板代码执行 -> 读服务器上的 flag 文件）。

为什么这样设计：纯泄漏型 SSTI（`{{ FLAG }}` 直接出 flag）已被 web-002 覆盖并证明
可解；web-008 故意把 flag 移出模板上下文，强制走「代码执行 -> 命令读取文件」的
RCE 路径，从而验证主 Agent 在「受信 RCE 通道」支撑下能否自动解 RCE 类 web 题。

靶机仅监听 127.0.0.1（回环），属自研训练靶，无外部影响面。
"""
from __future__ import annotations

import http.server
import os
import re
import socketserver
import tempfile
import threading
import urllib.parse

PORT = 9008
REAL_FLAG = "flag{ssti_rce_2026}"
DECOY_FLAG = "flag{ssti_leak_decoy_2026}"
FLAG_FILE = os.path.join(tempfile.gettempdir(), "ctf_ssti_rce_flag.txt")


def render(expr: str) -> str:
    """安全渲染：仅做算术/简单表达式 eval（无 os 命名空间），避免靶机自身真 RCE。"""
    if expr.strip() == "FLAG":
        return DECOY_FLAG  # 泄漏型只给诱饵，真实 flag 在文件系统
    try:
        return str(eval(expr, {"__builtins__": {}}, {}))
    except Exception:
        return "[render error]"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        name = qs.get("name", [""])[0]
        if "{{" in name and "}}" in name:
            m = re.search(r"\{\{(.+?)\}\}", name, re.S)
            out = render(m.group(1)) if m else "[no expr]"
        else:
            out = (
                "<h1>Web-008</h1>"
                "<p>SSTI challenge. You can achieve code execution in the template, "
                "but the flag is NOT in the template context — leak gives only a decoy. "
                "Read it from the server filesystem via RCE.</p>"
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(out.encode("utf-8"))

    def log_message(self, *args) -> None:  # 静默日志
        pass


def start() -> str:
    # 写入真实 flag 到「靶机文件系统」
    with open(FLAG_FILE, "w", encoding="utf-8") as f:
        f.write(REAL_FLAG)
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return "http://127.0.0.1:%d/web-008" % PORT


if __name__ == "__main__":
    addr = start()
    print("web-008 up at", addr, "| real flag file:", FLAG_FILE)
    # 常驻（训练靶机由外层进程管理生命周期）
    threading.Event().wait()
