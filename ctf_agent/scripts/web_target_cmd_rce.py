"""web-009：命令注入 RCE 真靶机（self_authored_training，不计 KPI）。

设计要点（镜像 web-008 抽象，验证受信 RCE 通道可复用）
------------------------------------------------------
- 服务端把 `cmd` 参数**未加引号拼接**进 shell 命令，制造命令注入点：
  `;id` -> 靶机执行 id 并返回 uid/gid（证明存在命令执行）。
- 真实 flag 由靶机启动时写入 `tempfile.gettempdir()/ctf_cmd_rce_flag.txt`，
  代表「靶机文件系统上的文件」。要拿到它，agent 必须**经 RCE 后渗透读文件**——
  这正对应真实命令注入题的利用链（注入点 -> 读服务器上的 flag 文件）。

为什么这样设计：纯 HTTP 响应返回的"命令注入读 flag"可用现有沙盒友好的
`_FALLBACK_CMD`（纯 httpx）解出；web-009 故意把 flag 移出命令执行响应、放到
文件系统，强制走「命令执行证明 -> 经受信 RCE 通道读文件」的 RCE 后渗透路径，
从而验证主 Agent 在「受信 RCE 通道」支撑下能否自动解**命令注入类** RCE 题
（与 web-008 的 SSTI RCE 形成两个不同子类，证明通道可泛化复用，非 SSTI 单点）。

靶机仅监听 127.0.0.1（回环），属自研训练靶，无外部影响面。
"""
from __future__ import annotations

import http.server
import os
import socketserver
import subprocess
import tempfile
import threading
import urllib.parse

PORT = 9009
REAL_FLAG = "flag{cmd_injection_rce_2026}"
FLAG_FILE = os.path.join(tempfile.gettempdir(), "ctf_cmd_rce_flag.txt")


def exec_injection(user_input: str) -> str:
    """故意的命令注入点：把输入未加引号拼到 shell 命令里。

    注意：flag 文件**不在**命令执行响应里——它只存在于文件系统，
    需经受信 RCE 通道后渗透读取（与 web-008 抽象一致）。
    """
    # 不引号包裹 user_input：';id' 会变成 `echo input: ; id` 两段执行
    cmd = "echo input: " + user_input
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5,
            env={k: v for k, v in os.environ.items()
                 if "KEY" not in k.upper() and "SECRET" not in k.upper()
                 and "TOKEN" not in k.upper()},
        )
        return (proc.stdout or "")[:500]
    except Exception:
        return "[exec error]"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        cmd = qs.get("cmd", [""])[0] or qs.get("c", [""])[0] or qs.get("input", [""])[0]
        if cmd:
            out = exec_injection(cmd)
        else:
            out = (
                "<h1>Web-009</h1>"
                "<p>Command Injection challenge. You have command execution on the "
                "server, but the flag is NOT printed by your command — it lives on "
                "the server filesystem. Read it via post-exploitation (RCE).</p>"
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
    return "http://127.0.0.1:%d/web-009" % PORT


if __name__ == "__main__":
    addr = start()
    print("web-009 up at", addr, "| real flag file:", FLAG_FILE)
    # 常驻（训练靶机由外层进程管理生命周期）
    threading.Event().wait()
