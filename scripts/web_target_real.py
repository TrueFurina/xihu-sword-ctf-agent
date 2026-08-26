"""web-001 真执行靶机：替代 _mock_web_target.py 的静态死页面。

第九轮计划 3.5 真杠杆落地：把"正则认输"的 mock 升级为**真执行**后端——
带 sqlite 数据库的登录接口，SQL 用字符串拼接（存在注入漏洞），
`admin' OR '1'='1'-- -` 能真查询到 admin 并返回 flag。

WAF：拦截拖库类关键字（UNION / SLEEP / BENCHMARK / information_schema / /**/ 注释）
但**放行** OR '1'='1' 类的登录绕过（这是题面预期解"WAF 过滤部分关键字"），
确保靶机"仁慈度下降、练兵价值上升"——主 Agent 必须真推理注入才能拿到 flag，
而非正则从 HTML 注释里捡。

不计分练兵场：比赛已结束、平台不可达，本靶机仅用于暴露主 Agent 在 web 上的
真实 LLM 能力缺口（E 类问题），不计入任何 KPI。

用法：
    .venv/Scripts/python.exe scripts/web_target_real.py          # 起服务（默认 9001）
    from scripts.web_target_real import RealWebTarget; t = RealWebTarget(); t.start()
"""
from __future__ import annotations

import http.server
import sqlite3
import threading
import urllib.parse
from pathlib import Path

PORT = 9001
FLAG = "flag{sqli_waf_bypass_2026}"

# WAF：拖库类关键字拦截（大小写不敏感）。放行 OR '1'='1' 登录绕过。
_WAF_BLOCK = [
    "union", "sleep(", "benchmark(", "information_schema",
    "/*", "*/", "--+", "1=1--+", "or 1=1", "or 1 = 1",
]


def _waf_hit(s: str) -> str | None:
    low = (s or "").lower()
    for kw in _WAF_BLOCK:
        if kw in low:
            return kw
    return None


def _init_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, flag TEXT)")
    # 仅 admin 持有 flag；密码故意设为一个非 admin 的值，迫使走注入
    con.execute("INSERT INTO users (username, password, flag) VALUES ('admin', 's3cr3t_pw', ?)",
                (FLAG,))
    con.execute("INSERT INTO users (username, password, flag) VALUES ('guest', 'guest', 'no_flag_here')")
    con.commit()
    return con


class _Handler(http.server.BaseHTTPRequestHandler):
    db: sqlite3.Connection = None  # 类级共享连接（由 RealWebTarget 注入）

    def _send(self, body: bytes, ctype: str = "text/html", status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        parsed = urllib.parse.parse_qs(raw)
        return {k: (v[0] if v else "") for k, v in parsed.items()}

    def do_GET(self):
        if self.path == "/robots.txt":
            self._send(b"User-agent: *\nDisallow: /admin\n")
            return
        html = (
            b"<!DOCTYPE html><html><head><title>Login - RealCTF</title></head>"
            b"<body><h1>Admin Login</h1>"
            b'<form action="/login" method="post">'
            b'<input name="username" /><input name="password" type="password" />'
            b'<input type="submit" value="Login"></form>'
            b"<p>hint: WAF blocks UNION/SLEEP but login bypass works</p>"
            b"</body></html>"
        )
        self._send(html)

    def do_POST(self):
        # 靶机仅登录功能：/login 与 /web-001 均走登录逻辑（匹配题面写的靶机 URL）
        form = self._read_form()
        u = form.get("username", "")
        p = form.get("password", "")

        # WAF：拦截拖库关键字
        hit = _waf_hit(u) or _waf_hit(p)
        if hit:
            self._send(
                f"403 Forbidden: WAF blocked keyword '{hit}'".encode(),
                status=403,
            )
            return

        # 漏洞 SQL：字符串拼接（故意不过滤）
        sql = f"SELECT username, flag FROM users WHERE username='{u}' AND password='{p}'"
        try:
            rows = self.db.execute(sql).fetchall()
        except sqlite3.Error as e:
            # SQL 语法错误回显（注入探测的关键信号）
            self._send(f"500 Internal: sqlite error: {e}".encode(), status=500)
            return

        if rows:
            user, flag = rows[0]
            if flag and flag != "no_flag_here":
                # 直接输出干净 flag 值（已是 flag{...} 格式），便于主 Agent 正则提取
                self._send(f"Welcome {user}! {flag}".encode())
                return
            self._send(f"Welcome {user}! (no flag for you)".encode())
            return
        self._send(b"invalid credentials", status=401)


class RealWebTarget:
    """起真执行 web-001 靶机（sqlite 后端 + SQL 注入漏洞）。"""

    def __init__(self, host: str = "127.0.0.1", port: int = PORT) -> None:
        self.host = host
        self.port = port
        self._server = None
        self._thread = None

    def start(self) -> str:
        _Handler.db = _init_db()
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
    t = RealWebTarget()
    addr = t.start()
    print(f"web-001 真执行靶机已启动: {addr}")
    print(f"  预期 flag: {FLAG}")
    print(f"  注入示例: username=admin' OR '1'='1'-- -&password=x")
    print("按 Ctrl+C 退出")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        t.stop()


if __name__ == "__main__":
    _standalone()
