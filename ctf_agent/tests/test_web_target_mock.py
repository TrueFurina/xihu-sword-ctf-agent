"""web_target_interact 离线密封验证（替代原 _mock_web_target 方案）。

密封化（2026-08-28 · P4 / 8-27 巡检"关闭 _mock_web_target.py"）：
- 不再依赖 openssl 生成自签证书（旧方案 2× "https 端口 2s 未就绪" 假绿的来源）；
- 不再有 2s 端口就绪竞态——改用 port=0 由 OS 分配、serve_forever 即就绪的纯 stdlib 服务。
覆盖：probe / fetch / flag_hints 提取 / proxy 参数贯通 / conn_refused 诊断分类。
另加 web_target_real.RealWebTarget 真执行靶机冒烟（验证替代靶机本身可用，SQL 注入链路可解）。

运行：pytest tests/test_web_target_mock.py -q
"""
from __future__ import annotations

import importlib.util
import sys
import threading
import urllib.request
from pathlib import Path

import http.server
import pytest

_ROOT = Path(__file__).resolve().parent.parent


def _load(module_name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(module_name, _ROOT / rel_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


web_skill = _load("web_target_interact_hermetic", "skills/web_target_interact.py")
real_mod = _load("web_target_real_hermetic", "scripts/web_target_real.py")

FLAG_HINT = b"DASCTF{hermetic_web_flag_2026}"


class _Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, body: bytes, ctype: str = "text/html", status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/robots.txt":
            self._send(b"User-agent: *\nDisallow: /admin\n")
            return
        html = (
            b"<!DOCTYPE html><html><body><h1>Login</h1>"
            b"<!-- hint: DASCTF{hermetic_web_flag_2026} -->"
            b'<a href="/admin">admin</a></body></html>'
        )
        self._send(html)

    def do_POST(self):
        self._send(b'{"ok":false}', "application/json")

    def log_message(self, *a):  # 静默
        pass


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    """极简正向代理：仅转发 GET（覆盖决赛 web 经 proxy 访问场景）。"""

    def do_GET(self):
        try:
            with urllib.request.urlopen(self.path, timeout=5) as r:
                data = r.read()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:  # noqa: BLE001
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, *a):  # 静默
        pass


@pytest.fixture(scope="module")
def srv():
    http_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    proxy_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ProxyHandler)
    t1 = threading.Thread(target=http_srv.serve_forever, daemon=True)
    t2 = threading.Thread(target=proxy_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()
    addrs = {
        "http": f"http://127.0.0.1:{http_srv.server_address[1]}/",
        "proxy": f"http://127.0.0.1:{proxy_srv.server_address[1]}/",
    }
    yield addrs
    http_srv.shutdown()
    proxy_srv.shutdown()


def test_http_probe_and_flag_hint(srv):
    out = web_skill.probe({"url": srv["http"]})
    assert out["ok"], out
    assert "http_ok" in out["verdicts"], out
    fetch_out = web_skill.fetch({"url": srv["http"], "max_body": 2000})
    assert fetch_out["ok"], fetch_out
    hints = fetch_out.get("flag_hints", [])
    assert any("hermetic_web_flag_2026" in h["match"] for h in hints), hints


def test_proxy_param_plumbing(srv):
    # 经正向代理访问 HTTP 靶机，验证 proxy 参数贯通
    out = web_skill.fetch({"url": srv["http"], "proxy": srv["proxy"], "max_body": 500})
    assert out["ok"], out
    assert out["status"] == 200, out
    hints = out.get("flag_hints", [])
    assert any("hermetic_web_flag_2026" in h["match"] for h in hints), hints


def test_conn_refused_classified():
    # 连一个必然不通的端口，验证诊断分类（不依赖靶机）
    out = web_skill.probe({"host": "127.0.0.1", "port": "1", "timeout": 2})
    assert not out["ok"]
    dead = {"conn_refused", "conn_timeout", "connect_error", "dns_fail"}
    assert dead & set(out["verdicts"]), out


@pytest.fixture(scope="module")
def real_target():
    # 真执行 web-001 靶机（替代 _mock_web_target 的静态死页面）：验证替代靶机本身可用
    t = real_mod.RealWebTarget(host="127.0.0.1", port=0)
    addr = t.start()
    yield addr
    t.stop()


def test_real_target_sqli_smoke(real_target):
    import httpx

    # 直接打靶机登录接口，验证 SQL 注入漏洞链路（OR '1'='1' 绕过）可解
    r = httpx.post(
        real_target + "login",
        data={"username": "admin' OR '1'='1'-- -", "password": "x"},
        timeout=5, verify=False,
    )
    assert r.status_code == 200, r.status_code
    assert "flag{sqli_waf_bypass_2026}" in r.text, r.text
