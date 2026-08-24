"""M5 验证：web_target_interact 对本地 mock 靶机的 HTTP/HTTPS/代理三场景。

不依赖真实平台（40403 关闭），纯离线验证"靶机交互层"可用性——
决赛 web 靶机交互是 23 道 web 题的得分上限决定者。

运行：.venv/Scripts/python.exe -m pytest tests/test_web_target_mock.py -q
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


def _load(module_name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name, _ROOT / rel_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


web_skill = _load("web_target_interact_mocked", "skills/web_target_interact.py")
mock_mod = _load("mock_web_target_mod", "scripts/_mock_web_target.py")


@pytest.fixture(scope="module")
def target():
    t = mock_mod.MockTarget()
    addrs = t.start()
    yield addrs
    t.stop()


def test_http_probe_and_flag_hint(target):
    out = web_skill.probe({"url": target["http"]})
    assert out["ok"], out
    assert "http_ok" in out["verdicts"], out
    fetch_out = web_skill.fetch({"url": target["http"], "max_body": 2000})
    assert fetch_out["ok"], fetch_out
    hints = fetch_out.get("flag_hints", [])
    assert any("mock_web_target_flag_2026" in h["match"] for h in hints), hints


def test_https_self_signed_reachable(target):
    # 自签证书 + verify=False 应 http_ok
    out = web_skill.fetch({"url": target["https"], "max_body": 500})
    assert out["ok"], out
    assert out["status"] == 200, out
    hints = out.get("flag_hints", [])
    assert any("mock_web_target_flag_2026" in h["match"] for h in hints), hints


def test_proxy_param_plumbing(target):
    # 经正向代理访问 HTTP 靶机，验证 proxy 参数贯通
    out = web_skill.fetch({"url": target["http"], "proxy": target["proxy"], "max_body": 500})
    assert out["ok"], out
    assert out["status"] == 200, out
    hints = out.get("flag_hints", [])
    assert any("mock_web_target_flag_2026" in h["match"] for h in hints), hints


def test_conn_refused_classified():
    # 连一个必然不通的端口，验证诊断分类（不依赖靶机）
    out = web_skill.probe({"host": "127.0.0.1", "port": "1", "timeout": 2})
    assert not out["ok"]
    dead = {"conn_refused", "conn_timeout", "connect_error", "dns_fail"}
    assert dead & set(out["verdicts"]), out
