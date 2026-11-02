# -*- coding: utf-8 -*-
"""`_verify_failopen.py` 的守卫（2026-11-01 审计补）。

验证的是「无 Key 时 client 返回 None 且**不抛异常**」。

为什么需要独立守卫
------------------
原脚本只有两条 `assert r is None`。它能发现「返回了非 None」，
但对「抛异常」这一半**没有诊断能力**——异常会在赋值那一行炸掉，
输出 traceback 而不是「fail-open 失败」，退出码也无法区分两种错。

本文件锁三件事：
  1. 无 Key 时 `ai_chat` / `ai_chat_json` 都返回 None
  2. 无 Key 时**不抛异常**（这是 fail-open 的定义）
  3. 脚本自身的 `_probe` 能把「抛异常」和「返回非 None」区分开
     —— 用注入的假函数做变异，证明它不是恒真
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import importlib.util
import pathlib

import pytest

_SCRIPT = pathlib.Path(_ROOT) / "scripts" / "_verify_failopen.py"


def _load_module():
    """加载被测模块（它会清掉 Key 环境变量，所以每个用例前重载）。"""
    spec = importlib.util.spec_from_file_location("_vfailopen", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def vf(monkeypatch):
    # 确保没有任何 Key 残留（脚本自己也会清，但这里先清一次以防 import 期已读取）
    for var in ("DEEPSEEK_API_KEY", "CTF_AGENT_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    return _load_module()


# ── 1&2 真实行为：返回 None 且不抛 ─────────────────────────────────────────
def test_ai_chat_returns_none_without_key(vf):
    assert vf.ai_chat([{"role": "user", "content": "test"}]) is None


def test_ai_chat_json_returns_none_without_key(vf):
    assert vf.ai_chat_json([{"role": "user", "content": "test"}]) is None


def test_main_reports_ok_without_key(vf):
    assert vf.main() == 0


# ── 3 _probe 的判别力：抛异常 vs 返回非 None 必须分开 ─────────────────────
def test_probe_distinguishes_exception(vf):
    def boom(_msgs):
        raise RuntimeError("no key")

    raised, why, value = vf._probe("boom", boom)
    assert raised is True
    assert "RuntimeError" in why
    assert value is None


def test_probe_passes_through_normal_return(vf):
    raised, why, value = vf._probe("ok", lambda m: None)
    assert raised is False and why is None and value is None


def test_probe_detects_non_none_return(vf):
    raised, why, value = vf._probe("bad", lambda m: "leaked")
    assert raised is False
    assert value == "leaked"


# ── 变异验证：`main()` 必须真的会因为异常报 FAIL ────────────────────────────
def test_main_fails_when_client_raises(vf, monkeypatch):
    """把 ai_chat 换成会抛异常的实现 → main 必须返回 1 且打印 FAIL。

    这是最核心的一条：它证明「不抛异常」这一半**真的被检查了**。
    修复前的脚本在这里会直接崩溃而不是给出 FAIL 结论。
    """
    def boom(_msgs):
        raise RuntimeError("simulated: client raised instead of returning None")

    monkeypatch.setattr(vf, "ai_chat", boom)
    rc = vf.main()
    assert rc == 1, "客户端抛异常时 fail-open 守卫必须判 FAIL"


def test_main_fails_when_client_leaks_value(vf, monkeypatch):
    """返回非 None 也必须判 FAIL（原脚本已覆盖，这里一起锁住）。"""
    monkeypatch.setattr(vf, "ai_chat", lambda m: "some-value")
    assert vf.main() == 1
