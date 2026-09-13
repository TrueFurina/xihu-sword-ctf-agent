"""_llm_breaking_ice 诚实分类单元测试（无需 LLM key 即可跑）。

验证：
  1. _credential_available 在无 key 时返回 False（当前 CI/沙盒环境）。
  2. _credential_available 在注入 key 后返回 True。
  3. _solve_one 在无凭证时立即返回 INFRA_NO_CREDENTIAL，且不触碰 LLM 客户端
     （证明"没 key"不会被误标成推理失败/UNSOLVED）。
  4. _solve_one 在凭证就绪但 API 挂死时返回 TIMEOUT 且带 timeout_cause 标注。
"""
from __future__ import annotations

import asyncio
import importlib
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ctf_agent
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
_SCRIPT_DIR = os.path.join(_ROOT, "scripts")
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import _llm_breaking_ice as mod  # noqa: E402


def test_credential_unavailable_without_env():
    # 清掉相关 env，确保确定性
    saved = {}
    for k in ("CTF_AGENT_USE_REAL_LLM", "QIANFAN_AK", "QIANFAN_SK", "BAIDU_API_KEY",
              "CTF_AGENT_BAIDU_KEY", "DEEPSEEK_API_KEY", "CTF_AGENT_DEEPSEEK_KEY"):
        if k in os.environ:
            saved[k] = os.environ.pop(k)
    try:
        assert mod._credential_available("baidu") is False
        assert mod._credential_available("deepseek") is False
    finally:
        os.environ.update(saved)


def test_credential_available_with_env(monkeypatch):
    monkeypatch.setenv("CTF_AGENT_USE_REAL_LLM", "1")
    monkeypatch.setenv("QIANFAN_AK", "dummy-ak")
    monkeypatch.setenv("QIANFAN_SK", "dummy-sk")
    assert mod._credential_available("baidu") is True


def test_solve_one_infra_no_credential(tmp_path, monkeypatch):
    # 确保无凭证
    for k in ("CTF_AGENT_USE_REAL_LLM", "QIANFAN_AK", "QIANFAN_SK", "BAIDU_API_KEY",
              "CTF_AGENT_BAIDU_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    rec = asyncio.run(mod._solve_one("real_crypto_ezrsa", "baidu", 1, 30, False))
    assert rec["status"] == "INFRA_NO_CREDENTIAL"
    assert "note" in rec
    # 不得误标成推理失败
    assert rec["status"] != "UNSOLVED"


def test_timeout_classification_has_cause(monkeypatch):
    """构造一个凭证就绪但 _run 永久挂死的场景，验证 TIMEOUT 带 timeout_cause。"""
    monkeypatch.setenv("CTF_AGENT_USE_REAL_LLM", "1")
    monkeypatch.setenv("QIANFAN_AK", "x")
    monkeypatch.setenv("QIANFAN_SK", "y")

    async def _fake_run():
        await asyncio.sleep(10)  # 永远不返回，靠 wait_for 超时

    import core.presolve as _ps  # noqa: F401  (确保 import 路径可用)

    # 直接替换 solver 的 _run 行为：用 monkeypatch 让 build_solver 抛不出，但 run 挂死
    orig_build = mod.run_mod.build_solver

    def _build(*a, **k):
        # 返回一个 coroutine 函数，调用后内部 await 永不返回
        async def _fake_solver(q, i, none):
            await _fake_run()
        return _fake_solver

    monkeypatch.setattr(mod.run_mod, "build_solver", _build)
    try:
        rec = asyncio.run(mod._solve_one("real_crypto_ezrsa", "baidu", 1, 1, False))
    finally:
        monkeypatch.setattr(mod.run_mod, "build_solver", orig_build)
    assert rec["status"] == "TIMEOUT"
    assert rec["timeout_cause"] == "api_hang_or_no_first_response_suspected"
