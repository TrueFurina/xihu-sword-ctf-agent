"""代码动作兜底（recover_script）回归测试。

背景（2026-10-06 A5 实测，5 题 0/5）：弱模型 glm-4-flash 无视 JSON 动作协议，
直接吐 ```python``` 代码块解题 → 旧链路把它当「不可解析」丢弃 → 主链空转超时。

真因（本刀修）：生产路径 build_solver 注入的 llm_client 调
`ai_chat_json_async_with_usage`，该变体**无 recover_script 形参**，且
`llm_wrapper.llm_json` 在注入分支收到 None 时直接返回 None → plan 步的
`recover_script=True` 完全失效（recover 分支恒死）。

本刀：
1. `_recover_script_from_code` 纯函数（提取首个代码围栏 → script 动作）；
2. `ai_chat_json_with_usage` / `_async_with_usage` 加 `recover_script` 形参；
3. `llm_wrapper._invoke_client` 容忍旧三参签名、对新签名透传 recover_script；
4. `run.py` 注入客户端接受并转发 recover_script（生产路径打通）。

覆盖：纯函数各形态 + usage 变体开/关 + 异步透传 + 旧签名容忍 + 注入 str 恢复。
"""

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import llm.client as lc  # noqa: E402
from core.llm_wrapper import _invoke_client, llm_json  # noqa: E402
from llm.client import _recover_script_from_code  # noqa: E402


# ── 1. 纯函数：_recover_script_from_code ────────────────────────────
def test_recover_python_fence_prefixed():
    out = _recover_script_from_code("```python\nprint('hi')\n```")
    assert out["action"] == "script"
    assert out["code"] == "python: print('hi')"
    assert out["_recovered_from_code"] is True
    assert out["done"] is False


def test_recover_py_and_python3_tags():
    assert _recover_script_from_code("```py\nx=1\n```")["code"] == "python: x=1"
    assert _recover_script_from_code("```python3\nx=1\n```")["code"] == "python: x=1"


def test_recover_bash_fence_left_raw():
    out = _recover_script_from_code("```bash\nopenssl enc -d -aes-256-cbc\n```")
    assert out["action"] == "script"
    assert out["code"] == "openssl enc -d -aes-256-cbc"  # 无 python: 前缀 → 沙盒 shell


def test_recover_bare_fence_left_raw():
    # 无语言标签 → 原样（交给沙盒 _looks_like_python 自动识别）
    out = _recover_script_from_code("```\nimport base64\nprint(1)\n```")
    assert out["code"] == "import base64\nprint(1)"


def test_recover_ignores_leading_empty_fence():
    out = _recover_script_from_code("```\n```\n```python\nprint(2)\n```")
    assert out["code"] == "python: print(2)"  # 首个非空围栏优先


def test_recover_no_fence_returns_none():
    assert _recover_script_from_code("I cannot determine the next step.") is None


def test_recover_empty_python_fence_returns_none():
    assert _recover_script_from_code("```python\n\n```") is None


def test_recover_non_str_returns_none():
    assert _recover_script_from_code(None) is None
    assert _recover_script_from_code(123) is None


# ── 2. ai_chat_json_with_usage：recover_script 开/关 ────────────────
def _fake_ai_chat_with_usage(content):
    def _f(*args, **kwargs):
        return content, {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
    return _f


def test_usage_variant_recovers_when_enabled(monkeypatch):
    monkeypatch.setattr(lc, "ai_chat_with_usage",
                        _fake_ai_chat_with_usage("```python\nprint('hi')\n```"))
    obj, usage = lc.ai_chat_json_with_usage(
        [{"role": "user", "content": "x"}], recover_script=True)
    assert obj["action"] == "script"
    assert obj["code"].startswith("python: ")
    assert usage["total_tokens"] == 3  # usage 原样返回（记账不受恢复影响）


def test_usage_variant_no_recover_when_disabled(monkeypatch):
    # 默认 False → 严格 JSON 调用方（supervisor/feedback）不回归
    monkeypatch.setattr(lc, "ai_chat_with_usage",
                        _fake_ai_chat_with_usage("```python\nprint('hi')\n```"))
    obj, usage = lc.ai_chat_json_with_usage([{"role": "user", "content": "x"}])
    assert obj is None
    assert usage["total_tokens"] == 3


def test_usage_variant_clean_json_unaffected(monkeypatch):
    monkeypatch.setattr(lc, "ai_chat_with_usage",
                        _fake_ai_chat_with_usage('{"action": "run"}'))
    obj, _ = lc.ai_chat_json_with_usage(
        [{"role": "user", "content": "x"}], recover_script=True)
    assert obj == {"action": "run"}  # 正常 JSON 不受恢复逻辑影响


def test_sync_ai_chat_json_recovers(monkeypatch):
    monkeypatch.setattr(lc, "ai_chat", lambda *a, **k: "```python\nprint(1)\n```")
    obj = lc.ai_chat_json([{"role": "user", "content": "x"}], recover_script=True)
    assert obj["action"] == "script" and obj["code"] == "python: print(1)"


# ── 3. 异步 usage 变体透传 recover_script（生产路径）─────────────────
def test_async_usage_variant_forwards_recover(monkeypatch):
    monkeypatch.setattr(lc, "ai_chat_with_usage",
                        _fake_ai_chat_with_usage("```bash\nopenssl x\n```"))
    obj, usage = asyncio.run(lc.ai_chat_json_async_with_usage(
        [{"role": "user", "content": "x"}], recover_script=True))
    assert obj["action"] == "script"
    assert obj["code"] == "openssl x"  # bash 原样
    assert usage["total_tokens"] == 3


# ── 4. _invoke_client：旧三参签名容忍 + 新签名透传 ──────────────────
def test_invoke_client_tolerates_legacy_signature():
    async def legacy(system, user, attempt):
        return {"ok": True}

    out = asyncio.run(_invoke_client(legacy, "s", "u", 0, recover_script=True))
    assert out == {"ok": True}


def test_invoke_client_forwards_recover_script():
    seen = {}

    async def modern(system, user, attempt, recover_script=False):
        seen["rs"] = recover_script
        return {"ok": True}

    asyncio.run(_invoke_client(modern, "s", "u", 0, recover_script=True))
    assert seen["rs"] is True


# ── 5. llm_json 注入 client（返回代码字符串）恢复 ───────────────────
def test_llm_json_injected_str_recovers_code():
    async def client(system, user, attempt):
        return "```python\nprint(42)\n```"

    out = asyncio.run(llm_json("s", "u", 0, client, recover_script=True))
    assert out["action"] == "script" and out["code"] == "python: print(42)"


def test_llm_json_injected_str_no_recover_when_disabled():
    async def client(system, user, attempt):
        return "```python\nprint(42)\n```"

    out = asyncio.run(llm_json("s", "u", 0, client))
    assert out is None  # 默认 False → 严格 JSON 调用方不回归
