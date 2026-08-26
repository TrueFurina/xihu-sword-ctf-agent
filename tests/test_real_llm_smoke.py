# -*- coding: utf-8 -*-
"""真实 LLM 端到端 smoke 测试（P0-3，2026-08-21）。

现状：全库 test_*.py 均不触碰真实 deepseek（45/45 全 mock 自嗨），得分链路一旦
LLM 封装/白名单/key 解析回归，mock 测试全绿也拦不住。本测试补最小真实链路闭环：
走真实 client 一次往返，断言能拿到非空响应。

默认 skip，绝不进 CI 阻断 mock 测试——需同时满足才真正发请求：
1. 环境变量 CTF_AGENT_REAL_LLM_SMOKE=1（显式 opt-in）；
2. 能解析到对应 provider 的 API Key（无 key 时 skip）。

用法：
    CTF_AGENT_REAL_LLM_SMOKE=1 CTF_AGENT_LLM_PROVIDER=deepseek \
    CTF_AGENT_ENFORCE_WHITELIST=1 pytest tests/test_real_llm_smoke.py -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 显式 opt-in 开关：未设则不跑真实请求（默认 0，保证 mock 测试不受影响）
_RUN_REAL = os.getenv("CTF_AGENT_REAL_LLM_SMOKE", "0") == "1"


def _provider() -> str:
    """当前 provider（优先环境变量，回落 config 默认 deepseek）。"""
    return os.getenv("CTF_AGENT_LLM_PROVIDER", "deepseek").strip().lower()


def _has_api_key() -> bool:
    """能否解析到当前 provider 的 API Key（无 key 直接 skip，不空跑）。"""
    try:
        from config import resolve_api_key
        return bool(resolve_api_key(_provider()))
    except Exception:  # noqa: BLE001 - 解析失败视为无 key
        return False


pytestmark = pytest.mark.skipif(
    not _RUN_REAL,
    reason="真实 LLM smoke 未开启（设 CTF_AGENT_REAL_LLM_SMOKE=1 才跑，避免 CI 空耗）",
)


@pytest.mark.skipif(not _has_api_key(), reason=f"未配置 {_provider()} 的 API Key")
def test_real_llm_roundtrip():
    """最简单请求走真实 client 一次往返，断言非空响应。"""
    from llm.client import ai_chat

    reply = ai_chat(
        [{"role": "user", "content": "只回复两个字：OK"}],
        provider=_provider(),
        max_tokens=16,
        temperature=0.0,
    )
    assert reply is not None, "真实 LLM 调用应返回非空响应（fail-open 不应返回 None）"
    assert len(reply.strip()) > 0, "真实 LLM 响应不应为空串"
    print(f"✓ 真实 LLM 往返成功（provider={_provider()}），响应: {reply.strip()[:40]}")


if __name__ == "__main__":
    test_real_llm_roundtrip()
    print("=== 真实 LLM smoke 通过 ===")
