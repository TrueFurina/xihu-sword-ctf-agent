# -*- coding: utf-8 -*-
"""llm/client 契约回归（P1-1 记账重构，2026-08-21 赛后）。

覆盖：
1. ai_chat 返回 str（非 _post_chat 重构后误返回的 tuple）
2. ai_chat_with_usage / ai_chat_json_with_usage 正确返回 (内容, usage)
3. 异步包装 ai_chat_json_async_with_usage 不阻塞事件循环（to_thread）
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_ai_chat_returns_str_not_tuple(monkeypatch):
    """_post_chat 返回 (content, usage) 后，ai_chat 必须只返回 content 字符串。"""
    from llm import client as llm_client

    _USAGE = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}

    def fake_post_chat(messages, temperature, max_tokens, settings):
        return "flag{ok}", dict(_USAGE)

    monkeypatch.setattr(llm_client, "_post_chat", fake_post_chat)
    # 伪装有 key（绕过 fail-open 提前返回）
    monkeypatch.setattr(llm_client, "_resolve_settings",
                        lambda model=None, provider=None: {"api_key": "x", "provider": "baidu",
                                                           "base_url": "https://qianfan.baidubce.com/v2/chat/completions"})
    out = llm_client.ai_chat([{"role": "user", "content": "hi"}])
    assert isinstance(out, str)
    assert out == "flag{ok}"


def test_ai_chat_with_usage_returns_usage(monkeypatch):
    """ai_chat_with_usage 返回 (content, usage)，usage 为真实 token 数。"""
    from llm import client as llm_client

    _USAGE = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}

    def fake_post_chat(messages, temperature, max_tokens, settings):
        return "answer", dict(_USAGE)

    monkeypatch.setattr(llm_client, "_post_chat", fake_post_chat)
    monkeypatch.setattr(llm_client, "_resolve_settings",
                        lambda model=None, provider=None: {"api_key": "x", "provider": "baidu",
                                                           "base_url": "https://qianfan.baidubce.com/v2/chat/completions"})
    content, usage = llm_client.ai_chat_with_usage([{"role": "user", "content": "hi"}])
    assert content == "answer"
    assert usage["total_tokens"] == 15


def test_ai_chat_json_async_with_usage_works(monkeypatch):
    """异步包装（to_thread）返回 (json, usage)，事件循环不被同步调用阻塞。"""
    from llm import client as llm_client

    _USAGE = {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}

    def fake_ai_chat_json_with_usage(messages, system=None, temperature=0.1,
                                     max_tokens=2000, model=None, provider=None):
        return {"action": "reason"}, dict(_USAGE)

    monkeypatch.setattr(llm_client, "ai_chat_json_with_usage", fake_ai_chat_json_with_usage)

    async def main():
        obj, usage = await llm_client.ai_chat_json_async_with_usage(
            [{"role": "user", "content": "hi"}])
        return obj, usage

    obj, usage = asyncio.run(main())
    assert obj == {"action": "reason"}
    assert usage["total_tokens"] == 3
