# -*- coding: utf-8 -*-
"""ai_vision 多模态视觉接口单元测试（2026-08-28 视觉能力骨架）。

验证：多模态 messages 正确构造（text + image_url base64）、空图/熔断/缺 key 等
失败开放路径返回 None。不调真实 API（mock _post_chat）。
"""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm import client as llm_client

IMG = "data/questions_real/_attachments/misc/real_misc_xuanhun_signin/_extracted.png"


def _fixed_settings(model=None, provider=None):
    return {"api_key": "test", "base_url": "https://qianfan.baidubce.com/v2/chat/completions",
            "model": "ernie-4.5-turbo-vl", "provider": "baidu", "timeout": 30}


def test_ai_vision_constructs_multimodal_messages(monkeypatch):
    cap = {}

    def fake_post(messages, temperature, max_tokens, settings):
        cap["m"] = messages
        cap["s"] = settings
        return "flag{abc}", {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}

    monkeypatch.setattr(llm_client, "_resolve_settings", _fixed_settings)
    monkeypatch.setattr(llm_client, "provider_circuit_open", lambda p: False)
    monkeypatch.setattr(llm_client, "_post_chat", fake_post)
    out = llm_client.ai_vision("read?", [IMG])
    assert out == "flag{abc}"
    parts = cap["m"][0]["content"]
    assert isinstance(parts, list)
    assert any(p.get("type") == "image_url" for p in parts)
    img = [p for p in parts if p.get("type") == "image_url"][0]
    assert img["image_url"]["url"].startswith("data:image/png;base64,")


def test_ai_vision_empty_images_returns_none(monkeypatch):
    monkeypatch.setattr(llm_client, "_resolve_settings", _fixed_settings)
    monkeypatch.setattr(llm_client, "provider_circuit_open", lambda p: False)
    assert llm_client.ai_vision("read?", []) is None


def test_ai_vision_circuit_open_skips(monkeypatch):
    called = {"v": False}

    def fake_post(*a, **k):
        called["v"] = True
        return "x", {}

    monkeypatch.setattr(llm_client, "_resolve_settings", _fixed_settings)
    monkeypatch.setattr(llm_client, "provider_circuit_open", lambda p: True)
    monkeypatch.setattr(llm_client, "_post_chat", fake_post)
    assert llm_client.ai_vision("read?", [IMG]) is None
    assert called["v"] is False


def test_ai_vision_missing_api_key_returns_none(monkeypatch):
    s = _fixed_settings()
    s["api_key"] = ""
    monkeypatch.setattr(llm_client, "_resolve_settings", lambda *a, **k: s)
    monkeypatch.setattr(llm_client, "provider_circuit_open", lambda p: False)
    assert llm_client.ai_vision("read?", [IMG]) is None
