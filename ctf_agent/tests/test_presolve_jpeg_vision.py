# -*- coding: utf-8 -*-
"""presolve JPEG-PNG 视觉兜底路由单元测试（2026-08-28 视觉能力骨架）。

验证：skills 提取 PNG 但 tesseract 未命中时，_try_jpeg_png_embedded 调用视觉 LLM
兜底读图内 flag，且以题面 flag_sha256 严格校验（匹配通过 / 不匹配丢弃 / 无 png 不调）。
不调真实视觉 API（mock ai_vision）。
"""
import asyncio
import hashlib
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm import client as llm_client
import core.presolve as P

JPG = "data/questions_real/_attachments/misc/real_misc_xuanhun_signin/xz1.jpg"
IMG = "data/questions_real/_attachments/misc/real_misc_xuanhun_signin/_extracted.png"


def _q(flag_sha256=""):
    return SimpleNamespace(id="real_misc_xuanhun_signin", category="misc",
                           attachments=[JPG], flag_sha256=flag_sha256,
                           flag_pattern="flag\\{[^}]+\\}")


def test_vision_fallback_sha256_pass(monkeypatch):
    skill_ret = {"ok": True, "png_path": IMG, "flag": None}
    monkeypatch.setattr(P, "_attachments", lambda q: [JPG])
    monkeypatch.setattr("skills.jpeg_png_embedded.run", lambda params: skill_ret)
    monkeypatch.setattr(llm_client, "ai_vision", lambda prompt, imgs, **kw: "flag{abc}")
    flag = asyncio.run(P._try_jpeg_png_embedded(_q(hashlib.sha256(b"flag{abc}").hexdigest())))
    assert flag == "flag{abc}"


def test_vision_fallback_sha256_mismatch_returns_none(monkeypatch):
    skill_ret = {"ok": True, "png_path": IMG, "flag": None}
    monkeypatch.setattr(P, "_attachments", lambda q: [JPG])
    monkeypatch.setattr("skills.jpeg_png_embedded.run", lambda params: skill_ret)
    monkeypatch.setattr(llm_client, "ai_vision", lambda prompt, imgs, **kw: "flag{wrong}")
    flag = asyncio.run(P._try_jpeg_png_embedded(_q(hashlib.sha256(b"flag{abc}").hexdigest())))
    assert flag is None


def test_vision_fallback_no_png_returns_none(monkeypatch):
    skill_ret = {"ok": True, "png_path": None, "flag": None}
    monkeypatch.setattr(P, "_attachments", lambda q: [JPG])
    monkeypatch.setattr("skills.jpeg_png_embedded.run", lambda params: skill_ret)
    ai_called = {"v": False}

    def fake_vision(prompt, imgs, **kw):
        ai_called["v"] = True
        return "flag{abc}"

    monkeypatch.setattr(llm_client, "ai_vision", fake_vision)
    flag = asyncio.run(P._try_jpeg_png_embedded(_q("")))
    assert flag is None
    assert ai_called["v"] is False
