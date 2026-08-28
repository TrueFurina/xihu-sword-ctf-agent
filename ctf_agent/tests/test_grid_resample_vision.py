# -*- coding: utf-8 -*-
"""misc_grid_resample 视觉兜底单元测试（2026-08-28 视觉能力复用 vnctf_flag）。

验证：tesseract 读不出像素字体时，_vision_ocr 调用统一 ai_vision
（ernie-4.5-turbo-vl via baidu，复用 xuanhun_signin 同链路）读取揭示图，
并以题面 flag_sha256 严格校验（匹配通过 / 不匹配丢弃 / 视觉返回空丢弃 / 文件缺失丢弃）。
不调真实视觉 API（mock ai_vision）。
"""
import hashlib
import os
import re
import sys

import pytest
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import llm.client as llm_client
import skills.misc_grid_resample as GR


def _reveal_tmp(tmp_path):
    p = tmp_path / "_grid_reveal_max.png"
    Image.new("L", (40, 20), color=255).save(p)
    return str(p)


def _pat():
    return GR._flag_regex("flag\\{[^}]+\\}")


def test_vision_ocr_sha256_pass(monkeypatch, tmp_path):
    rp = _reveal_tmp(tmp_path)
    truth = hashlib.sha256(b"flag{abc}").hexdigest()
    monkeypatch.setattr(llm_client, "ai_vision",
                        lambda prompt, imgs, **kw: "flag{abc}")
    out = GR._vision_ocr(rp, truth, _pat())
    assert out == "flag{abc}"


def test_vision_ocr_sha256_mismatch_returns_none(monkeypatch, tmp_path):
    rp = _reveal_tmp(tmp_path)
    truth = hashlib.sha256(b"flag{abc}").hexdigest()
    monkeypatch.setattr(llm_client, "ai_vision",
                        lambda prompt, imgs, **kw: "flag{wrong}")
    out = GR._vision_ocr(rp, truth, _pat())
    assert out is None


def test_vision_ocr_empty_returns_none(monkeypatch, tmp_path):
    rp = _reveal_tmp(tmp_path)
    truth = hashlib.sha256(b"flag{abc}").hexdigest()
    monkeypatch.setattr(llm_client, "ai_vision",
                        lambda prompt, imgs, **kw: None)
    out = GR._vision_ocr(rp, truth, _pat())
    assert out is None


def test_vision_ocr_missing_file_returns_none(monkeypatch):
    monkeypatch.setattr(llm_client, "ai_vision",
                        lambda prompt, imgs, **kw: "flag{abc}")
    out = GR._vision_ocr("nonexistent_path.png", "x" * 64, _pat())
    assert out is None
