"""OCR 多 psm 候选择优（skills/svg_path_text._select_ocr_candidate）行为 + 变异测试。

背景（真实缺陷，2026-10-07 修）：
    `ocr_image` 早期实现「按 psm 顺序（7→6）、首个含花括号者即返回」。当 psm7
    给出含非可打印字符（如 '§'）的伪命中时会被抢先返回，丢掉 psm6 给出的正确
    结果。实测 CSAW-Quals 2017 forensics「missed_registration」的 BMP：
        psm7 → '| FLAG{anm_LaunDR3Y_FL4E_L34k§_}'   （含 '§'，非 ASCII）
        psm6 → 'FLAG{3Am_LaunDR3Y_FL4G_L34kz!}'     （正确）
    旧实现选前者 → sha256 与题面真值不符；psm7 的 '§' 还会污染下游。

本文件：纯函数单测（零外部依赖，不跑 tesseract）+ ocr_image 接线测试（monkeypatch）。
真题端到端由 tests/test_pcap_http_carve.py 与 tests/test_svg_path_text.py 覆盖。

变异验证：把 `_select_ocr_candidate` 改成 `return outs[0]`（旧行为）→
          test_select_prefers_clean_flag_over_nonascii 必红。
"""
from __future__ import annotations

import types
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import svg_path_text as S  # noqa: E402

# 实测候选（真题 pcap 的 BMP OCR 输出）
_PSM7_BAD = "| FLAG{anm_LaunDR3Y_FL4E_L34k\u00a7_}"   # '§' = U+00A7
_PSM6_GOOD = "FLAG{3Am_LaunDR3Y_FL4G_L34kz!}\nz!"


# ------------------------------------------------------------------ 评分
def test_score_flags_printable_ascii():
    assert S._ocr_candidate_score("FLAG{abc}") == (1, 1, 9, 9)


def test_score_penalizes_non_ascii_body():
    # 花括号体内含 '§' → 不构成良构 flag；且整体非 ASCII
    assert S._ocr_candidate_score(_PSM7_BAD) == (0, 0, 0, len(_PSM7_BAD))


def test_score_no_flag_is_lowest_flag_bucket():
    has_flag, ascii_only, flag_len, total = S._ocr_candidate_score("hello world")
    assert has_flag == 0 and flag_len == 0 and total == 11


def test_score_prefers_longer_flag_on_tie():
    assert S._ocr_candidate_score("FLAG{a}") < S._ocr_candidate_score("FLAG{abcdef}")


# ------------------------------------------------------------------ 择优
def test_select_prefers_clean_flag_over_nonascii():
    """核心回归：含非 ASCII 伪命中在前，也必须选后面的干净候选。"""
    assert S._select_ocr_candidate([_PSM7_BAD, _PSM6_GOOD]) == _PSM6_GOOD
    # 顺序颠倒亦然
    assert S._select_ocr_candidate([_PSM6_GOOD, _PSM7_BAD]) == _PSM6_GOOD


def test_select_tie_keeps_first():
    """并列分数 → 保留先出现者（保持 psm7 优先的历史语义）。"""
    a = "FLAG{aaaa}"
    b = "FLAG{bbbb}"
    assert S._select_ocr_candidate([a, b]) == a


def test_select_ignores_empty_candidates():
    assert S._select_ocr_candidate(["", _PSM6_GOOD, ""]) == _PSM6_GOOD


def test_select_empty_returns_none():
    assert S._select_ocr_candidate([]) is None
    assert S._select_ocr_candidate(["", ""]) is None


def test_select_falls_back_to_longest_when_no_flag():
    assert S._select_ocr_candidate(["ab", "abcdef", "abc"]) == "abcdef"


# ------------------------------------------------------------------ ocr_image 接线
class _FakeProc:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def test_ocr_image_votes_across_psm(monkeypatch):
    """ocr_image 必须收集 psm7 与 psm6 两个候选，再择优（而非首个含花括号即返回）。"""
    pytest.importorskip("PIL")
    from PIL import Image

    monkeypatch.setattr(S, "_find_tesseract", lambda: "tesseract")
    monkeypatch.setattr(S, "_tessdata_for", lambda _b: None)

    seen = []

    def fake_run(cmd, **kw):  # noqa: ANN001
        psm = cmd[cmd.index("--psm") + 1]
        seen.append(psm)
        return _FakeProc(_PSM7_BAD if psm == "7" else _PSM6_GOOD)

    monkeypatch.setattr(S, "subprocess", types.SimpleNamespace(run=fake_run))

    img = Image.new("L", (16, 8), 0)
    out = S.ocr_image(img)
    assert out == _PSM6_GOOD
    assert seen == ["7", "6"], "两个 psm 都应被尝试（不可提前 return）"


def test_ocr_image_no_tesseract_returns_none(monkeypatch):
    monkeypatch.setattr(S, "_find_tesseract", lambda: None)
    assert S.ocr_image(object()) is None


# ------------------------------------------------------------------ 变异验证（手动）
# 手动变异：把 S._select_ocr_candidate 的 return 改为 outs[0]（= 旧「首个即返回」）
#   → test_select_prefers_clean_flag_over_nonascii 必红；
#   → test_ocr_image_votes_across_psm 也会红（psm7 的 '§' 被返回）。
# 还原后全绿。此文件不内置变异开关，避免污染生产语义。
