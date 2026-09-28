"""flag 外部校验闸门测试（core/flag_verify.py）。

锁死铁律：**正则命中 = 候选；sha256 比对 = 解出**。
起因：2026-09-28 真机真题批次1，LLM `echo "flag{...}"` 打印占位符被误判为
SUCCESS（假成功 2 个，真实成绩 0/3）。本测试确保闸门 fail-closed。
"""
from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from core.flag_verify import (  # noqa: E402
    FlagGate, extract_candidates, matches_sha256, sha256_of,
)

REAL = "flag{REAL_FLAG_2026}"
REAL_SHA = hashlib.sha256(REAL.encode()).hexdigest()


def test_sha256_of_known_value():
    assert sha256_of("abc") == hashlib.sha256(b"abc").hexdigest()


def test_matches_sha256_case_insensitive():
    assert matches_sha256(REAL, REAL_SHA.upper())
    assert not matches_sha256(REAL, "0" * 64)
    assert not matches_sha256("", REAL_SHA)
    assert not matches_sha256(REAL, "")


def test_gate_verifies_real_flag():
    g = FlagGate(expected_sha256=REAL_SHA)
    r = g.judge(["flag{...}", REAL])
    assert r.verified is True
    assert r.flag == REAL
    assert r.candidates == 2


def test_gate_rejects_only_placeholders():
    g = FlagGate(expected_sha256=REAL_SHA)
    r = g.judge(["flag{...}", "flag{}", "flag{xxx}"])
    assert r.verified is False
    assert r.flag is None
    assert "未通过" in r.reason


def test_gate_fail_closed_without_baseline():
    """没有答案基准时绝不记为解出（防止把命中当能力）。"""
    g = FlagGate(expected_sha256="")
    r = g.judge([REAL])
    assert r.verified is False
    assert r.flag is None
    assert "不可核验" in r.reason


def test_gate_no_candidates():
    g = FlagGate(expected_sha256=REAL_SHA)
    r = g.judge([])
    assert r.verified is False
    assert r.candidates == 0


def test_extract_candidates_dedup_ordered():
    text = "x flag{...} y flag{A} z flag{A}"
    got = extract_candidates(text, r"flag\{.*?\}")
    assert got == ["flag{...}", "flag{A}"]


def test_judge_text_picks_real_among_placeholder():
    g = FlagGate(expected_sha256=REAL_SHA)
    r = g.judge_text(f"noise flag{{...}} then {REAL}")
    assert r.verified is True and r.flag == REAL


def test_judge_text_placeholder_only_not_verified():
    g = FlagGate(expected_sha256=REAL_SHA, flag_pattern=r"flag\{.*?\}")
    # 复现真机场景：LLM echo 占位符
    r = g.judge_text("$ echo 'flag{...}'\nflag{...}\n")
    assert r.verified is False
