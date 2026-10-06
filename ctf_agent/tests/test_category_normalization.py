"""外部题源 category 归一化回归测试（2026-10-07）。

背景：外部题池（NYU/CSAW、cybench 等）产出别名类别拼写——`rev`（逆向）、
`forensics`（取证）——而下游 presolve 路由、兜底链、heavy 模型升级、步数预算
全部按 `== "reverse"` / `in ("crypto","pwn","reverse")` 硬判。未归一化时这些题
的能力「存在但不可达」（实测 41 道外部题受影响）。

修复：`Question.from_dict` 走 `normalize_category`，把别名收敛到规范集
（rev→reverse、forensics→misc，后者与本地库把取证题标为 misc 的约定一致）。

本测试锁定：纯函数映射方向 + from_dict 端到端 + 未知类别不改写 + 消费者判定可达。
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.cases import (  # noqa: E402
    CANONICAL_CATEGORIES,
    Question,
    load_questions,
    normalize_category,
)


# --------------------------------------------------------------------------
# normalize_category 纯函数
# --------------------------------------------------------------------------
def test_rev_maps_to_reverse():
    assert normalize_category("rev") == "reverse"
    assert normalize_category("reversing") == "reverse"
    assert normalize_category("reverse-engineering") == "reverse"
    assert normalize_category("reverse_engineering") == "reverse"


def test_forensics_maps_to_misc():
    assert normalize_category("forensics") == "misc"
    assert normalize_category("forensic") == "misc"


def test_case_and_whitespace_insensitive():
    assert normalize_category("  REV  ") == "reverse"
    assert normalize_category("Forensics") == "misc"
    assert normalize_category("CRYPTO") == "crypto"


def test_canonical_passthrough():
    for cat in CANONICAL_CATEGORIES:
        assert normalize_category(cat) == cat, f"{cat} 不应被改写"


def test_empty_falls_back_to_misc():
    assert normalize_category("") == "misc"
    assert normalize_category(None) == "misc"


def test_unknown_category_not_rewritten():
    # 未知类别原样返回（不猜测、保留可观测性——便于发现新题源）
    assert normalize_category("blockchain") == "blockchain"
    assert normalize_category("osint") == "osint"


# --------------------------------------------------------------------------
# Question.from_dict 端到端
# --------------------------------------------------------------------------
def test_from_dict_normalizes_rev():
    q = Question.from_dict({"id": "x", "title": "t", "category": "rev"})
    assert q.category == "reverse"
    # 归一化后满足下游 heavy/步数/presolve 的规范判定
    assert q.category in ("crypto", "pwn", "reverse")


def test_from_dict_normalizes_forensics():
    q = Question.from_dict({"id": "x", "title": "t", "category": "forensics"})
    assert q.category == "misc"


def test_from_dict_default_missing_category():
    q = Question.from_dict({"id": "x", "title": "t"})
    assert q.category == "misc"


# --------------------------------------------------------------------------
# load_questions 全链路
# --------------------------------------------------------------------------
def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)


def test_load_questions_normalizes_external_aliases(tmp_path):
    bank = tmp_path / "bank"
    _write(str(bank / "rev" / "r1.json"),
           {"id": "r1", "title": "t", "category": "rev"})
    _write(str(bank / "forensics" / "f1.json"),
           {"id": "f1", "title": "t", "category": "forensics"})
    _write(str(bank / "crypto" / "c1.json"),
           {"id": "c1", "title": "t", "category": "crypto"})
    by_id = {q.id: q.category for q in load_questions(str(bank))}
    assert by_id["r1"] == "reverse"
    assert by_id["f1"] == "misc"
    assert by_id["c1"] == "crypto"
