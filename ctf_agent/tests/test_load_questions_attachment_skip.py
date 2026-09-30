"""load_questions 附件目录跳过守卫回归测试（2026-09-30 修复）。

背景：load_questions 用 rglob("*.json") 递归扫描题库目录，而适配器把
附件放在 data/questions_ext/_attachments/ 下。collusion 题的输入文件
bobs-key.json / carols-key.json / message.json 被误当题目 JSON 解析，
题库从 34 虚增到 37（misc 2→5）。修复后 rglob 跳过 _attachments 等
附件目录。本测试用 tmp_path 构造最小复现，锁定「附件 .json 不得当题目」。
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.cases import load_questions  # noqa: E402

_QDOC = {
    "id": "t_real_q",
    "provenance": "real_past_ctf",
    "category": "crypto",
    "title": "real q",
    "description": "solve it",
    "flag": "f" * 64,  # sha256 占位
    "flag_sha256": "f" * 64,
    "attachments": [],
    "difficulty": "EASY",
}


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)


def test_attachments_dir_json_is_skipped(tmp_path):
    bank = tmp_path / "bank"
    # 一道真题目
    _write(str(bank / "crypto" / "real_q.json"), _QDOC)
    # 附件目录里的 .json 输入文件（模拟 collusion 的 bobs-key.json）
    _write(str(bank / "_attachments" / "crypto" / "x" / "bobs-key.json"),
           {"foo": "bar", "not_a_question": True})
    _write(str(bank / "_attachments" / "crypto" / "x" / "message.json"),
           {"baz": 1})
    qs = load_questions(str(bank))
    ids = [q.id for q in qs]
    assert ids == ["t_real_q"], f"附件 .json 被误当题目: {ids}"


def test_answers_dir_json_is_skipped(tmp_path):
    bank = tmp_path / "bank"
    _write(str(bank / "crypto" / "real_q.json"), _QDOC)
    _write(str(bank / "answers" / "real_q.json"), {"id": "should_be_skipped"})
    qs = load_questions(str(bank))
    assert [q.id for q in qs] == ["t_real_q"]


def test_real_question_still_loads(tmp_path):
    bank = tmp_path / "bank"
    _write(str(bank / "crypto" / "real_q.json"), _QDOC)
    qs = load_questions(str(bank))
    assert len(qs) == 1 and qs[0].id == "t_real_q"
    assert qs[0].category == "crypto"
