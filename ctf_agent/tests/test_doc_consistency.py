# -*- coding: utf-8 -*-
"""文档↔实现一致性校验器（scripts/_doc_consistency.py）单测。

覆盖：状态断言漂移检测 + 三个避免误报的边界（引号提及 / 否定表述 / 批判文档豁免）。
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _doc_consistency as dc  # noqa: E402


def test_stale_assertion_hits():
    """裸的过时断言命中（真的声称"单写者全局租约"）。"""
    hits = dc.check_stale_assertions("x.md", "当前执法层实现为单写者全局租约")
    assert any("单写者全局租约" in h for h in hits)


def test_quoted_mention_exempt():
    """引号包裹的「提及」不命中（治理记录引用违规词说明已去掉）。"""
    assert dc.check_stale_assertions("x.md", "原协议声称「单写者全局租约」，已修订") == []


def test_negation_exempt():
    """否定表述不命中（"不再是单写者全局租约锁"）。"""
    assert dc.check_stale_assertions("x.md", "不再是一次仅一个会话可写的单写者全局租约锁") == []


def test_review_doc_exempt():
    """批判/审查类文档豁免（锐评引用过时断言是在批评它）。"""
    hits = dc.check_stale_assertions("CTDE协同协议-锐评-20260823.md", "协议声称单写者全局租约，实测已落地")
    assert hits == []


def test_missing_file_detected(monkeypatch, tmp_path):
    """关键文件缺失时检测出来（TASK_BOARD.md 不存在）。"""
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "DOC_ROOT", str(tmp_path / "deliverables"))
    monkeypatch.setattr(dc, "_REQUIRED_FILES", ("TASK_BOARD.md",))
    hits = dc.check_missing_files()
    assert any("TASK_BOARD.md" in h for h in hits)
