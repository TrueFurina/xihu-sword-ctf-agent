# -*- coding: utf-8 -*-
"""文档↔实现一致性校验器（scripts/_doc_consistency.py）单测。

覆盖：
- 状态断言漂移检测 + 三个避免误报的边界（引号提及 / 否定表述 / 批判文档豁免）
- KPI 数字漂移（2026-09-12 新增）：声明位数字 ≠ 机器计数即报红，含 README / 台账 /
  基线 / KPI_WATERMARK 四个位，以及「锚点缺失不误报」「取不到真值不误报」
  「历史演进叙述（12→13）不误报」三条边界
- 真实仓库回归守卫 test_live_repo_kpi_declarations_consistent：
  只改一处文档即红（已做变异验证：台账汇总行 13→12 → 该测试 FAIL）
"""
import pytest
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


# ── KPI 数字漂移（2026-09-12 新增）───────────────────────────────────────
# 触发本闸门的真实事故：specialcurve2 晋级 12→13 后，README 与台账第二节都改了 13，
# 台账第五节汇总行仍写 12 —— 而当时 26 个一致性/反注水测试全绿（旧校验只查措辞）。

_LEDGER_PAT = dict(dc._KPI_DECL_PATTERNS)["REAL_SOLVES_LEDGER.md"]
_README_PAT = dict(dc._KPI_DECL_PATTERNS)[os.path.join(os.path.pardir, "README.md")]


def test_kpi_ledger_declaration_drift_detected(monkeypatch, tmp_path):
    """台账第五节汇总行数字 ≠ 机器计数 → 必须报漂移。"""
    (tmp_path / "L.md").write_text(
        "| **严格真题 offline_verified（唯一 KPI，merge_gate 机器真值）** | **12** |\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", (("L.md", _LEDGER_PAT),))
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 13, 13))
    hits = dc.check_kpi_number_consistency()
    assert any("12" in h and "13" in h for h in hits), hits


def test_kpi_readme_declaration_drift_detected(monkeypatch, tmp_path):
    """README 指标表数字 ≠ 机器计数 → 必须报漂移。"""
    (tmp_path / "R.md").write_text(
        "| **offline_verified** (strict real-problem KPI) | **9** |\n", encoding="utf-8",
    )
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", (("R.md", _README_PAT),))
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 13, 13))
    hits = dc.check_kpi_number_consistency()
    assert any("9" in h and "13" in h for h in hits), hits


def test_kpi_baseline_and_watermark_drift_detected(monkeypatch, tmp_path):
    """基线棘轮锚 / KPI_WATERMARK 派生不变式被破坏 → 各自报出。"""
    (tmp_path / "KPI_BASELINE.json").write_text('{"offline_verified": 12}', encoding="utf-8")
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", ())
    monkeypatch.setattr(dc, "_KPI_BASELINE_REL", "KPI_BASELINE.json")
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 11, 12))
    hits = dc.check_kpi_number_consistency()
    assert any("基线" in h for h in hits), hits
    assert any("KPI_WATERMARK" in h for h in hits), hits


def test_kpi_no_anchor_no_false_positive(monkeypatch, tmp_path):
    """文档改版/删表导致锚点消失 → 不误报（宁漏勿误）。"""
    (tmp_path / "L.md").write_text("# 文档\n本文件没有 KPI 汇总表\n", encoding="utf-8")
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", (("L.md", _LEDGER_PAT),))
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 13, 13))
    assert dc.check_kpi_number_consistency() == []


def test_kpi_truth_unavailable_no_false_positive(monkeypatch):
    """取不到机器真值 → 不误报（绝不因取数失败阻断门禁）。"""
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (None, None, None))
    assert dc.check_kpi_number_consistency() == []


def test_kpi_historical_mentions_not_flagged(monkeypatch, tmp_path):
    """历史叙述里的「12→13」「回退 12→9」是合法演进记录，不得误报。"""
    hist = (
        "- **晋级**：水位 12→13（地板 9 + 晋升 4，全证据态）。\n"
        "- 2026-08-28 诚实回退 12→9；2026-09-03 三道带证据重新晋级。\n"
        "- 此 12 / 13 为全证据态，与回退前口径不同。\n"
    )
    # ① 过时断言检查不命中
    assert dc.check_stale_assertions("x.md", hist) == []
    # ② 声明位正则不命中演进叙述行
    (tmp_path / "L.md").write_text(hist, encoding="utf-8")
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", (("L.md", _LEDGER_PAT),))
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 13, 13))
    assert dc.check_kpi_number_consistency() == []


# 依赖本地真值台账（.gitignore 排除）：机器 KPI 计数在 CI 上恒为 -1。
@pytest.mark.local
def test_kpi_machine_truth_self_consistent():
    """机器真值自洽：计数 = 水位 = 基线（本仓真实状态，非 mock）。"""
    count, watermark, baseline = dc.machine_kpi_truth()
    assert isinstance(count, int) and count > 0, (count, watermark, baseline)
    assert count == watermark == baseline, (count, watermark, baseline)


# 依赖本地真值台账（.gitignore 排除）：机器 KPI 计数在 CI 上恒为 -1。
@pytest.mark.local
def test_live_repo_kpi_declarations_consistent():
    """真实仓库回归：README / 台账 / 基线 三处手写数字必须与机器计数一致。

    这条是「口径单一真值」的常驻守卫——若有人只改一处文档，CI 立刻红。
    """
    assert dc.check_kpi_number_consistency() == []
