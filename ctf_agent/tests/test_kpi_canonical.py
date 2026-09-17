#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KPI 单一权威口径源测试（P0-②，2026-09-17）。

守的是「口径不漂移」这条治理红线——测试本身就是把口径铁律编码为可执行断言：
若哪天有人改回欺骗性比率（如 14/10=140%）、或让 offline_verified 与机器真值脱钩，
这里必须 FAIL，而不是让错误数字静默流进 README/台账。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts._kpi_canonical import (  # noqa: E402
    canonical_kpi, count_offline_verified, count_real_corpus,
    count_heldout_candidates, _DEPRECATED_SUBSET,
)


def test_offline_verified_matches_machine_truth():
    """canonical 的 offline_verified 必须等于 _merge_gate 机器真值（不得手写漂移）。"""
    k = canonical_kpi()
    assert k["offline_verified"] == count_offline_verified() > 0, \
        "offline_verified 与 _merge_gate.count_offline_verified() 脱钩（口径漂移）"
    print("✓ test_offline_verified_matches_machine_truth")


def test_real_corpus_is_recursive_json_count():
    """real_corpus 必须等于 data/questions_real 递归 json 数（分母不许手填）。"""
    k = canonical_kpi()
    assert k["real_corpus"] == count_real_corpus() > 0
    assert k["real_corpus"] >= k["offline_verified"], \
        "分母小于解出数 = 计数通道错乱"
    print("✓ test_real_corpus_is_recursive_json_count")


def test_no_deceptive_heldout_ratio():
    """红线：held-out 覆盖率恒 None（14 与 unseen 池不相交，14/N 是欺骗性比率）。"""
    k = canonical_kpi()
    assert k["coverage_of_heldout"] is None, \
        "held-out 覆盖率不得输出数值——14 属已训练题，与 unseen 池不相交，任何比率都是误导"
    assert k["heldout_candidates"] >= 0
    print("✓ test_no_deceptive_heldout_ratio")


def test_kpi_and_heldout_sets_disjoint():
    """offline_verified 全部不得出现在 held-out 候选池（否则已知题被当未见题测）。"""
    try:
        from scripts.benchmark_heldout import select_candidates
        import scripts._antifraud as af
    except Exception as exc:  # pragma: no cover
        print(f"  (skip: 无法 import heldout/antifraud: {exc})")
        return
    cands, _ = select_candidates()
    cand_ids = {c["id"] for c in cands}
    auth = set(af.AUTHORIZED_KPI_SOLVES)
    overlap = cand_ids & auth
    assert not overlap, f"held-out 候选池混入了已训练 KPI 题：{overlap}"
    print("✓ test_kpi_and_heldout_sets_disjoint")


def test_deprecated_subset_anchor():
    """过时 15 题子集口径必须留警示锚点，防止死灰复燃。"""
    assert _DEPRECATED_SUBSET == 15
    print("✓ test_deprecated_subset_anchor")


if __name__ == "__main__":
    test_offline_verified_matches_machine_truth()
    test_real_corpus_is_recursive_json_count()
    test_no_deceptive_heldout_ratio()
    test_kpi_and_heldout_sets_disjoint()
    test_deprecated_subset_anchor()
    print("\nALL KPI CANONICAL TESTS PASSED")
