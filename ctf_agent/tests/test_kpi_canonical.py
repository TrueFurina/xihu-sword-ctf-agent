#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KPI 单一权威口径源测试（P0-②，2026-09-17）。

守的是「口径不漂移」这条治理红线——测试本身就是把口径铁律编码为可执行断言：
若哪天有人改回欺骗性比率（如 14/10=140%）、或让 offline_verified 与机器真值脱钩，
这里必须 FAIL，而不是让错误数字静默流进 README/台账。
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts._kpi_canonical import (  # noqa: E402
    canonical_kpi, count_offline_verified, count_real_corpus,
    count_heldout_candidates, count_heldout_runnable_pool,
    count_skills, count_regression_checks,
    check_readme_counts, _DEPRECATED_SUBSET,
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


def test_runnable_pool_is_distinct_from_capability_denominator():
    """2026-09-26：heldout_candidates(能力分母) 与 heldout_runnable_pool(可选跑池)
    必须**同时存在且可区分**。

    起因：二者此前在文档/对话中混称（都叫「held-out 池」），已造成一次混淆；
    且 select_candidates 的 docstring 曾误称「默认并入外部题」（签名实为 None），
    实测 select_candidates() = 2 题 vs 带 external = 17 题。
    把 0/17 或 1/17 当能力率，等于把「题更难」说成「能力更低」——是欺骗性比率。
    """
    k = canonical_kpi()
    assert "heldout_runnable_pool" in k, "canonical 必须暴露可选跑池字段（否则二者必然混称）"
    denom, pool = k["heldout_candidates"], k["heldout_runnable_pool"]
    assert denom > 0 and pool >= denom, \
        f"可选跑池({pool}) 不应小于能力分母({denom})"
    # 能力分母不得被悄悄改成跑池（那会静默改变 KPI 口径）
    assert denom == count_heldout_candidates(), "heldout_candidates 与机器真值脱钩"
    assert pool == count_heldout_runnable_pool(), "heldout_runnable_pool 与机器真值脱钩"
    print(f"✓ test_runnable_pool_is_distinct_from_capability_denominator "
          f"(能力分母={denom}, 可选跑池={pool})")


def test_runnable_pool_includes_external_questions():
    """可选跑池必须真的含外部采源：显式传 external_dir 才并入（默认 None 不并入）。"""
    from scripts.benchmark_heldout import select_candidates, QUESTIONS_EXTERNAL
    without_ext, _ = select_candidates()
    with_ext, _ = select_candidates(external_dir=QUESTIONS_EXTERNAL)
    pool = count_heldout_runnable_pool()
    assert len(without_ext) == count_heldout_candidates(), \
        "能力分母应等于「不并入外部题」的选池结果"
    assert pool == len(with_ext), "可选跑池应等于「并入外部题」的选池结果"
    assert len(with_ext) >= len(without_ext), "并入外部题后跑池不应变小"
    print(f"✓ test_runnable_pool_includes_external_questions "
          f"({len(without_ext)} → {len(with_ext)})")


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


# ── P0-5：手写计数 → 机器派生（2026-09-19）─────────────────────────────────
def test_skills_count_is_machine_derived():
    """skills 数必须是机器派生（skills/*.py 顶层 run 入口），不得手写漂移。

    历史 README 手写的「52」经实测为伪（真值 56），正是本检查要堵的漂移。
    """
    k = canonical_kpi()
    assert k["skills"] == count_skills() > 0, \
        "canonical skills 与 count_skills() 脱钩（口径漂移）"
    # 记录这次真实漂移：机器真值不应回退到手写的历史值 52。
    assert k["skills"] != 52, \
        "skills 机器计数回到 52（历史手写伪值）——取数逻辑疑坏或被改回"
    print(f"✓ test_skills_count_is_machine_derived (skills={k['skills']})")


def test_regression_checks_count_is_machine_derived():
    """回归集条数必须机器派生（委托 _merge_gate.REGRESSION_CHECKS）。"""
    k = canonical_kpi()
    assert k["regression_checks"] == count_regression_checks() > 0, \
        "canonical regression_checks 与 _merge_gate.REGRESSION_CHECKS 脱钩"
    print(f"✓ test_regression_checks_count_is_machine_derived "
          f"(regression_checks={k['regression_checks']})")


def test_readme_counts_green_on_live_repo():
    """活仓库两份 README 的计数声明必须与机器真值一致（空列表 = 绿）。"""
    hits = check_readme_counts()
    assert hits == [], "README 计数漂移：\n  - " + "\n  - ".join(hits)
    print("✓ test_readme_counts_green_on_live_repo")


def test_readme_count_check_bites_when_truth_moves():
    """【变异】真值一移动，README 手写计数必须立刻变红（证明锚点真的绑定真值）。"""
    moved = {"skills": 9999, "real_corpus": 92, "regression_checks": 16}
    hits = check_readme_counts(truth=moved)
    assert hits, "真值移动后仍有声明未报红——锚点未真正绑定机器真值（假闸门）"
    assert any("9999" in h for h in hits), f"未命中 skills 漂移：{hits}"
    assert any("skills" in h for h in hits), f"漂移点未指向 skills：{hits}"
    print(f"✓ test_readme_count_check_bites_when_truth_moves ({len(hits)} hits)")


def test_readme_count_check_detects_missing_declaration():
    """【变异】声明被整行删掉 → mandatory 锚点必须报「声明缺失」，堵删除绕过。"""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # README 文件存在，但 skills / regression 声明整行被删（只剩无关正文）。
        (root / "README.md").write_text(
            "# Project\nJust prose, no counts here.\n", encoding="utf-8")
        (root / "README.zh.md").write_text(
            "# 项目\n只有正文，没有任何计数声明。\n", encoding="utf-8")
        hits = check_readme_counts(readme_root=root)
        assert hits, "声明整行缺失时未报红——可被「删掉声明」绕过"
        assert any("缺失" in h for h in hits), f"未产出「声明缺失」告警：{hits}"
        # 10 条锚点全部 mandatory=True 且都缺失 → 应得 10 条缺失告警。
        assert len(hits) == 10, f"应命中 10 条声明缺失，实得 {len(hits)}：{hits}"
    print(f"✓ test_readme_count_check_detects_missing_declaration")


def test_readme_count_check_green_on_synthetic_consistent():
    """【正样本】合成 README 数字全对 → 绿（证明不会误报，宁漏勿误）。"""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "README.md").write_text(
            "├── skills/        56 deterministic skills\n"
            "→ deterministic skills (56)\n"
            "- holds 56 runnable skills\n"
            "| Deterministic pipeline coverage | **14 / 92** full-corpus (15.2%) |\n"
            "| Regression-set reproducible count | **16 / 16** |\n",
            encoding="utf-8",
        )
        (root / "README.zh.md").write_text(
            "├── skills/        56 个确定性解题 skill\n"
            "→ 确定性 skill(56)\n"
            "- 含 56 个即用 skill\n"
            "| 确定性管线（presolve 直出） | **14 / 92**（全集，15.2%） |\n"
            "| 回归集可复现计数 | **16 / 16** |\n",
            encoding="utf-8",
        )
        truth = {"skills": 56, "real_corpus": 92, "regression_checks": 16}
        hits = check_readme_counts(readme_root=root, truth=truth)
        assert hits == [], f"数字全对却报红（误报）：{hits}"
    print("✓ test_readme_count_check_green_on_synthetic_consistent")


def test_readme_count_check_bites_on_synthetic_drift():
    """【变异】合成 README 里 skills 写错 → 必须红（精确指向漂移行）。"""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "README.md").write_text(
            "├── skills/        52 deterministic skills\n"
            "→ deterministic skills (52)\n"
            "- holds 52 runnable skills\n"
            "| Deterministic pipeline coverage | **14 / 92** full-corpus (15.2%) |\n"
            "| Regression-set reproducible count | **16 / 16** |\n",
            encoding="utf-8",
        )
        (root / "README.zh.md").write_text(
            "├── skills/        52 个确定性解题 skill\n"
            "→ 确定性 skill(52)\n"
            "- 含 52 个即用 skill\n"
            "| 确定性管线（presolve 直出） | **14 / 92**（全集，15.2%） |\n"
            "| 回归集可复现计数 | **16 / 16** |\n",
            encoding="utf-8",
        )
        truth = {"skills": 56, "real_corpus": 92, "regression_checks": 16}
        hits = check_readme_counts(readme_root=root, truth=truth)
        assert hits, "skills 写错（52≠56）却未报红——real 变异漏检"
        # 6 处 skills 声明全部应命中（README.com 3 + README.zh.md 3）。
        assert len(hits) == 6, f"应命中 6 处 skills 漂移，实得 {len(hits)}：{hits}"
        assert all("52" in h and "56" in h for h in hits), f"漂移明细不含 52/56：{hits}"
    print(f"✓ test_readme_count_check_bites_on_synthetic_drift (6 hits)")


def test_readme_count_check_skips_when_corpus_absent():
    """【防误报】语料/目录不可得（真值<=0）时跳过而非误报（.gitignore / sparse clone 陷阱）。

    data/questions_real/ 虽由 `!data/questions_real/**` 反忽略而跟踪，但 sparse/LFS clone
    或误配 .gitignore 下会得 real_corpus=0；此时必须「宁漏勿误」跳过，不得把 README 判红。
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "README.md").write_text(
            "├── skills/        56 deterministic skills\n"
            "deterministic skills (56)\n"
            "- holds 56 runnable skills\n"
            "| Deterministic pipeline coverage | **14 / 92** full-corpus (15.2%) |\n"
            "| Regression-set reproducible count | **16 / 16** |\n",
            encoding="utf-8",
        )
        (root / "README.zh.md").write_text(
            "├── skills/        56 个确定性解题 skill\n"
            "确定性 skill(56)\n"
            "- 含 56 个即用 skill\n"
            "| 确定性管线（presolve 直出） | **14 / 92**（全集，15.2%） |\n"
            "| 回归集可复现计数 | **16 / 16** |\n",
            encoding="utf-8",
        )
        # 模拟 sparse/LFS clone：语料缺失 → real_corpus=0；skills/regression 仍可知。
        truth = {"skills": 56, "real_corpus": 0, "regression_checks": 16}
        hits = check_readme_counts(readme_root=root, truth=truth)
        assert hits == [], f"语料不可得时误报 RED（.gitignore/sparse clone 陷阱）：{hits}"
    print("✓ test_readme_count_check_skips_when_corpus_absent")


if __name__ == "__main__":
    test_offline_verified_matches_machine_truth()
    test_real_corpus_is_recursive_json_count()
    test_no_deceptive_heldout_ratio()
    test_kpi_and_heldout_sets_disjoint()
    test_deprecated_subset_anchor()
    test_skills_count_is_machine_derived()
    test_regression_checks_count_is_machine_derived()
    test_readme_counts_green_on_live_repo()
    test_readme_count_check_bites_when_truth_moves()
    test_readme_count_check_detects_missing_declaration()
    test_readme_count_check_green_on_synthetic_consistent()
    test_readme_count_check_bites_on_synthetic_drift()
    test_readme_count_check_skips_when_corpus_absent()
    print("\nALL KPI CANONICAL TESTS PASSED")
