"""Cybench 适配器单元测试（T2 阶段 A 脚手架）。

不依赖 Docker / 密钥 / 网络：验证加载、sha256 评分闭环、dry-run 数据通路。
"""
from __future__ import annotations

import json
from pathlib import Path

from eval.cases import Question

from benchmarks.cybench.adapter import (
    cybench_question_from_dict,
    load_cybench_questions,
)
from benchmarks.cybench.runner import dry_run, fixture_solver

_PACKAGE_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "cybench"


def _sample_alpha() -> dict:
    raw = (_PACKAGE_DIR / "questions" / "cybench_sample_alpha.json").read_text(encoding="utf-8")
    return json.loads(raw)


def test_cybench_question_from_dict_preserves_sha256():
    q = cybench_question_from_dict(_sample_alpha())
    assert isinstance(q, Question)
    assert q.id == "cybench_dryrun_alpha"
    # source_pool 透传到 extra
    assert q.extra.get("source_pool") == "dryrun_fixture"
    # sha256 预期值可读
    assert q.expected_sha256 == q.flag_sha256
    # 合成明文命中 sha256 校验
    assert q.flag_matches(q.extra["dryrun_fixture_flag"]) is True
    # 错误候选判否
    assert q.flag_matches("flag{wrong}") is False


def test_load_cybench_questions_sample_dir():
    qs = load_cybench_questions([str(_PACKAGE_DIR / "questions")])
    assert len(qs) >= 2
    assert all(isinstance(q, Question) for q in qs)


def test_dry_run_sample_solves_via_fixture():
    report = dry_run(
        [str(_PACKAGE_DIR / "questions")],
        use_fixture=True,
        results_dir="data/results/_test_cybench_dryrun",
    )
    summary = report["summary"]
    assert summary["total"] >= 2
    # 合成样本 fixture 全解
    assert summary["solved"] == summary["total"]
    assert summary["solve_rate"] == 1.0


def test_dry_run_no_fixture_scores_zero():
    report = dry_run(
        [str(_PACKAGE_DIR / "questions")],
        use_fixture=False,
        results_dir="data/results/_test_cybench_dryrun",
    )
    summary = report["summary"]
    # 无本地 solver → 合成样本悉数计 0（数据通路仍闭环：加载→评分→报告）
    assert summary["solved"] == 0


def test_fixture_solver_returns_plaintext_only_for_fixture():
    solver = fixture_solver()
    q = cybench_question_from_dict(_sample_alpha())
    out = solver(q, 0)
    assert out["flag"] == q.extra["dryrun_fixture_flag"]
    # 无 fixture 的题返回 None（真实 Cybench 任务本地无容器）
    q2 = cybench_question_from_dict({**_sample_alpha(), "extra": {}})
    assert solver(q2, 0)["flag"] is None
