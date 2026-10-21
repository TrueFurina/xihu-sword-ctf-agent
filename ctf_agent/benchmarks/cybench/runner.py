"""Cybench dry-run 执行器（T2 阶段 A 脚手架）。

本地 dry-run：不依赖 Docker / 密钥 / 网络，仅验证「加载→求解→评分→报告」数据通路。
- 默认（--sample）：跑内置合成样本（benchmarks/cybench/questions/），fixture solver
  从 extra.dryrun_fixture_flag 取合成明文 flag 回灌，证明 sha256 评分闭环。
- --real：加载 benchmarks/external_unseen/questions 的 ext_cybench_* 真实任务，
  经可测性分层（input-less 自动跳过），真实链路需后续容器执行器 + 密钥。

评分口径与全仓一致：Question.flag_matches（sha256 优先、明文兜底）。
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Sequence

logger = logging.getLogger(__name__)

_PACKAGE_DIR = Path(__file__).resolve().parent


def fixture_solver() -> callable:
    """构造本地 fixture solver：对携带 dryrun_fixture_flag 的样本题返回合成明文。

    仅用于 dry-run 验证数据通路；真实求解由未来容器执行器 + LLM 完成。
    """

    def solver(q, attempt: int = 0):
        fixture = (q.extra or {}).get("dryrun_fixture_flag")
        if fixture:
            return {"flag": str(fixture), "solved_by": "dryrun_fixture", "confidence": 1.0}
        return {
            "flag": None,
            "solved_by": "none",
            "confidence": 0.0,
            "error": {"category": "no_local_solver", "detail": "dry-run 无容器执行器"},
        }

    return solver


def _default_sample_sources() -> list[str]:
    return [str(_PACKAGE_DIR / "questions")]


def _default_real_sources() -> list[str]:
    # 真实 Cybench 任务已在 external_unseen 落地（vendored 数据，非代码）
    return [
        str(
            _PACKAGE_DIR.parent.parent
            / "external_unseen"
            / "questions"
            / "ext_cybench_*.json"
        )
    ]


def dry_run(
    sources: Sequence[str],
    use_fixture: bool = True,
    max_retries: int = 1,
    results_dir: str = "data/results/cybench_dryrun",
    apply_corpus_gate: bool = True,
) -> dict:
    """加载 Cybench 题目并跑评估循环（eval.benchmark.run_benchmark）+ 汇总 + 写报告。"""
    from eval.benchmark import run_benchmark, summarize
    from eval.corpus import apply_corpus_gate

    from benchmarks.cybench.adapter import load_cybench_questions

    questions = load_cybench_questions(list(sources))
    if not questions:
        logger.warning("[cybench] 无可用 Cybench 题目：%s", list(sources))
        return {"total": 0, "solved": 0, "solve_rate": 0.0}

    if apply_corpus_gate:
        questions, unmeasurable, _raw = apply_corpus_gate(questions)
        if unmeasurable:
            logger.warning(
                "[cybench] 剔除 %d 道不可测题（--no-gate 可保留）", len(unmeasurable)
            )

    solver = fixture_solver() if use_fixture else (lambda q, a=0: {"flag": None})
    results = run_benchmark(
        questions, solver, max_retries=max_retries, use_mock=False,
        per_question_wallclock_s=30.0,
    )
    summary = summarize(results)

    out_dir = Path(results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "mode": "cybench_dryrun",
        "disclaimer": "dry-run 仅验证数据通路（加载→评分→报告），非真实解题水位；fixture 为合成样本",
        "summary": summary,
        "results": [r.to_dict() for r in results],
    }
    (out_dir / "benchmark_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("[cybench] 报告已导出: %s", out_dir / "benchmark_report.json")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Cybench dry-run（不依赖 Docker/密钥）")
    ap.add_argument(
        "--source", nargs="*", default=None,
        help="Cybench 题目来源（文件/目录/glob）；默认内置合成样本或 --real",
    )
    ap.add_argument(
        "--real", action="store_true",
        help="加载 benchmarks/external_unseen/questions 的真实 ext_cybench_* 任务",
    )
    ap.add_argument(
        "--no-fixture", action="store_true",
        help="不使用 fixture solver（真实题会悉数计 0）",
    )
    ap.add_argument(
        "--no-gate", action="store_true",
        help="不做可测性分层（保留 input-less 题）",
    )
    ap.add_argument("--results-dir", default="data/results/cybench_dryrun")
    args = ap.parse_args()

    if args.real:
        sources = args.source or _default_real_sources()
    else:
        sources = args.source or _default_sample_sources()
    dry_run(
        sources,
        use_fixture=not args.no_fixture,
        apply_corpus_gate=not args.no_gate,
        results_dir=args.results_dir,
    )


if __name__ == "__main__":
    main()
