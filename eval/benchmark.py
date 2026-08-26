"""题库评测基准：解出率优先统计（v2.1）。

统计维度（对齐解出率优先战略）：
- 各题型解出率 = 解出题数 / 总题数
- 单题耗时（ms）
- 重试次数（校验-反馈循环）
- 模型升级记录（分级降级调度是否触发）

用法：
    python -m eval.benchmark --questions-dir data/questions --mock     # Mock 链路（仅回归统计框架连通性）
    python -m eval.benchmark --questions-dir data/questions            # 真实链路（主 Agent 全链路）

**口径声明（2026-08-22 锐评整改）**：
- 真实模式（非 --mock）solver 已接入 run.build_solver(use_mock=False)——
  主 Agent Plan-Act-Observe 全链路（工具层 + 监督 + 校验 + FeedbackLoop）。
  真实模式产出的解出率 = 主 Agent 全链路水位，**可以引用**。
- Mock 模式数字（预设答案直出）**禁止引用**，仅用于统计框架连通性回归。
  与《诚实水位声明.md》口径一致。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


class BenchmarkResult:
    """单题评测结果。"""

    def __init__(self, question, output: Optional[dict], duration_ms: int, retries: int):
        self.question_id = question.id
        self.category = question.category
        self.provenance = getattr(question, "provenance", "self_authored_training")
        self.solved = bool(output and output.get("flag"))
        self.flag = output.get("flag") if output else None
        self.confidence = (output or {}).get("confidence", 0.0)
        self.error = ((output or {}).get("error") or {}).get("category") if output else "no_output"
        self.duration_ms = duration_ms
        self.retries = retries
        # 2026-08-24 诚实化：解出路径（presolve=静态分析器零 LLM / main_agent_llm=真推理）
        self.solved_by = (output or {}).get("solved_by", "unknown")

    def to_dict(self) -> dict:
        return {
            "question_id": self.question_id,
            "category": self.category,
            "provenance": self.provenance,
            "solved": self.solved,
            "solved_by": self.solved_by,
            "flag": self.flag,
            "confidence": self.confidence,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "retries": self.retries,
        }


def run_benchmark(
    questions,
    solver,
    max_retries: int = 3,
    use_mock: bool = False,
    per_question_wallclock_s: float = 300.0,
) -> list[BenchmarkResult]:
    """对题目列表逐个求解并统计。

    Args:
        questions: 题目列表
        solver: callable(question, attempt) -> AgentOutput dict | None
                （async callable 亦可——真实链路为 async，此处自动 await）
        max_retries: 校验-反馈循环最大重试次数
        use_mock: 是否使用 mock（仅用于统计标识）
        per_question_wallclock_s: 每题硬墙钟（秒，默认 300s 对齐比赛模式）。

    墙钟口径（2026-08-23 锐评整改）：评测器必须与比赛执行器同一约束——超过墙钟的题
    判为 wallclock_timeout 失败，而非"解出"。否则评测高估比赛形态下的真实表现。
    """
    results: list[BenchmarkResult] = []
    for q in questions:
        start = time.perf_counter()
        output = None
        retries = 0
        for attempt in range(max_retries):
            try:
                _out = solver(q, attempt)
                if asyncio.iscoroutine(_out):
                    # 真实链路为 async solver：用独立事件循环驱动（CLI 同步上下文）
                    _loop = asyncio.new_event_loop()
                    try:
                        # 比赛墙钟：超过 per_question_wallclock_s 强杀（asyncio.wait_for 超时）
                        output = _loop.run_until_complete(
                            asyncio.wait_for(_out, timeout=per_question_wallclock_s)
                        )
                    except asyncio.TimeoutError:
                        output = {"error": {"category": "wallclock_timeout",
                                            "detail": f"超过 {per_question_wallclock_s:.0f}s 硬墙钟"}}
                        break  # 超时不再重试
                    finally:
                        _loop.close()
                else:
                    output = _out
            except Exception as exc:  # noqa: BLE001 - 单题求解异常不中断整体评测
                logger.warning("[%s] 求解异常: %s", getattr(q, "id", "?"), exc)
                output = {"error": {"category": "solver_exception", "detail": str(exc)[:200]}}
            if output and output.get("flag"):
                break
            retries = attempt + 1
        duration_ms = int((time.perf_counter() - start) * 1000)
        results.append(BenchmarkResult(q, output, duration_ms, retries))
    return results


def summarize(results: list[BenchmarkResult]) -> dict:
    """汇总统计：解出率/耗时/重试次数（按题型分组）。"""
    total = len(results)
    solved = sum(1 for r in results if r.solved)
    by_category: dict[str, dict] = {}
    for r in results:
        bucket = by_category.setdefault(
            r.category, {"total": 0, "solved": 0, "durations": [], "retries": []}
        )
        bucket["total"] += 1
        bucket["solved"] += 1 if r.solved else 0
        bucket["durations"].append(r.duration_ms)
        bucket["retries"].append(r.retries)

    for bucket in by_category.values():
        bucket["solve_rate"] = round(bucket["solved"] / bucket["total"], 3) if bucket["total"] else 0.0
        bucket["avg_duration_ms"] = (
            round(sum(bucket["durations"]) / len(bucket["durations"]), 1)
            if bucket["durations"]
            else 0
        )
        bucket["avg_retries"] = (
            round(sum(bucket["retries"]) / len(bucket["retries"]), 2)
            if bucket["retries"]
            else 0
        )

    # 溯源口径拆分（2026-08-24 诚实化整改）：唯一 KPI 只看 real_past_ctf，
    # self_authored_training 仅训练不计分。防止自产题稀释外部真值水位。
    by_provenance: dict[str, dict] = {}
    for r in results:
        bucket = by_provenance.setdefault(
            r.provenance, {"total": 0, "solved": 0}
        )
        bucket["total"] += 1
        bucket["solved"] += 1 if r.solved else 0
    for bucket in by_provenance.values():
        bucket["solve_rate"] = round(bucket["solved"] / bucket["total"], 3) if bucket["total"] else 0.0

    # 2026-08-24 诚实化：解出路径拆分（presolve 静态分析器 vs main_agent_llm 真推理）
    # 杜绝把静态分析器功劳算到 LLM 头上（第六轮锐评防自欺核心）。
    by_solved_by: dict[str, dict] = {}
    for r in results:
        bucket = by_solved_by.setdefault(
            r.solved_by, {"total": 0, "solved": 0, "solved_list": []}
        )
        bucket["total"] += 1
        if r.solved:
            bucket["solved"] += 1
            bucket["solved_list"].append(r.question_id)
    for bucket in by_solved_by.values():
        bucket["solve_rate"] = round(bucket["solved"] / bucket["total"], 3) if bucket["total"] else 0.0

    return {
        "total": total,
        "solved": solved,
        "solve_rate": round(solved / total, 3) if total else 0.0,
        "by_category": by_category,
        "by_provenance": by_provenance,
        "by_solved_by": by_solved_by,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="CTF-Agent 题库评测（解出率优先）")
    parser.add_argument("--questions-dir", default="data/questions")
    parser.add_argument("--results-dir", default="data/results")
    parser.add_argument("--mock", action="store_true", help="使用 Mock 求解器（数字禁止引用，仅回归）")
    parser.add_argument("--provider", default="baidu",
                        help="真实模式 LLM provider；支持逗号分隔多 provider（如 baidu,qwen）顺序跑，"
                             "报告含 per_provider 与各 provider 均解出(robust 交集)，避免单 provider 熔断致 KPI 不可复现")
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--limit", type=int, default=0, help="只跑前 N 题（真实模式省钱调试，0=全部）")
    parser.add_argument("--wallclock", type=float, default=300.0,
                        help="每题硬墙钟秒数（默认 300s 对齐比赛模式，超时判 timeout 失败）")
    parser.add_argument("--presolve-skip", action="store_true",
                        help="跳过确定性预扫（presolve），强制走主 Agent 全链路——"
                             "构造「必须走主 Agent」的子集（回归集饱和时 presolve 14/15 直出，"
                             "主 Agent 改进测不到，用本参数做 A/B 对比）")
    args = parser.parse_args()

    from eval.cases import load_questions, preset_answers

    questions = load_questions(args.questions_dir)
    if not questions:
        logger.warning("题库为空，请先往 %s 放入题目 JSON", args.questions_dir)
        return
    if args.limit and args.limit > 0:
        questions = questions[: args.limit]

    # 钉死审计（2026-08-23）：打印本次基线使用的 provider/base_url，保证数字可复现、可审计。
    # base_url 含赛事网关路径，仅打印 host 段，不暴露凭证路径。
    _bu = os.getenv("CTF_AGENT_LLM_BASE_URL", "") or "<config-default>"
    _bu_host = _bu.split("//", 1)[-1].split("/", 1)[0] if _bu != "<config-default>" else _bu

    if args.mock:
        from llm.mock import mock_solve, set_preset_answers

        set_preset_answers(preset_answers(questions))

        def solver(q, attempt):
            return mock_solve(q.id, q.to_prompt_text(), q.category)

        logger.info("MOCK 基线（数字禁止引用）：仅统计框架回归")
        results = run_benchmark(questions, solver, max_retries=args.max_retries, use_mock=True,
                                per_question_wallclock_s=args.wallclock)
        summary = summarize(results)
        _emit_report(args, "mock", summary, results, None)
        return

    # 真实链路（2026-08-22 锐评整改）：接入 run.build_solver(use_mock=False)——
    # 主 Agent Plan-Act-Observe 全链路（工具层+监督+校验+FeedbackLoop）。
    from run import build_solver

    providers = [p.strip() for p in args.provider.split(",") if p.strip()]
    if len(providers) == 1:
        # 单 provider：行为与历史版本完全一致（保持可复现基线）。
        _solver = build_solver(use_mock=False, provider=providers[0], validate_locally=True,
                               skip_presolve=args.presolve_skip)

        async def solver(q, attempt):
            out = await _solver(q, attempt)
            # 未通过正确性校验的 flag 一律视为未解出（build_solver 已把 flag 置 None）
            return out

        logger.info("真实基线钉死配置 provider=%s base_url_host=%s wallclock=%.0fs",
                    providers[0], _bu_host, args.wallclock)
        results = run_benchmark(questions, solver, max_retries=args.max_retries, use_mock=False,
                                per_question_wallclock_s=args.wallclock)
        summary = summarize(results)
        _emit_report(args, "real_main_agent", summary, results, None)
        return

    # 多 provider 互备（2026-08-24 诚实化整改）：顺序跑每个 provider，
    # 报告含 per_provider 逐家汇总 + robust_intersection（所有 provider 均解出=真解出，
    # 规避单 provider 熔断/配额耗尽导致 KPI 随脸色漂移、不可比）。
    per_provider: dict[str, dict] = {}
    intersection_ids: Optional[set] = None
    union_ids: set = set()
    for prov in providers:
        # 2026-08-24 修复（SoftwareWorkshop / 任务 SW-QWEN1）：
        # 原实现复用同一批 Question 对象给所有 provider。baidu 先跑时
        # core.presolve.presolve() 会给每题打 `_PRESOLVE_ATTEMPTED` 去重标记
        # （core/presolve.py:294-305）；qwen 后跑时 presolve 见标记直接 return None
        # → 零 presolve 命中、全靠 LLM 慢解、union/robust 口径被污染（实测 qwen
        # 7 解全被错算成 main_agent_llm，robust 从潜在 13 掉到 7）。
        # 每 provider 重新 load 题目对象，使 presolve 不被前一家 provider 标记污染，
        # 还原干净的 solved_by 归因与可复现的 robust/union 口径。
        # 注意：retries 内的同题 presolve 跳过（dedup）仍保留——那是单题维度
        # 的正确语义，与跨 provider 的对象复用是两回事。
        _questions = load_questions(args.questions_dir)
        if args.limit and args.limit > 0:
            _questions = _questions[: args.limit]
        _solver = build_solver(use_mock=False, provider=prov, validate_locally=True,
                               skip_presolve=args.presolve_skip)

        async def solver(q, attempt, _s=_solver):
            return await _s(q, attempt)

        logger.info("真实基线(多provider之一) provider=%s base_url_host=%s wallclock=%.0fs",
                    prov, _bu_host, args.wallclock)
        res = run_benchmark(_questions, solver, max_retries=args.max_retries, use_mock=False,
                            per_question_wallclock_s=args.wallclock)
        summ = summarize(res)
        per_provider[prov] = summ
        ids = {r.question_id for r in res if r.solved}
        union_ids |= ids
        intersection_ids = ids if intersection_ids is None else (intersection_ids & ids)

    total = len(questions)
    robust = {
        "total": total,
        "solved": len(intersection_ids or set()),
        "solve_rate": round(len(intersection_ids or set()) / total, 3) if total else 0.0,
    }
    union = {
        "total": total,
        "solved": len(union_ids),
        "solve_rate": round(len(union_ids) / total, 3) if total else 0.0,
    }
    combined = {
        "mode": "real_main_agent_multi",
        "disclaimer": "mock 数字禁止引用；真实模式=主 Agent 全链路可引用；"
                      "robust_intersection=所有 provider 均解出（最保守真解），union=任一 provider 解出",
        "providers": providers,
        "robust_intersection": robust,
        "union": union,
        "per_provider": per_provider,
    }
    _emit_report(args, "real_main_agent_multi", combined, None, combined)
    print(f"多 provider 报告：robust(全解出)={robust['solved']}/{total}  "
          f"union(任一解出)={union['solved']}/{total}  各家见 per_provider")


def _emit_report(args, mode: str, summary: dict, results, multi: Optional[dict]) -> None:
    """写出 benchmark_report.json 并打印摘要（单/多 provider 共用）。"""
    out_dir = Path(args.results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "benchmark_report.json"
    if multi is not None:
        payload = multi
    else:
        payload = {
            "mode": mode,
            "disclaimer": "mock 数字禁止引用；真实模式=主 Agent 全链路可引用",
            "summary": summary,
            "results": [r.to_dict() for r in results],
        }
    report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=== CTF-Agent 题库评测报告 ===")
    if multi is not None:
        print("口径: 真实链路（主 Agent 全链路，多 provider 互备）")
        print(f"robust 交集(全 provider 解出): {multi['robust_intersection']['solved']}/"
              f"{multi['robust_intersection']['total']} = {multi['robust_intersection']['solve_rate']}")
        for prov, summ in multi["per_provider"].items():
            bp = summ.get("by_provenance", {})
            rp = bp.get("real_past_ctf", {})
            sf = bp.get("self_authored_training", {})
            print(f"  [{prov}] 解出 {summ['solved']}/{summ['total']} = {summ['solve_rate']}"
                  f"  | real={rp.get('solve_rate', 'n/a')} self={sf.get('solve_rate', 'n/a')}")
    else:
        print(f"口径: {'MOCK（数字禁止引用）' if mode == 'mock' else '真实链路（主 Agent 全链路，可引用）'}")
        print(f"总题数: {summary['total']}  解出: {summary['solved']}  解出率: {summary['solve_rate']}")
        bp = summary.get("by_provenance", {})
        if "real_past_ctf" in bp:
            print(f"  [真实赛题 real_past_ctf] 解出 {bp['real_past_ctf']['solved']}/"
                  f"{bp['real_past_ctf']['total']} = {bp['real_past_ctf']['solve_rate']}  ← 唯一 KPI 分母")
        if "self_authored_training" in bp:
            print(f"  [自产训练 self_authored_training] 解出 {bp['self_authored_training']['solved']}/"
                  f"{bp['self_authored_training']['total']} = {bp['self_authored_training']['solve_rate']}  ← 不计分")
        for cat, bucket in summary["by_category"].items():
            print(
                f"  [{cat}] 解出率 {bucket['solve_rate']} "
                f"({bucket['solved']}/{bucket['total']})  均耗时 {bucket['avg_duration_ms']}ms  "
                f"均重试 {bucket['avg_retries']} 次"
            )
    print(f"报告已导出: {report_path}")


if __name__ == "__main__":
    main()
