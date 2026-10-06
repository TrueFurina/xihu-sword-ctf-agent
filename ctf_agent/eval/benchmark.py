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


# 2026-09-23：两个错误口径常量已提升为**单一真值** core/error_taxonomy.py——
# 因为它们在多层重试循环（benchmark 层 + FeedbackLoop 层）被共同消费，
# 散落复刻字面量已致实证事故（见 core/error_taxonomy.py 模块 docstring）。
# 此处保留同名 re-export，向后兼容既有 import（tests 等）。
from core.error_taxonomy import (  # noqa: E402
    NON_RETRYABLE_CATEGORIES,
    TRUNCATED_ERROR_CATEGORIES,
)

# 2026-09-29 诚实化修复：机制终结 ≠ 被外部掐断。
# race_abandon / budget_exceeded 是「题跑过了，因预算/反思早停而终态失败」——
# 属正常判负，不是「基础设施未执行 / 被外部掐断」。把它们与真正的外部故障
# （solver_exception / 限流 / 无凭证 …）分开，否则所有
# held-out 报告都被误标 interpretable:false（M2 实测 8 题全真跑过仍被误标）。
#
# 🔴 2026-10-06 wallclock 内外拆分（消除「过度作废」）：原 wallclock_timeout 被
#   三处产生点共用同一名字，报告层无法区分来路，导致 Agent **用满公平窗口**的真实
#   测量被当成「被外部掐断」一并作废。现按来源拆成两类：
#     · wallclock_timeout ← **Agent 内部**墙钟硬止损（main_agent._wallclock_hit /
#       run.py 竞速墙钟），= 题跑过了、用满设计窗口仍没解出 → **正常判负**，归入本集合；
#     · wallclock_killed  ← **评测器外部** wait_for 掐断（见 _solve_question），
#       = Agent 未跑完即被杀（真·infra 故障）→ 留在 TRUNCATED_ERROR_CATEGORIES，
#       如实标 interpretable:false。
#   实证依据（A5 held-out 报告）：duration≈180.0s=外部掐断、≈155-160s=内部止损，
#   此前同名混算使两者全部被作废。
# 注意：NON_RETRYABLE_CATEGORIES 仍必须含全部三类以短路重试——此处只改报告语义，
# 不动重试口径（改动最小原则，详见 core/error_taxonomy.py docstring）。
MECHANISM_TERMINATED_CATEGORIES = frozenset({
    "race_abandon",
    "budget_exceeded",
    "wallclock_timeout",
})


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
    race_controller: "Optional[RaceController]" = None,
    concurrency: int = 1,
    progress_path: Optional[str] = None,
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
    async def _solve_question(q) -> BenchmarkResult:
        """单题完整求解（重试循环 + 墙钟 + race 早停），并发安全（ContextVar 记账）。

        提取为协程：串行路径用独立事件循环逐个驱动；并发路径由 Semaphore+gather
        在同一循环内并发驱动。solver 支持 sync / async 两种（async 自动 await）。
        """
        start = time.perf_counter()
        output = None
        retries = 0
        for attempt in range(max_retries):
            try:
                _out = solver(q, attempt)
                if asyncio.iscoroutine(_out):
                    try:
                        output = await asyncio.wait_for(_out, timeout=per_question_wallclock_s)
                    except asyncio.TimeoutError:
                        # 2026-10-06：评测器**外部**掐断，与 Agent 内部墙钟止损区分。
                        # 内部止损（wallclock_timeout）走 MECHANISM_TERMINATED_CATEGORIES
                        # → 视为正常判负、保留可解释性；外部掐断（wallclock_killed）
                        # = Agent 未跑完即被杀（真 infra 故障）→ 留在 TRUNCATED，
                        # 如实标 interpretable:false。
                        output = {"error": {"category": "wallclock_killed",
                                            "detail": f"超过 {per_question_wallclock_s:.0f}s 硬墙钟（评测器外部掐断）"}}
                        break  # 超时不再重试
                else:
                    output = _out
            except Exception as exc:  # noqa: BLE001 - 单题求解异常不中断整体评测
                logger.warning("[%s] 求解异常: %s", getattr(q, "id", "?"), exc)
                output = {"error": {"category": "solver_exception", "detail": str(exc)[:200]}}
            if output and output.get("flag"):
                break
            # P0-3 修复（2026-09-23）：终态失败类别不可通过立即重跑恢复，跳过重试避免空烧预算/墙钟。
            _err_cat = (((output or {}).get("error") or {}).get("category")) if output else None
            if _err_cat in NON_RETRYABLE_CATEGORIES:
                logger.info("[%s] 终态失败(%s)，跳过重试避免空烧预算", getattr(q, "id", "?"), _err_cat)
                break
            # race-intelligence 预算反思早停（默认关闭；开启后仅 ABANDON 时提前中断重试）
            if race_controller is not None and output is not None:
                _decision = race_controller.reflect_on_attempt(q.id, output, attempt, max_retries)
                if _decision == "ABANDON":
                    output = {"error": {"category": "race_abandon",
                                        "detail": "budget_reflection ABANDON 早停，避免空烧预算"}}
                    break
        retries = attempt + 1
        duration_ms = int((time.perf_counter() - start) * 1000)
        return BenchmarkResult(q, output, duration_ms, retries)

    if concurrency and concurrency > 1:
        # 并发层（Block 2 解锁）：单事件循环 + Semaphore(N) + gather 真实并发跑题。
        # 默认关闭（concurrency<=1 走下方串行，行为与历史完全一致，零回归）。
        # 注意：真实模式（MainAgent 共享实例）并发时，presolve 直出题（stateless）安全；
        # LLM 重度题共享 MainAgent 上下文需隔离——kpi9 题集 LLM 贡献 0/9，故本基准并发低风险。
        async def _run_concurrent():
            # Semaphore 必须在运行中的循环内创建，否则会绑定到错误的事件循环
            # （asyncio.Semaphore 在循环外构造时捕获 get_event_loop()，与 run_until_complete
            # 新建的 _loop 不一致 → "future belongs to a different loop"）。
            _sem = asyncio.Semaphore(concurrency)

            async def _bounded(q):
                async with _sem:
                    return await _solve_question(q)

            return await asyncio.gather(*[_bounded(q) for q in questions], return_exceptions=True)

        _loop = asyncio.new_event_loop()
        try:
            _gathered = _loop.run_until_complete(_run_concurrent())
        finally:
            _loop.close()
        results: list[BenchmarkResult] = []
        for _r in _gathered:
            if isinstance(_r, Exception):
                logger.error("并发求解崩溃（已跳过该题）: %s", _r)
                continue
            results.append(_r)
        return results

    # 串行（默认）：每题独立事件循环，与历史版本行为一致
    results = []
    for q in questions:
        _loop = asyncio.new_event_loop()
        try:
            results.append(_loop.run_until_complete(_solve_question(q)))
        finally:
            _loop.close()
        # 崩溃安全网（2026-09-01）：逐题落盘——即使中途异常终止（B1 exit=1 教训），
        # 已完成题的原始数据不丢（progress.jsonl）。
        if progress_path:
            try:
                import json as _json
                with open(progress_path, "a", encoding="utf-8") as _pf:
                    _pf.write(_json.dumps(results[-1].to_dict(), ensure_ascii=False) + "\n")
            except Exception:  # noqa: BLE001 - 进度落盘失败不影响评测
                pass
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

    # 2026-09-23 诚实化修复：区分「真尝试后判负」与「根本没跑/被预算掐死」。
    # 根因：held-out 17 池跑批中全局预算耗尽 → 第 4 题 0 token 完全没执行，
    # 但它照样被计入 total，报告面输出 "0/4 = 0.0%"——这个数字会被读成
    # "能力 0%"，而事实是"钱不够、压根没试"。同类事故已连续发生三次
    # （tokenhub 402 → 0/3；deepseek budget_exceeded → 0/4）。
    # 口径：
    #   zero_work  = duration_ms 为 0（一步没走成）
    #   truncated  = 被外部条件掐断（预算/墙钟/异常/限流），**不含** no_output
    #                （no_output = solver 正常跑完但没解出，是正常的判负，不是错误）
    # interpretable=False 时，solve_rate **不得**作为能力率对外引用。
    by_error: dict[str, int] = {}
    for r in results:
        _e = getattr(r, "error", None)
        if _e:
            _k = str(_e)
            by_error[_k] = by_error.get(_k, 0) + 1
    zero_work = [r for r in results if not int(getattr(r, "duration_ms", 0) or 0)]
    # 机制终结（题跑过，因早停/预算烧穿终态失败，属正常判负）—— 不复用
    # TRUNCATED_ERROR_CATEGORIES，否则会把「跑过的题」误标成「被外部掐断」。
    mechanism_terminated = [
        r for r in results
        if str(getattr(r, "error", "") or "") in MECHANISM_TERMINATED_CATEGORIES
    ]
    # 真·外部/基础设施掐断（不含机制终结、不含 no_output）。
    truncated = [
        r for r in results
        if str(getattr(r, "error", "") or "") in TRUNCATED_ERROR_CATEGORIES
        and str(getattr(r, "error", "") or "") not in MECHANISM_TERMINATED_CATEGORIES
    ]
    integrity = {
        "attempted": total - len(zero_work),
        "zero_work_not_attempted": len(zero_work),
        "not_attempted_ids": [getattr(r, "question_id", None) for r in zero_work],
        "mechanism_terminated": len(mechanism_terminated),
        "mechanism_terminated_ids": [getattr(r, "question_id", None) for r in mechanism_terminated],
        "truncated": len(truncated),
        "truncated_ids": [getattr(r, "question_id", None) for r in truncated],
        "interpretable": (len(truncated) == 0 and len(zero_work) == 0),
    }

    return {
        "total": total,
        "solved": solved,
        "solve_rate": round(solved / total, 3) if total else 0.0,
        "by_category": by_category,
        "by_provenance": by_provenance,
        "by_solved_by": by_solved_by,
        "by_error": by_error,
        "integrity": integrity,
    }


def _run_benchmark_safely(args, questions, solver, use_mock: bool, race_controller) -> list:
    """崩溃安全网（2026-09-01）：run_benchmark + 逐题进度落盘 + BaseException 兜底报告。

    B1 首跑 exit=1（无 traceback、无报告）教训——任何逃逸（SystemExit/KeyboardInterrupt 等
    BaseException 类，`except Exception` 抓不住）都要留下诊断信息与已完成数据，
    不允许静默丢报告。
    """
    import dataclasses
    from pathlib import Path

    _progress = str(Path(args.results_dir) / "progress.jsonl")
    try:
        return run_benchmark(questions, solver, max_retries=args.max_retries, use_mock=use_mock,
                             per_question_wallclock_s=args.wallclock,
                             race_controller=race_controller, concurrency=args.concurrency,
                             progress_path=_progress)
    except BaseException as _bex:  # noqa: BLE001 - 安全网兜底（一切逃逸）
        logger.error("评测异常终止（安全网捕获）: %r", _bex)
        try:
            _od = Path(args.results_dir)
            _od.mkdir(parents=True, exist_ok=True)
            (_od / "benchmark_report.json").write_text(
                json.dumps({"aborted": True, "abort_reason": repr(_bex)},
                           ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception:  # noqa: BLE001 - 兜底报告失败不影响 raise
            pass
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="CTF-Agent 题库评测（解出率优先）")
    parser.add_argument("--questions-dir", default="data/questions")
    parser.add_argument("--results-dir", default="data/results")
    parser.add_argument("--mock", action="store_true", help="使用 Mock 求解器（数字禁止引用，仅回归）")
    parser.add_argument("--provider", default="deepseek",
                        help="真实模式 LLM provider；支持逗号分隔多 provider（如 deepseek）顺序跑，"
                             "报告含 per_provider 与各 provider 均解出(robust 交集)，避免单 provider 熔断致 KPI 不可复现。"
                             "注意：原默认值 baidu 已欠费（403 account_overdue，实测不可达），真跑一律 deepseek；"
                             "不要因本默认值而省略 --provider 以外的省钱约束（真实跑批仍须先估 token 与金额并获授权）。")
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--limit", type=int, default=0, help="只跑前 N 题（真实模式省钱调试，0=全部）")
    parser.add_argument("--wallclock", type=float, default=300.0,
                        help="每题硬墙钟秒数（默认 300s 对齐比赛模式，超时判 timeout 失败）")
    parser.add_argument("--presolve-skip", action="store_true",
                        help="跳过确定性预扫（presolve），强制走主 Agent 全链路——"
                             "构造「必须走主 Agent」的子集（回归集饱和时 presolve 14/15 直出，"
                             "主 Agent 改进测不到，用本参数做 A/B 对比）")
    parser.add_argument("--race-intelligence", action="store_true",
                        help="启用 race-intelligence 预算反思早停（默认关闭；接入 "
                             "core.race_orchestrator.RaceController，零 LLM、可单测）")
    parser.add_argument("--concurrency", type=int, default=1,
                        help="题目并发数（Block 2 解锁）：1=串行(历史默认,零回归)；"
                             ">1=单事件循环+Semaphore(N)+gather 真实并发跑题。真实模式共享 MainAgent，"
                             "presolve 直出题安全；LLM 重度题建议先隔离 MainAgent 再高并发")
    args = parser.parse_args()

    from eval.cases import load_questions, preset_answers

    questions = load_questions(args.questions_dir)
    if not questions:
        logger.warning("题库为空，请先往 %s 放入题目 JSON", args.questions_dir)
        return
    if args.limit and args.limit > 0:
        questions = questions[: args.limit]

    # race-intelligence 接入（默认关闭）：构造控制器并规划资源分配方案
    race_controller = None
    if args.race_intelligence:
        from core.race_orchestrator import RaceController
        race_controller = RaceController()
        _alloc = race_controller.plan(questions)
        logger.info("RACE-INTELLIGENCE 已接入：Allocation concurrency=%s per_question_budget=%.3f focus=%s",
                    _alloc.concurrency, _alloc.per_question_budget, _alloc.focus)

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
                                per_question_wallclock_s=args.wallclock,
                                race_controller=race_controller, concurrency=args.concurrency)
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
                               skip_presolve=args.presolve_skip,
                               wallclock=args.wallclock)  # P1 墙钟对齐：评测墙钟下传 Agent

        async def solver(q, attempt):
            out = await _solver(q, attempt)
            # 未通过正确性校验的 flag 一律视为未解出（build_solver 已把 flag 置 None）
            return out

        logger.info("真实基线钉死配置 provider=%s base_url_host=%s wallclock=%.0fs",
                    providers[0], _bu_host, args.wallclock)
        results = _run_benchmark_safely(args, questions, solver, use_mock=False,
                                        race_controller=race_controller)
        summary = summarize(results)
        # Claim 1 实验（2026-08-28）：真实 token 用量（solver.budget 记账）——
        # 供"熔断降 Token"对比实验报实测基线（评估要求 ≥3 种子 + CI，先报基线再谈 delta）。
        _b = getattr(_solver, "budget", None)
        if _b is not None:
            summary["tokens"] = {
                "global_total": _b.global_usage,   # @property，非方法
                "per_question": {q.id: _b.usage(q.id) for q in questions},
            }
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
                               skip_presolve=args.presolve_skip,
                               wallclock=args.wallclock)  # P1 墙钟对齐：评测墙钟下传 Agent

        async def solver(q, attempt, _s=_solver):
            return await _s(q, attempt)

        logger.info("真实基线(多provider之一) provider=%s base_url_host=%s wallclock=%.0fs",
                    prov, _bu_host, args.wallclock)
        res = _run_benchmark_safely(args, _questions, solver, use_mock=False,
                                    race_controller=race_controller)
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
        # 2026-09-23 诚实化：报告不可解释时**主动喊出来**，不让 0/N 被误读成能力率。
        _ig = summary.get("integrity", {})
        if not _ig.get("interpretable", True):
            print("  !! 本报告不可作为能力率引用：分母含「真未执行」或「被基础设施掐断」的题 !!")
            print(f"     真尝试 {_ig.get('attempted')}/{summary['total']}；"
                  f"零执行(未尝试) {_ig.get('zero_work_not_attempted')} 题"
                  f"{_ig.get('not_attempted_ids') or ''}；"
                  f"被外部掐断(真故障) {_ig.get('truncated')} 题 {_ig.get('truncated_ids') or ''}")
            print(f"     错误分类分布: {summary.get('by_error')}")
            print("     solve_rate 只反映'钱/配额够不够'，不反映能力；引用前必须重跑或声明口径。")
        elif _ig.get("mechanism_terminated", 0):
            # 机制终结（早停/预算烧穿，题已跑过，属正常判负）—— 不影响可解释性，
            # 但诚实标注，避免与「真未执行」混淆。
            print(f"  · {_ig.get('mechanism_terminated')} 题属「机制终结」"
                  f"（早停/预算烧穿，题已跑过，属正常判负）："
                  f"{_ig.get('mechanism_terminated_ids') or ''}")
    print(f"报告已导出: {report_path}")


if __name__ == "__main__":
    main()
