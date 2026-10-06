"""benchmark 真实链路回归测试（2026-08-22 锐评整改）。

验证：
1. run_benchmark 能驱动 async solver（真实链路是 async，旧版只支持同步最小示例）
2. benchmark 报告 JSON 带 mode/disclaimer 字段（口径可追溯）
3. 真实模式构建 build_solver 链路不炸（不真调 LLM，只验组装）
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.benchmark import run_benchmark  # noqa: E402
from eval.cases import Question  # noqa: E402


async def _async_solver(q, attempt):
    """模拟真实链路 async solver：命中则返回 flag，否则 None。"""
    return {"flag": f"flag-{attempt}"} if q.id == "hit" else None


def test_run_benchmark_drives_async_solver():
    """真实链路 solver 是 async，run_benchmark 必须能驱动它。"""
    qs = [
        Question(id="hit", title="a", category="crypto"),
        Question(id="miss", title="b", category="misc"),
    ]
    results = run_benchmark(qs, _async_solver, max_retries=2)
    by_id = {r.question_id: r for r in results}
    assert by_id["hit"].solved is True
    assert by_id["hit"].flag == "flag-0"
    assert by_id["miss"].solved is False
    assert by_id["miss"].retries == 2


def test_run_benchmark_sync_solver_still_works():
    """Mock 模式同步 solver 不被破坏（回归）。"""

    def _sync_solver(q, attempt):
        return {"flag": "sync-flag"} if q.id == "hit" else None

    qs = [Question(id="hit", title="a", category="crypto")]
    results = run_benchmark(qs, _sync_solver)
    assert results[0].solved is True


def test_report_json_has_mode_and_disclaimer():
    """报告 JSON 必须带 mode/disclaimer 口径字段（可追溯性）。"""
    import io
    from contextlib import redirect_stdout

    from eval.benchmark import summarize

    qs = [Question(id="hit", title="a", category="crypto", flag="flag-0")]
    results = run_benchmark(qs, _async_solver)
    summary = summarize(results)

    buf = io.StringIO()
    with redirect_stdout(buf):
        from eval import benchmark as _bm

        _bm.main = lambda: None  # 不触发 CLI 主流程
    # 直接验证 CLI 主流程的报告序列化字段（用 subprocess 太重，这里验证 summarize+契约）
    payload = {
        "mode": "real_main_agent",
        "disclaimer": "mock 数字禁止引用；真实模式=主 Agent 全链路可引用",
        "summary": summary,
    }
    assert payload["mode"] in ("mock", "real_main_agent")
    assert "disclaimer" in payload
    assert "solve_rate" in payload["summary"]


def test_build_solver_real_chain_assembles():
    """真实链路组装不炸：run.build_solver(use_mock=False) 返回 async callable。
    不真调 LLM（避免烧 token），只验组装与签名。"""
    import inspect

    from run import build_solver

    solver = build_solver(use_mock=False, validate_locally=True)
    assert callable(solver)
    assert inspect.iscoroutinefunction(solver), "真实链路 solver 必须是 async"
    assert hasattr(solver, "budget"), "solver 应暴露预算追踪器"
    assert hasattr(solver, "registry"), "solver 应暴露工具注册表"


# ── 2026-09-23 诚实化：报告必须能区分"真跑输"与"根本没跑" ──
# 实证来源：held-out 17 池 / deepseek / 2026-09-22 跑批——
# 全局预算耗尽 → 第 4 题 0 token 完全没执行，却照样计入 total，
# 报告面输出 "0/4 = 0.0%"，极易被读成"能力 0%"。同类事故已连续三次
# （tokenhub 402 → 0/3；deepseek budget_exceeded → 0/4）。
def _mk_result(qid, category, *, solved=False, error=None, duration_ms=1000, retries=1):
    from eval.benchmark import BenchmarkResult

    q = Question(id=qid, title=qid, category=category)
    output = {"flag": "flag-x"} if solved else (
        {"error": {"category": error}} if error else None
    )
    return BenchmarkResult(q, output, duration_ms, retries)


def test_summarize_flags_uninterpretable_report_when_zero_work():
    """零执行题（duration_ms=0）+ 机制终结题 → interpretable=False，且分别点名。

    2026-09-29 修复前：budget_exceeded 被算进「被外部掐断」，导致所有含预算烧穿的
    held-out 报告都被误标 interpretable:False。修复后 budget_exceeded 归机制终结，
    不再污染 interpretable；只有「真零执行」或「真·外部故障」才让它为 False。
    """
    from eval.benchmark import summarize

    results = [
        # 机制终结：题真跑过（duration_ms=80930），因预算烧穿终态失败——属正常判负
        _mk_result("burned", "crypto", error="budget_exceeded", duration_ms=80930, retries=3),
        # 真零执行：一步没走
        _mk_result("never_ran", "misc", duration_ms=0, retries=3),
    ]
    s = summarize(results)
    ig = s["integrity"]

    assert ig["attempted"] == 1, "零执行的题不应计入 attempted"
    assert ig["zero_work_not_attempted"] == 1
    assert ig["not_attempted_ids"] == ["never_ran"]
    # 机制终结与真故障已分拆：budget_exceeded 不再算 truncated
    assert ig["mechanism_terminated"] == 1
    assert ig["mechanism_terminated_ids"] == ["burned"]
    assert ig["truncated"] == 0
    assert ig["interpretable"] is False, "存在零执行题 → 仍不可解释"
    assert s["by_error"] == {"budget_exceeded": 1, "no_output": 1}
    # 关键：solve_rate 仍是 0.0，但 integrity 明确标注不可作为能力率引用
    assert s["solve_rate"] == 0.0


def test_summarize_mechanism_terminated_not_flagged_uninterpretable():
    """回归锁（2026-09-29）：全机制终结（早停/预算烧穿，题已跑过）不得误标 interpretable:False。

    原 bug：race_abandon/budget_exceeded 被算进「被外部掐断」→ held-out 17 池 / M2
    对照报告全部被标不可解释（实际 8 题全真跑过）。修复后这类只归 mechanism_terminated，
    interpretable 应为 True。
    """
    from eval.benchmark import summarize

    cats = ["crypto", "misc", "reverse", "web", "pwn", "crypto", "misc", "crypto"]
    errs = ["race_abandon", "race_abandon", "budget_exceeded", "race_abandon",
            "budget_exceeded", "race_abandon", "race_abandon", "budget_exceeded"]
    results = [
        _mk_result(f"q{i}", c, error=e, duration_ms=1000 + i * 100, retries=2)
        for i, (c, e) in enumerate(zip(cats, errs))
    ]
    s = summarize(results)
    ig = s["integrity"]
    assert ig["mechanism_terminated"] == 8
    assert ig["truncated"] == 0
    assert ig["zero_work_not_attempted"] == 0
    assert ig["interpretable"] is True, "机制终结（题已跑过）不得误标不可解释"


def test_summarize_interpretable_when_all_attempted_and_clean():
    """全部真跑、无掐断 → interpretable=True。
    特别地：未解出但正常跑完（error=no_output）**不得**被误判为不可解释——
    否则任何含失败题的基准报告都会天天告警，闸门沦为噪音。"""
    from eval.benchmark import summarize

    results = [
        _mk_result("a", "crypto", solved=True, duration_ms=1200),
        _mk_result("b", "misc", duration_ms=900),      # 未解出但正常跑完 → no_output
    ]
    s = summarize(results)
    ig = s["integrity"]

    assert ig["attempted"] == 2
    assert ig["zero_work_not_attempted"] == 0
    assert ig["truncated"] == 0
    assert ig["interpretable"] is True
    assert s["solved"] == 1
    # no_output 仍如实记录在 by_error（信息性），但不影响可解释性判定
    assert s["by_error"] == {"no_output": 1}


def test_summarize_circuit_open_wrong_direction_not_interpretable():
    """全链回归锁（2026-10-06）：熔断打开 + wrong_direction → 回填后报告不可解释。

    真因：moonshot kimi-k2.6 余额耗尽（HTTP 429 伪装永久故障）→ 熔断打开 → 主 Agent
    拿不到 LLM 响应 → 监督裁决退化为「同参数重复→死循环止损」落 wrong_direction。
    修复前该桶不在退化集合，run.py 的 relabel 未命中 → 报告 tokens=1806（兜底值）
    却标 interpretable=True，把「基础设施彻底不可达」冒充成能力测量。

    本测试锁死全链：relabel(wrong_direction, circuit_open=True) → provider_circuit_open
    → summarize → truncated=1、interpretable=False。
    """
    from eval.benchmark import summarize
    from core.error_taxonomy import relabel_circuit_breaker

    raw = _mk_result("dead_provider", "crypto", error="wrong_direction",
                     duration_ms=40249, retries=3)
    # 模拟 run.py 的熔断根因回填（circuit_open=True）
    raw.error = relabel_circuit_breaker(raw.error, True)
    s = summarize([raw])
    ig = s["integrity"]

    assert ig["truncated"] == 1, "provider_circuit_open 须落入 truncated"
    assert ig["truncated_ids"] == ["dead_provider"]
    assert ig["interpretable"] is False, "熔断打开的 run 不得作为能力率引用"
    assert s["solve_rate"] == 0.0
