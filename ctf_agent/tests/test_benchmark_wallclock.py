# -*- coding: utf-8 -*-
"""eval/benchmark.py 比赛墙钟（裁决②）单测。

2026-10-06 扩展：wallclock 来源拆分回归（消除「过度作废」）——
  · **外部**掐断（评测器 asyncio.wait_for）→ wallclock_killed → truncated → interpretable=False
  · **内部**止损（Agent 墙钟硬止损 main_agent._wallclock_hit）→ wallclock_timeout
    → 机制终结（MECHANISM_TERMINATED_CATEGORIES）→ 不 truncate、保留可解释性
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval import benchmark  # noqa: E402
from core.error_taxonomy import (  # noqa: E402
    NON_RETRYABLE_CATEGORIES,
    TRUNCATED_ERROR_CATEGORIES,
)


class _Q:
    id = "q1"
    category = "crypto"


def test_wallclock_timeout_marks_failure():
    """超过墙钟的 async solver 判失败，而非"解出"。

    2026-10-06：评测器外部掐断 → 类别为 wallclock_killed（区别于内部 wallclock_timeout）。
    """
    async def slow_solver(q, attempt):
        await asyncio.sleep(10)  # 远超墙钟
        return {"flag": "flag{x}"}  # 永不到达

    results = benchmark.run_benchmark(
        [_Q()], slow_solver, max_retries=1, per_question_wallclock_s=0.01
    )
    assert results[0].solved is False
    assert results[0].error == "wallclock_killed"


def test_external_wallclock_is_truncated_and_uninterpretable():
    """外部掐断 → integrity.truncated≥1 且 interpretable=False（不得当能力率引用）。"""
    async def slow_solver(q, attempt):
        await asyncio.sleep(10)
        return {"flag": "flag{x}"}

    results = benchmark.run_benchmark(
        [_Q()], slow_solver, max_retries=1, per_question_wallclock_s=0.01
    )
    s = benchmark.summarize(results)
    ig = s["integrity"]
    assert ig["truncated"] == 1
    assert ig["interpretable"] is False
    assert "wallclock_killed" in s["by_error"]


def test_internal_wallclock_is_mechanism_not_truncated():
    """Agent **内部**墙钟止损（wallclock_timeout）→ 机制终结，不算外部掐断。

    这是「过度作废」修复的核心断言：内部止损 = 题跑过了、用满窗口仍没解出，
    属正常判负，不应被判为「被基础设施掐断」而作废整份报告。
    """
    async def internal_wc_solver(q, attempt):
        await asyncio.sleep(0.005)  # 保证 duration_ms>0（否则落 zero_work）
        return {"error": {"category": "wallclock_timeout", "detail": "内部止损"}}

    results = benchmark.run_benchmark(
        [_Q()], internal_wc_solver, max_retries=1, per_question_wallclock_s=5.0
    )
    assert results[0].error == "wallclock_timeout"
    s = benchmark.summarize(results)
    ig = s["integrity"]
    assert ig["mechanism_terminated"] == 1
    assert ig["truncated"] == 0
    assert ig["interpretable"] is True


def test_taxonomy_wallclock_split():
    """单一真值源一致性：内部 timeout 属机制终结，外部 killed 属真·掐断；两者都不可重试。"""
    assert "wallclock_timeout" in benchmark.MECHANISM_TERMINATED_CATEGORIES
    assert "wallclock_killed" not in benchmark.MECHANISM_TERMINATED_CATEGORIES
    assert "wallclock_killed" in TRUNCATED_ERROR_CATEGORIES
    assert "wallclock_killed" in NON_RETRYABLE_CATEGORIES
    assert "wallclock_timeout" in NON_RETRYABLE_CATEGORIES


def test_fast_solver_not_timed_out():
    """快速 solver 正常解出，不受墙钟影响。"""
    async def fast_solver(q, attempt):
        return {"flag": "flag{ok}"}

    results = benchmark.run_benchmark(
        [_Q()], fast_solver, max_retries=1, per_question_wallclock_s=5.0
    )
    assert results[0].solved is True
    assert results[0].flag == "flag{ok}"


def test_sync_solver_ok():
    """sync solver（mock 链路）不受 wait_for 影响，正常返回。"""
    def sync_solver(q, attempt):
        return {"flag": "flag{sync}"}

    results = benchmark.run_benchmark(
        [_Q()], sync_solver, max_retries=1, per_question_wallclock_s=5.0
    )
    assert results[0].solved is True
