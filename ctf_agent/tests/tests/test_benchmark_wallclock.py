# -*- coding: utf-8 -*-
"""eval/benchmark.py 比赛墙钟（裁决②）单测。"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval import benchmark  # noqa: E402


class _Q:
    id = "q1"
    category = "crypto"


def test_wallclock_timeout_marks_failure():
    """超过墙钟的 async solver 判 wallclock_timeout 失败，而非"解出"。"""
    async def slow_solver(q, attempt):
        await asyncio.sleep(10)  # 远超墙钟
        return {"flag": "flag{x}"}  # 永不到达

    results = benchmark.run_benchmark(
        [_Q()], slow_solver, max_retries=1, per_question_wallclock_s=0.01
    )
    assert results[0].solved is False
    assert results[0].error == "wallclock_timeout"


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
