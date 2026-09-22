"""P0-8 回归测试（2026-09-23 held-out 验证跑实证）。

背景（磁盘实测）
--------------
`ext_gctf2023_cursved` 一题被重跑 4 段步循环，单题烧 111K tokens 零候选。
追查发现**三层重试循环**里只有 benchmark 层做了终态短路：

  ① `eval/benchmark.py` `for attempt in range(max_retries)`  ← P0-3 已修
  ② `verify/feedback.py` `FeedbackLoop.run` `for attempt in range(retries)`  ← 本文件守护（P0-8）
  ③ `core/main_agent.py` 步循环内的 continue/break            ← P0-5/P0-7 已修

② 是最内层——每轮都会重新进入主 Agent 的**整个步循环**，此前完全不看
`error.category`，因此终态失败被重烧到 retries 耗尽。

本文件锁死①：终态类别在 FeedbackLoop 层立即返回（solver 只被调 1 次）；
②：非终态失败仍走满 retries（反误伤）；③：两层用的是**同一个口径对象**。
"""
from __future__ import annotations

import asyncio

import pytest

from core.error_taxonomy import NON_RETRYABLE_CATEGORIES
from verify.feedback import FeedbackLoop


class _Q:
    def __init__(self, qid: str = "q1") -> None:
        self.id = qid
        self.flag_pattern = None


def _run(solver, max_retries: int = 3):
    return asyncio.run(FeedbackLoop(max_retries=max_retries).run(_Q(), solver))


def _counting_solver(payload: dict):
    """返回 (solver, calls) —— solver 每次都返回同一 payload 并计数。"""
    calls: list[int] = []

    async def solver(question, attempt, correction=None):
        calls.append(attempt)
        return dict(payload)

    return solver, calls


# ── A. 终态类别：FeedbackLoop 必须立即返回 ──────────────────────────


@pytest.mark.parametrize("cat", sorted(NON_RETRYABLE_CATEGORIES))
def test_terminal_category_short_circuits_at_feedback_layer(cat):
    solver, calls = _counting_solver({"flag": None, "error": {"category": cat}})
    out = _run(solver, max_retries=3)
    assert len(calls) == 1, f"终态 {cat!r} 应只调 solver 1 次，实际 {len(calls)} 次"
    assert out["retries"] == 0
    assert out["validated"] is False
    assert out["error"]["category"] == cat


def test_transient_category_still_retries():
    """反误伤：瞬时/未分类失败必须走满重试（校验-反馈循环的核心价值）。"""
    for payload in (
        {"flag": None},                                      # 无 error 字段
        {"flag": None, "error": {"category": "no_output"}},  # 正常判负
        {"flag": None, "error": {"category": "rate_limited"}},
        {"flag": None, "error": {"category": "provider_error"}},
    ):
        solver, calls = _counting_solver(payload)
        _run(solver, max_retries=3)
        assert len(calls) == 3, f"{payload} 应重试 3 次，实际 {len(calls)} 次"


def test_success_returns_immediately():
    """不回归：解出（格式校验通过）立即返回，不受终态短路影响。"""
    solver, calls = _counting_solver({"flag": "flag{ok}"})
    out = _run(solver, max_retries=3)
    assert len(calls) == 1
    assert out.get("validated") is True


def test_missing_error_key_is_safe():
    """None 安全：error 为 None / 非 dict 时不得抛异常。"""
    for payload in ({"flag": None, "error": None}, {"flag": None, "error": "oops"}):
        solver, calls = _counting_solver(payload)
        _run(solver, max_retries=2)
        assert len(calls) == 2


# ── B. 跨模块口径锁（防字面量漂移）────────────────────────────────


def test_feedback_and_benchmark_share_same_object():
    """两层必须消费**同一个**口径对象——散落复刻字面量正是本次事故的根因。"""
    from eval.benchmark import NON_RETRYABLE_CATEGORIES as bench_cat

    assert bench_cat is NON_RETRYABLE_CATEGORIES, (
        "benchmark 与 error_taxonomy 的不可重试口径不是同一对象 —— 存在漂移风险"
    )


def test_main_agent_terminal_category_is_covered():
    """main_agent 产出的终态类别必须在本单一真值内（P0-7 × P0-8 接口一致）。"""
    from core.main_agent import ERR_RACE_ABANDON

    assert ERR_RACE_ABANDON in NON_RETRYABLE_CATEGORIES
