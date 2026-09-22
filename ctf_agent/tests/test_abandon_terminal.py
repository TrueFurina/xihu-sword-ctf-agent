"""P0-5 / P0-7 回归测试（2026-09-23 held-out 验证跑实证修复）。

背景（磁盘实测，非推演）
----------------------
`ext_gctf2023_cursved` 一题被外层重跑了 **4 段步循环**（attempt 0→2→0→0，每段 8-9 步、
每段都以 ABANDON 结束），且预算超限后连烧 5 步（102,256 → 111,021 tokens）才被 scheduler
兜底终止。两个缺陷：

- **P0-5**：`plan/act` 步异常统一 `continue`，把「预算硬顶」当成可重试的单步失败 → 空烧。
- **P0-7**：ABANDON 落地 `wrong_direction`（决策错），被外层当「换条路再试」→ 重跑，
  使 F1 早停的止损效果被完全抹掉。

本文件锁死两件事：①预算异常被识别且不误伤普通容错；②终态失败落到**与
eval/benchmark.NON_RETRYABLE_CATEGORIES 同名**的类别（防跨模块口径漂移）。
"""
from __future__ import annotations

import asyncio

import pytest

from core.main_agent import (
    ERR_EXTRACT_FAIL,
    ERR_RACE_ABANDON,
    ERR_WRONG_DIRECTION,
    AgentContext,
    _classify_give_up_category,
    _is_budget_exhausted,
)


class _Q:
    def __init__(self, qid: str) -> None:
        self.id = qid


def _ctx(qid: str = "q_ordinary", **kw) -> AgentContext:
    ctx = AgentContext(question=_Q(qid))
    for k, v in kw.items():
        setattr(ctx, k, v)
    return ctx


class _FakeBudgetExceeded(Exception):
    """仿 scheduler.budget.BudgetExceeded：靠 category 属性标识。"""

    category = "budget_exceeded"


# ── A. 预算异常识别 ────────────────────────────────────────────────


def test_budget_exceeded_recognized_by_category():
    assert _is_budget_exhausted(_FakeBudgetExceeded("x: 102591 >= 100000")) is True


def test_budget_exceeded_recognized_by_text():
    """无 category 属性的包装异常，走文本兜底。"""
    assert _is_budget_exhausted(RuntimeError("单题 token 预算超限（q: 1 >= 2）")) is True
    assert _is_budget_exhausted(RuntimeError("budget_exceeded")) is True


@pytest.mark.parametrize(
    "exc",
    [
        SyntaxError("invalid syntax"),          # 2026-09-19 容错场景：LLM 写出语法错误脚本
        ValueError("bad literal"),
        asyncio.TimeoutError(),
        RuntimeError("connection reset"),
        KeyError("flag"),
    ],
)
def test_ordinary_step_errors_are_not_budget(exc):
    """反误伤：普通单步失败必须 continue 重试（那是有价值的容错），不能被当预算硬顶误杀。"""
    assert _is_budget_exhausted(exc) is False


def test_real_budget_exceeded_class_if_importable():
    """与真实异常类对齐（若可导入）：识别必须成立，防止属性名漂移。"""
    try:
        from scheduler.budget import BudgetExceeded
    except Exception:  # noqa: BLE001  环境缺失时跳过，不影响主断言
        pytest.skip("scheduler.budget 不可用")
    assert getattr(BudgetExceeded, "category", None) == "budget_exceeded"


# ── B. 终态分类 ────────────────────────────────────────────────────


def test_abandoned_is_terminal_not_wrong_direction():
    ctx = _ctx(give_up_reason="budget_reflection 早停(ABANDON)", _abandoned=True)
    cat, detail = _classify_give_up_category(ctx)
    assert cat == ERR_RACE_ABANDON
    assert "ABANDON" in detail


def test_budget_hard_stop_is_terminal():
    ctx = _ctx(give_up_reason="预算硬顶：单题 token 预算超限", _budget_hard_stop=True)
    cat, _ = _classify_give_up_category(ctx)
    assert cat == ERR_RACE_ABANDON


def test_plain_supervisor_give_up_still_wrong_direction():
    """不回归：监督裁决放弃（真·方向错）仍归 wrong_direction，保留换路重试的价值。"""
    ctx = _ctx(give_up_reason="监督裁决放弃：方向错误")
    cat, _ = _classify_give_up_category(ctx)
    assert cat == ERR_WRONG_DIRECTION


def test_known_gap_takes_priority():
    ctx = _ctx(qid="10732", give_up_reason="缺参数", _abandoned=True)
    cat, _ = _classify_give_up_category(ctx)
    assert cat == ERR_EXTRACT_FAIL


def test_terminal_category_matches_benchmark_non_retryable():
    """跨模块口径锁：main_agent 产出的终态类别必须被 benchmark 判为不可重试。

    这是本修复生效的**充要条件**——若两边字面量漂移，P0-3 短路失效，
    就会重现实测的「ABANDON 后重跑 4 段」。
    """
    from eval.benchmark import NON_RETRYABLE_CATEGORIES

    assert ERR_RACE_ABANDON in NON_RETRYABLE_CATEGORIES, (
        f"main_agent 终态类别 {ERR_RACE_ABANDON!r} 不在 benchmark 不可重试集合 "
        f"{sorted(NON_RETRYABLE_CATEGORIES)} —— 早停会被重试抹掉"
    )


def test_abandoned_ctx_end_to_end_is_non_retryable():
    """端到端：一个被 ABANDON 的 ctx 走完分类，其结果确实触发 benchmark 短路判定。"""
    from eval.benchmark import NON_RETRYABLE_CATEGORIES

    ctx = _ctx(give_up_reason="budget_reflection 早停(ABANDON)", _abandoned=True)
    cat, _ = _classify_give_up_category(ctx)
    assert cat in NON_RETRYABLE_CATEGORIES


# ── C. 默认值不回归 ────────────────────────────────────────────────


def test_context_defaults_are_not_terminal():
    ctx = AgentContext(question=_Q("q"))
    assert ctx._abandoned is False
    assert ctx._budget_hard_stop is False
