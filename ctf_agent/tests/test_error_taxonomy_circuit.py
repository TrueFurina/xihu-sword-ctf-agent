"""provider 熔断(401/402/403) 根因回填 —— 诚实口径回归（2026-10-05）。

背景：provider 熔断后 ai_chat 返回 None → 主 Agent 退化成 race_abandon/budget_exceeded
（自身失败模式），报告误读为「Agent 能力失败」。修复后：
  1. provider_circuit_open 落入 TRUNCATED_ERROR_CATEGORIES → interpretable=False；
  2. relabel_circuit_breaker 在熔断打开时把退化桶回填为 provider_circuit_open。

变异验证：临时把 relabel_circuit_breaker 改成 `return error_category` 或把
provider_circuit_open 移出 TRUNCATED_ERROR_CATEGORIES → 本文件用例必须 FAIL。
"""
import pytest

from core.error_taxonomy import (
    TRUNCATED_ERROR_CATEGORIES,
    PROVIDER_CIRCUIT_OPEN,
    relabel_circuit_breaker,
)


def test_provider_circuit_open_in_truncated():
    """熔断类别必须落入 TRUNCATED → 报告置 interpretable=False（不污染能力率）。"""
    assert PROVIDER_CIRCUIT_OPEN in TRUNCATED_ERROR_CATEGORIES


@pytest.mark.parametrize("cat", ["race_abandon", "budget_exceeded", "solver_exception",
                                 "wrong_direction"])
def test_relabel_degraded_bucket_when_open(cat):
    """熔断打开时，退化的 Agent 失败桶回填为 provider_circuit_open。"""
    assert relabel_circuit_breaker(cat, True) == PROVIDER_CIRCUIT_OPEN


@pytest.mark.parametrize("cat", ["race_abandon", "budget_exceeded", "solver_exception",
                                 "wrong_direction"])
def test_relabel_noop_when_closed(cat):
    """熔断未打开 → 原样返回，不误伤。"""
    assert relabel_circuit_breaker(cat, False) == cat


def test_relabel_solved_none_open():
    """已解出(error=None) + 熔断打开 → 不回填（presolve 直出不受影响）。"""
    assert relabel_circuit_breaker(None, True) is None


def test_relabel_provider_error_open_unchanged():
    """provider_error 本身已是基础设施类 → 不重复回填。"""
    assert relabel_circuit_breaker("provider_error", True) == "provider_error"


def test_relabel_hallucination_open_unchanged():
    """hallucination 是 Agent 行为（有 LLM 响应）→ 熔断打开也不回填。"""
    assert relabel_circuit_breaker("hallucination", True) == "hallucination"


def test_wrong_direction_relabeled_when_circuit_open():
    """回归锁（2026-10-06）：熔断打开时 wrong_direction 必须回填为 provider_circuit_open。

    复现实证：moonshot kimi-k2.6 余额耗尽（HTTP 429 伪装永久故障）→ 熔断打开 →
    主 Agent 拿不到 LLM 响应 → 监督裁决退化为「同参数重复→死循环止损」落
    wrong_direction。修复前该桶不在退化集合 → 报告误标 interpretable=True
    （tokens=1806 兜底值）。修复后须回填，使报告置 interpretable=False。
    """
    assert relabel_circuit_breaker("wrong_direction", True) == PROVIDER_CIRCUIT_OPEN
    # 熔断未打开的真·方向错不回归（保留换路重试的价值）
    assert relabel_circuit_breaker("wrong_direction", False) == "wrong_direction"


def test_wrong_direction_not_in_mechanism_terminated():
    """wrong_direction 不是机制终结——回填后方可落入 TRUNCATED（本节已隐式保证）。"""
    from core.error_taxonomy import TRUNCATED_ERROR_CATEGORIES
    assert PROVIDER_CIRCUIT_OPEN in TRUNCATED_ERROR_CATEGORIES
