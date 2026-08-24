# -*- coding: utf-8 -*-
"""_supervision_stats 采纳率统计测试（2026-08-23 质检④整改）。

验证监督裁决流水统计的正确性：
1. 空流水 → 全零统计
2. 纯 continue → total=N, corrective=0, rate=0.0
3. 混合裁决 → corrective 与 by_action 计数正确
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.main_agent import (
    AgentContext,
    _supervision_stats,
    VERDICT_CONTINUE,
    VERDICT_REDIRECT,
    VERDICT_SWITCH,
    VERDICT_UPGRADE,
    VERDICT_GIVE_UP,
)


def _make_ctx(verdicts):
    """构造带指定裁决流水的 AgentContext。"""
    ctx = AgentContext()
    ctx.supervisor_verdicts = list(verdicts)
    return ctx


def test_empty_verdicts_zero_stats():
    """空流水：不咨询监督 → 全零统计（监督未介入）。"""
    ctx = _make_ctx([])
    stats = _supervision_stats(ctx)
    assert stats["total"] == 0
    assert stats["corrective"] == 0
    assert stats["corrective_rate"] == 0.0
    assert stats["by_action"] == {}


def test_all_continue_no_corrective():
    """纯 continue：监督每次都默认放行 → 干预率 0。"""
    ctx = _make_ctx([
        {"action": VERDICT_CONTINUE, "step_index": 1},
        {"action": VERDICT_CONTINUE, "step_index": 3},
    ])
    stats = _supervision_stats(ctx)
    assert stats["total"] == 2
    assert stats["corrective"] == 0
    assert stats["corrective_rate"] == 0.0
    assert stats["by_action"] == {VERDICT_CONTINUE: 2}


def test_mixed_verdicts_counts():
    """混合裁决：干预率与各 action 计数正确。"""
    ctx = _make_ctx([
        {"action": VERDICT_CONTINUE, "step_index": 1},
        {"action": VERDICT_SWITCH, "step_index": 4},
        {"action": VERDICT_UPGRADE, "step_index": 6},
        {"action": VERDICT_CONTINUE, "step_index": 8},
        {"action": VERDICT_GIVE_UP, "step_index": 10},
    ])
    stats = _supervision_stats(ctx)
    assert stats["total"] == 5
    assert stats["corrective"] == 3          # switch + upgrade + give_up
    assert stats["corrective_rate"] == round(3 / 5, 3)
    assert stats["by_action"] == {
        VERDICT_CONTINUE: 2,
        VERDICT_SWITCH: 1,
        VERDICT_UPGRADE: 1,
        VERDICT_GIVE_UP: 1,
    }


def test_missing_action_defaults_continue():
    """字段缺失：无 action 的流水按 continue 兜底（不误计为干预）。"""
    ctx = _make_ctx([
        {"step_index": 1},                     # 无 action
        {"action": VERDICT_REDIRECT, "step_index": 2},
    ])
    stats = _supervision_stats(ctx)
    assert stats["total"] == 2
    assert stats["corrective"] == 1           # 仅 redirect
    assert stats["by_action"][VERDICT_CONTINUE] == 1
    assert stats["by_action"][VERDICT_REDIRECT] == 1


def test_finalize_includes_stats():
    """_finalize 输出含 supervision_stats 字段（埋点端到端）。"""
    from core.main_agent import MainAgent

    agent = MainAgent()
    ctx = _make_ctx([
        {"action": VERDICT_CONTINUE, "step_index": 1},
        {"action": VERDICT_UPGRADE, "step_index": 3},
    ])
    out = agent._finalize(ctx, attempt=0)
    stats = out["supervision_stats"]
    assert stats["total"] == 2
    assert stats["corrective"] == 1
    assert stats["corrective_rate"] == 0.5
