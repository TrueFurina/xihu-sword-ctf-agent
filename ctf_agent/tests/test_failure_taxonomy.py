# -*- coding: utf-8 -*-
"""4 类失败埋点测试（2026-08-22 赛后重锐评 M1.3）。

验证：
1. 提取错（extract_flag 拒绝）→ error.category=extract_fail
2. 工具调用错（步骤级 tool_failure 累积）→ tool_failure
3. 决策错（监督 give_up）→ wrong_direction
4. 全新 ctx（无任何信号）仍 → stuck_loop（回归保护，不误判）
5. goal_directive.classify_failure 的 4 类映射
6. extract_flag 拒绝路径会落 ctx._extract_failed 标记
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace
from core.main_agent import (
    MainAgent,
    AgentContext,
    StepRecord,
    ERR_WALLCLOCK_TIMEOUT,
    ERR_STUCK_LOOP,
    ERR_TOOL_FAILURE,
    ERR_WRONG_DIRECTION,
    ERR_EXTRACT_FAIL,
)


def _make_question(qid="t1", category="crypto"):
    return SimpleNamespace(
        id=qid, category=category, title="test", description="",
        flag_pattern=r"flag\{[^}]+\}", attachments=None,
    )


def test_extract_fail_classified():
    """提取错：候选 flag 被拒 → extract_fail。"""
    agent = MainAgent(per_question_wallclock=300)
    ctx = AgentContext(question=_make_question())
    ctx._extract_failed = True
    result = agent._finalize(ctx, attempt=0)
    err = result.get("error")
    assert err is not None
    assert err["category"] == ERR_EXTRACT_FAIL, f"期望 extract_fail，实得 {err['category']}"
    print("✓ test_extract_fail_classified")


def test_tool_failure_classified():
    """工具调用错：步骤级 tool_failure 累积 → tool_failure。"""
    agent = MainAgent(per_question_wallclock=300)
    ctx = AgentContext(question=_make_question())
    ctx.record(StepRecord(action="tool:python", error_category=ERR_TOOL_FAILURE))
    ctx.record(StepRecord(action="tool:python", error_category=ERR_TOOL_FAILURE))
    result = agent._finalize(ctx, attempt=0)
    err = result.get("error")
    assert err is not None
    assert err["category"] == ERR_TOOL_FAILURE, f"期望 tool_failure，实得 {err['category']}"
    print("✓ test_tool_failure_classified")


def test_wrong_direction_classified():
    """决策错：监督 give_up 落 wrong_direction。"""
    agent = MainAgent(per_question_wallclock=300)
    ctx = AgentContext(question=_make_question())
    ctx.give_up_reason = "监督裁决：方向错误，连续失败"
    result = agent._finalize(ctx, attempt=0)
    err = result.get("error")
    assert err is not None
    assert err["category"] == ERR_WRONG_DIRECTION, f"期望 wrong_direction，实得 {err['category']}"
    assert "监督裁决" in err["detail"]
    print("✓ test_wrong_direction_classified")


def test_fresh_ctx_still_stuck_loop():
    """回归保护：无任何失败信号时仍 stuck_loop（不误判）。"""
    agent = MainAgent(per_question_wallclock=300)
    ctx = AgentContext(question=_make_question())
    result = agent._finalize(ctx, attempt=0)
    err = result.get("error")
    assert err is not None
    assert err["category"] == ERR_STUCK_LOOP, f"期望 stuck_loop，实得 {err['category']}"
    print("✓ test_fresh_ctx_still_stuck_loop")


def test_wallclock_still_priority():
    """墙钟优先：即便提取失败标记已打，墙钟命中仍归 wallclock_timeout。"""
    agent = MainAgent(per_question_wallclock=300)
    ctx = AgentContext(question=_make_question())
    ctx._wallclock_hit = True
    ctx._extract_failed = True
    result = agent._finalize(ctx, attempt=0)
    assert result["error"]["category"] == ERR_WALLCLOCK_TIMEOUT
    print("✓ test_wallclock_still_priority")


def test_classify_failure_mapping():
    """goal_directive.classify_failure 的 4 类映射。"""
    from core.goal_directive import classify_failure

    assert classify_failure("wallclock_timeout") == "超时"
    assert classify_failure("tool_failure") == "工具调用错"
    assert classify_failure("wrong_direction") == "决策错"
    assert classify_failure("stuck_loop") == "决策错"
    assert classify_failure("extract_fail") == "提取错"
    assert classify_failure("hallucination") == "提取错"
    assert classify_failure("budget_exceeded") == "other"
    assert classify_failure(None) == "other"
    assert classify_failure("unknown_xyz") == "other"
    print("✓ test_classify_failure_mapping")


def test_extract_flag_reject_sets_marker():
    """extract_flag 的格式符模板拒绝路径 → ctx._extract_failed=True。"""
    from core.phases import extract_flag

    agent = MainAgent(per_question_wallclock=300)
    ctx = AgentContext(question=_make_question())
    flag = extract_flag(agent, ctx, {"output": "flag{%d-%d}"})
    assert flag is None
    assert ctx._extract_failed is True, "格式符模板拒绝应打提取错标记"
    print("✓ test_extract_flag_reject_sets_marker")


if __name__ == "__main__":
    test_extract_fail_classified()
    test_tool_failure_classified()
    test_wrong_direction_classified()
    test_fresh_ctx_still_stuck_loop()
    test_wallclock_still_priority()
    test_classify_failure_mapping()
    test_extract_flag_reject_sets_marker()
    print("=== 4 类失败埋点测试全部通过 ===")
