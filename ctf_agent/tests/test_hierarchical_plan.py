"""hierarchical_plan 单元测试（P2 第三刀——分层规划，纯规则、无 LLM）。

契约：只在「黑板启用且已有失败/无产出签名」时才注入分层作战视图；
否则 build_hierarchical_view 返回 ''（prompt 与旧版逐字不变，A/B 安全）。
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.hierarchical_plan import build_hierarchical_view  # noqa: E402
from core.main_agent import AgentContext, StepRecord  # noqa: E402
from core.prompts import build_plan_prompt  # noqa: E402
from core.strategy_blackboard import StrategyBlackboard  # noqa: E402


class Q:
    id = "hp_test"
    title = "分层视图测试题"
    category = "misc"
    description = "test"
    flag_pattern = r"flag\{[^}]+\}"
    difficulty = "MEDIUM"


def _step(action="recon:command", tool=None, obs="", err=None):
    return StepRecord(stage="recon", action=action, tool_used=tool,
                      observation=obs, error_category=err)


def _ctx(category="misc", failures=0, blackboard=None):
    q = Q()
    if category is not None:
        q.category = category
    ctx = AgentContext(question=q)
    ctx.blackboard = blackboard
    if blackboard is not None and failures:
        for _ in range(failures):
            ctx.record(_step(err="tool_failure", obs="boom"))
    return ctx


# ── 返回空（A/B 安全）──
def test_none_blackboard_returns_empty():
    assert build_hierarchical_view(_ctx(blackboard=None)) == ""


def test_blackboard_without_failures_returns_empty():
    bb = StrategyBlackboard()
    bb.record(_step(obs="some progress"))  # 仅 progress，无失败
    assert build_hierarchical_view(_ctx(blackboard=bb)) == ""


# ── 正常视图 ──
def test_view_lists_flow_and_tried_and_rule():
    bb = StrategyBlackboard()
    ctx = _ctx(category="misc", failures=3, blackboard=bb)
    v = build_hierarchical_view(ctx)
    assert "【分层作战视图·卡壳换路】" in v
    assert "决策规则" in v
    assert "已试且失败/无产出的策略签名" in v
    assert "× recon|recon:command|-" in v
    assert "1." in v  # 标准路径编号（misc 有 flow）


def test_view_without_flow_still_lists_tried_and_rule():
    bb = StrategyBlackboard()
    ctx = _ctx(category="nonexistent_cat", failures=2, blackboard=bb)
    v = build_hierarchical_view(ctx)
    assert "已试且失败" in v
    assert "决策规则" in v
    # 无 flow 时不产生编号路径行
    assert "1." not in v


def test_failed_signatures_excludes_pure_progress():
    bb = StrategyBlackboard()
    bb.record(_step(obs="progress only", action="ok"))
    bb.record(_step(err="tool_failure", action="fail"))
    sigs = bb.failed_signatures()
    assert len(sigs) == 1
    assert "fail" in sigs[0]


# ── prompt 集成 ──
def test_prompt_injects_view_when_stuck():
    bb = StrategyBlackboard()
    ctx = _ctx(category="misc", failures=2, blackboard=bb)
    assert "【分层作战视图·卡壳换路】" in build_plan_prompt(ctx, 0)


def test_prompt_unchanged_when_blackboard_none():
    ctx_none = _ctx(category="misc", blackboard=None)
    assert "【分层作战视图" not in build_plan_prompt(ctx_none, 0)


def test_prompt_unchanged_when_no_failures():
    # ctx_a：黑板有 1 条 progress（无失败），step 同时进 steps 与黑板
    bb = StrategyBlackboard()
    ctx_a = _ctx(category="misc", blackboard=bb)
    ctx_a.record(_step(obs="ok", action="ok"))
    # ctx_b：无黑板，同 1 步
    ctx_b = _ctx(category="misc", blackboard=None)
    ctx_b.record(_step(obs="ok", action="ok"))
    assert "【分层作战视图" not in build_plan_prompt(ctx_a, 0)
    # 等价性：同 steps、黑板无失败 == 无黑板
    assert build_plan_prompt(ctx_a, 0) == build_plan_prompt(ctx_b, 0)
