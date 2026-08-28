# -*- coding: utf-8 -*-
"""MainAgent E2 步骤预算与止损测试（2026-08-25 桶B攻坚）。

验证 E2 三机制（不依赖真 LLM/工具，全 mock）：
1. 每题 LLM 调用预算硬封顶 12（难题 15 步 → 收敛 12，杜绝无限试错）
2. 每步超时（step_timeout_s）触发单步失败而非拖死整题/并发池
3. 连续同动作 3 次 → 强制切换策略（strategy_switches++，不空等到放弃）
4. result 契约暴露 llm_calls / step_timeouts 供 goal_log 统计
"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace
from unittest.mock import patch

from core.main_agent import (
    MainAgent,
    AgentContext,
    SupervisionVerdict,
    StepRecord,
    STAGE_STUCK,
    ERR_TOOL_FAILURE,
    ERR_STUCK_LOOP,
)


def _q(difficulty="EASY", category="crypto"):
    return SimpleNamespace(
        id="t",
        category=category,
        difficulty=difficulty,
        description="解题题面信息（模拟有数据，绕过 crypto/misc 无数据快速失败，专测纯 LLM 循环预算/止损）",
        attachments=None,
        flag_pattern=r"flag\{[^}]+\}",
    )


async def _fake_supervise(*a, **k):
    return SupervisionVerdict(action="continue")


def _fake_observe(agent, ctx, plan, act):
    # 每步记一个无错误的 StepRecord，action 取 plan 的 action（供同动作检测）
    return StepRecord(
        stage="recon",
        action=str(plan.get("action", "reason")),
        observation=str(act)[:200],
        error_category=None,
    )


async def _fake_presolve(*a, **k):
    return None


def _capturing_plan_factory(captured, action="reason", sleep=None):
    async def _p(agent, ctx, attempt):
        captured["ctx"] = ctx
        if sleep:
            await asyncio.sleep(sleep)
        return {"action": action, "hypothesis": "stuck_loop_probe"}
    return _p


async def _run_with(agent, question, plan_factory, act_return=None):
    async def _act(*a, **k):
        return act_return or {}
    with patch("core.phases.plan_step", plan_factory), \
         patch("core.phases.act_step", _act), \
         patch("core.phases.supervise_step", _fake_supervise), \
         patch("core.phases.observe_step", _fake_observe), \
         patch("core.presolve.presolve", _fake_presolve):
        return await agent.solve(question)


def test_llm_call_budget_capped_at_12():
    """HARD 题原 15 步 → E2 预算封顶 12；llm_calls==12，无 flag → stuck_loop。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    plan = _capturing_plan_factory(captured, action="reason")
    res = asyncio.run(_run_with(agent, _q(difficulty="HARD"), plan))
    ctx = captured["ctx"]
    assert ctx.llm_calls == 12, f"期望 llm_calls==12（预算封顶），实得 {ctx.llm_calls}"
    assert res["llm_calls"] == 12, "result 契约应暴露 llm_calls"
    err = res.get("error")
    assert err is not None and err["category"] == ERR_STUCK_LOOP, \
        f"无 flag 应 stuck_loop，实得 {err}"
    print("✓ test_llm_call_budget_capped_at_12 (llm_calls=12)")


def test_per_step_timeout_does_not_hang():
    """step_timeout_s=0.3，plan 挂起 10s → 单步超时记失败，整题快速返回（不拖死）。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, step_timeout_s=0.3, llm_call_budget=12)
    plan = _capturing_plan_factory(captured, action="reason", sleep=10)
    t0 = asyncio.get_event_loop().time() if False else __import__("time").monotonic()
    res = asyncio.run(_run_with(agent, _q(difficulty="EASY"), plan))
    elapsed = __import__("time").monotonic() - t0
    ctx = captured["ctx"]
    assert ctx.step_timeouts >= 1, f"期望 step_timeouts>=1，实得 {ctx.step_timeouts}"
    assert elapsed < 5, f"每步超时保护应使整题远快于 10s 挂起，实耗 {elapsed:.1f}s"
    assert res["step_timeouts"] >= 1, "result 契约应暴露 step_timeouts"
    print(f"✓ test_per_step_timeout_does_not_hang (step_timeouts={ctx.step_timeouts}, 耗时{elapsed:.2f}s)")


def test_repeated_action_3_times_forces_switch():
    """连续 3 步同 action（reason）→ 强制切换策略：strategy_switches>=1。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    plan = _capturing_plan_factory(captured, action="reason")
    asyncio.run(_run_with(agent, _q(difficulty="EASY"), plan))
    ctx = captured["ctx"]
    assert ctx.strategy_switches >= 1, \
        f"连续同动作3次应触发强制 switch_strategy，strategy_switches={ctx.strategy_switches}"
    print(f"✓ test_repeated_action_3_times_forces_switch (strategy_switches={ctx.strategy_switches})")


def test_budget_and_switch_coexist_on_hard_stuck():
    """综合：HARD + 同动作 reason → 既封顶 12 调用，又触发 switch（桶B双机制叠加）。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    plan = _capturing_plan_factory(captured, action="reason")
    asyncio.run(_run_with(agent, _q(difficulty="HARD"), plan))
    ctx = captured["ctx"]
    assert ctx.llm_calls == 12
    assert ctx.strategy_switches >= 1
    print(f"✓ test_budget_and_switch_coexist (llm_calls={ctx.llm_calls}, switches={ctx.strategy_switches})")


if __name__ == "__main__":
    test_llm_call_budget_capped_at_12()
    test_per_step_timeout_does_not_hang()
    test_repeated_action_3_times_forces_switch()
    test_budget_and_switch_coexist_on_hard_stuck()
    print("=== main_agent E2 预算/止损测试全部通过 ===")
