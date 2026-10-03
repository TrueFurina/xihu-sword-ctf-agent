# -*- coding: utf-8 -*-
"""MainAgent E2 步骤预算与止损测试（2026-08-25 桶B攻坚）。

验证 E2 三机制（不依赖真 LLM/工具，全 mock）：
1. 每题 LLM 调用预算硬封顶 12（难题 15 步 → 收敛 12，杜绝无限试错）
2. 每步超时（step_timeout_s）触发单步失败而非拖死整题/并发池
3. 连续同「策略签名」(action, observation[:200], tool) 3 次 → 强制切换策略（P2 修复：换算法/参数的正常探索不误伤）
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
    ERR_UNRESOLVED,
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
    # 每步观察不同 → 不触发死循环止损，可跑满预算封顶（测「封顶」本身）
    res = _run_e2_probe(agent, captured, lambda i: f"distinct-output-{i}", difficulty="HARD")
    ctx = captured["ctx"]
    assert ctx.llm_calls == 12, f"期望 llm_calls==12（预算封顶），实得 {ctx.llm_calls}"
    assert res["llm_calls"] == 12, "result 契约应暴露 llm_calls"
    err = res.get("error")
    # 注：原（action="reason"）口径下此处为 unresolved；本探针用 action="script" 且
    # 全程「无工具报错 + 零候选」→ 按失败谱系正确归类为 stuck_loop（真实空转），两者皆可。
    assert err is not None and err["category"] in (ERR_UNRESOLVED, ERR_STUCK_LOOP), \
        f"预算封顶无 flag 应归为 unresolved/stuck_loop，实得 {err}"
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


def test_budget_cap_and_switch_coexist_on_hard_stuck():
    """综合（2026-10-03 语义更新）：同签名空转时——E2 只切一次，随后交给硬止损，
    故 llm_calls 可能小于封顶 12；预算封顶仍是上限（<=12），无 flag → unresolved。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    # 观察恒定 → 同签名：强切 1 次后硬止损 break
    res = _run_e2_probe(agent, captured, lambda i: "same-output", difficulty="HARD")
    ctx = captured["ctx"]
    assert ctx.llm_calls <= 12, f"预算封顶是上限，实得 {ctx.llm_calls}"
    assert ctx.strategy_switches == 1, \
        f"同签名只应强切一次，实得 {ctx.strategy_switches}"
    err = res.get("error")
    assert err is not None, "空转止损后应有失败归因"
    print(f"✓ test_budget_cap_and_switch_coexist (llm_calls={ctx.llm_calls}, switches={ctx.strategy_switches}, err={err and err['category']})")


def _make_counting_observe(action, obs_factory):
    """可编程 observe：action 固定，observation 由 obs_factory(i) 逐步生成。"""
    counter = {"i": 0}

    def _observe(agent, ctx, plan, act):
        i = counter["i"]
        counter["i"] += 1
        return StepRecord(
            stage="recon",
            action=action,
            observation=obs_factory(i),
            error_category=None,
        )
    return _observe


async def _async_act(*a, **k):
    return {}


def _run_e2_probe(agent, captured, obs_factory, difficulty="EASY"):
    """E2 三元组签名探针：action 固定 script，observation 由 obs_factory(i) 生成。"""
    async def _plan_capture(agent, ctx, attempt):
        captured["ctx"] = ctx
        return {"action": "script", "hypothesis": "e2_triple_probe"}

    observe = _make_counting_observe("script", obs_factory)

    async def _run():
        with patch("core.phases.plan_step", _plan_capture), \
             patch("core.phases.act_step", _async_act), \
             patch("core.phases.supervise_step", _fake_supervise), \
             patch("core.phases.observe_step", observe), \
             patch("core.presolve.presolve", _fake_presolve):
            return await agent.solve(_q(difficulty=difficulty))
    return asyncio.run(_run())


def test_crypto_explore_different_outputs_not_interrupted():
    """P2 修复回归（2026-10-03）：同 action 连续写不同算法脚本（observation 实质不同）
    是正常 crypto 探索，不得被 E2 强制切换打断（G_p2ab 轮 47% 强切误伤的病灶）。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    _run_e2_probe(agent, captured, lambda i: f"rot13 decode attempt -> output variant {i}")
    ctx = captured["ctx"]
    assert ctx.strategy_switches == 0, (
        f"同 action+不同 observation 是正常探索，不应强切，实得 {ctx.strategy_switches}"
    )
    assert len(ctx.steps) >= 8, f"应能持续推进多步而非被打断，实得 {len(ctx.steps)} 步"
    print(f"✓ test_crypto_explore_different_outputs_not_interrupted (steps={len(ctx.steps)}, switches=0)")


def test_same_output_prefix_different_tail_still_interrupted():
    """E2 三元组签名按 observation[:200] 前缀判重：前 200 字符相同、尾部不同的
    近似重复仍会被拦截（比"完全相同 observation"严、比"仅同 action"松）。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    common = "y" * 200
    _run_e2_probe(agent, captured, lambda i: common + f"tail-{i}")
    ctx = captured["ctx"]
    assert ctx.strategy_switches >= 1, (
        f"同 action+同输出前缀（前200字符）应仍触发强切，实得 {ctx.strategy_switches}"
    )
    print(f"✓ test_same_output_prefix_different_tail_still_interrupted (switches={ctx.strategy_switches})")


def test_e2_switches_once_per_signature_then_hard_stop():
    """2026-10-03 G_p2c 实证修复：script 无输出时 observation="" → 三元组恒等，
    E2 每步触发并 continue，屏蔽了下方「同参数重复 → presolve 兜底 → 止损 break」。
    修复后：同一签名只强切一次，重复则放行给硬止损（不再空转到预算耗尽）。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    # 每步 observation 全为空（模拟 script 无输出捕获）→ 三元组恒等
    _run_e2_probe(agent, captured, lambda i: "")
    ctx = captured["ctx"]
    assert ctx.strategy_switches == 1, (
        f"同一签名只应强切一次，实得 {ctx.strategy_switches}"
    )
    assert len(ctx.steps) < 12, (
        f"强切后仍重复应交给硬止损快速 break，而非空转到预算封顶，实得 {len(ctx.steps)} 步"
    )
    print(f"✓ test_e2_switches_once_per_signature_then_hard_stop (steps={len(ctx.steps)}, switches=1)")


def test_distinct_signatures_each_get_one_switch():
    """不同签名互不影响：两份不同签名各允许一次强切（去重按签名而非全局）。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    # 前 3 步签名 A（空观察），之后换签名 B（不同观察）→ 应各切一次
    _run_e2_probe(agent, captured, lambda i: "" if i < 3 else f"new-output-{i}")
    ctx = captured["ctx"]
    assert ctx.strategy_switches >= 1, (
        f"首个签名应触发一次强切，实得 {ctx.strategy_switches}"
    )
    assert len(set(ctx.e2_switched_signatures)) == ctx.strategy_switches, (
        "已强切签名集合大小应与强切次数一致（每次强切对应一个唯一签名）"
    )
    print(f"✓ test_distinct_signatures_each_get_one_switch (switches={ctx.strategy_switches})")


if __name__ == "__main__":
    test_llm_call_budget_capped_at_12()
    test_per_step_timeout_does_not_hang()
    test_repeated_action_3_times_forces_switch()
    test_budget_cap_and_switch_coexist_on_hard_stuck()
    test_crypto_explore_different_outputs_not_interrupted()
    test_same_output_prefix_different_tail_still_interrupted()
    test_e2_switches_once_per_signature_then_hard_stop()
    test_distinct_signatures_each_get_one_switch()
    print("=== main_agent E2 预算/止损测试全部通过 ===")
