# -*- coding: utf-8 -*-
"""策略签名「空输出塌缩」修复回归测试（2026-10-05 架构根因修复）。

病灶（B2 实证 5/5 题在步骤 3–5 被误杀）：
  ``execute_script`` 只取 **stdout** 作 observation；脚本报错（traceback 进 stderr）
  或静默计算 → observation=""，且 script/command 步 ``tool_used=""`` →
  E2 强切 与 同参数重复检测 **共用** 的三元组签名
  ``(action, observation[:200], tool_used)`` 塌缩为常量 ``("script", "", "")``
  → LLM 连续写**不同算法**的解密脚本（正常探索）被误判「同策略死循环」：
  E2 强切一次（dedup）→ 下一步命中死循环检测 → ``break`` 弃题。

修复：``StepRecord.plan_fp``（plan 全字段稳定哈希）在「观察无有效载荷」时参与判重，
      两处判重（E2 强切 / 死循环检测）统一走 ``_strategy_signature``。

本测试锁定三层：
  1. ``_strategy_signature`` 直接语义（无载荷用指纹 / 有载荷同旧三元组 / rc-only 视作无载荷）
  2. ``_plan_fingerprint`` 稳定性（同 plan 同指纹、不同 code 不同指纹）
  3. 端到端：**真** observe_step + 每步不同脚本（空输出）→ 不强切、不误判死循环
"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace
from unittest.mock import patch

from core.main_agent import (
    MainAgent,
    StepRecord,
    SupervisionVerdict,
    _strategy_signature,
    _RC_ONLY_RE,
)
from core.phases import _plan_fingerprint, observe_step


# ──────────────────────────── 单元：_strategy_signature ────────────────────────────

def _step(action="script", obs="", tool="", plan_fp=""):
    return StepRecord(action=action, observation=obs, tool_used=tool, plan_fp=plan_fp)


def test_no_payload_uses_plan_fp_to_distinguish():
    """核心修复：同 action、空 observation、无 tool——但 plan 不同 → 签名必须不同。"""
    a = _strategy_signature(_step(obs="", plan_fp="aaaaaaaaaaaa"))
    b = _strategy_signature(_step(obs="", plan_fp="bbbbbbbbbbbb"))
    assert a != b, f"不同脚本指纹应得不同签名，实得 {a} == {b}"
    print("✓ test_no_payload_uses_plan_fp_to_distinguish")


def test_no_payload_same_plan_fp_still_collapses():
    """真重复（同脚本静默）仍被判重——不因放宽而放过真正的空转。"""
    a = _strategy_signature(_step(obs="", plan_fp="samefin"))
    b = _strategy_signature(_step(obs="", plan_fp="samefin"))
    assert a == b, "同脚本指纹应判重（真死循环仍须拦截）"
    print("✓ test_no_payload_same_plan_fp_still_collapses")


def test_payload_ignores_plan_fp_backward_compatible():
    """有有效载荷时行为与修复前**完全一致**（签名不含指纹，旧三元组语义）。"""
    a = _strategy_signature(_step(obs="decode: hello", plan_fp="X"))
    b = _strategy_signature(_step(obs="decode: hello", plan_fp="Y"))
    assert a == b, "有载荷时指纹不参与判重（保持旧行为，不引入逃避空间）"
    # 且前缀截断语义保持：前 200 字符相同即视为同签名
    assert a[1] == "decode: hello"
    assert a[3] == ""   # 载荷分支第 4 元为空
    print("✓ test_payload_ignores_plan_fp_backward_compatible")


def test_rc_only_prefix_treated_as_no_payload():
    """observation 仅含 `[rc=0]` 之类前缀（无实载荷）→ 视作无载荷，用指纹区分。"""
    for rc in ("[rc=0]", "[rc=-1]", "[rc=137]   "):
        assert _RC_ONLY_RE.sub("", rc).strip() == "", f"{rc!r} 应被视作无载荷"
    a = _strategy_signature(_step(obs="[rc=0]", plan_fp="pf1"))
    b = _strategy_signature(_step(obs="[rc=0]", plan_fp="pf2"))
    assert a != b, "rc-only 前缀下不同脚本应得不同签名"
    assert a[1] == "<no-payload>"
    print("✓ test_rc_only_prefix_treated_as_no_payload")


def test_payload_with_rc_prefix_is_payload():
    """`[rc=0]` 之后有真实输出 → 是载荷，不用指纹。"""
    a = _strategy_signature(_step(obs="[rc=0]\nflag{ok}", plan_fp="p1"))
    b = _strategy_signature(_step(obs="[rc=0]\nflag{ok}", plan_fp="p2"))
    assert a == b and a[1].startswith("[rc=0]"), "rc 前缀后有输出应视为载荷"
    print("✓ test_payload_with_rc_prefix_is_payload")


# ──────────────────────────── 单元：_plan_fingerprint ────────────────────────────

def test_plan_fingerprint_stable_and_distinct():
    p1 = {"action": "script", "code": "print(1)"}
    p1b = {"code": "print(1)", "action": "script"}   # key 顺序不同 → 同指纹
    p2 = {"action": "script", "code": "print(2)"}    # 内容不同 → 不同指纹
    assert _plan_fingerprint(p1) == _plan_fingerprint(p1b), "同 plan（key 顺序无关）应同指纹"
    assert _plan_fingerprint(p1) != _plan_fingerprint(p2), "不同 code 应不同指纹"
    assert len(_plan_fingerprint(p1)) == 12
    print("✓ test_plan_fingerprint_stable_and_distinct")


# ──────────────────────────── 单元：observe_step 注入 plan_fp ────────────────────────────

def test_observe_step_populates_plan_fp_for_script():
    """真 observe_step：script 空输出步必须带上 plan_fp（供签名判重）。"""
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    ctx = SimpleNamespace(steps=[], question=SimpleNamespace())
    plan = {"action": "script", "stage": "exploit", "code": "print('x')"}
    act = {"kind": "script", "output": ""}
    step = observe_step(agent, ctx, plan, act)
    assert step.plan_fp == _plan_fingerprint(plan), "observe_step 应注入 plan 指纹"
    assert step.plan_fp != "", "plan_fp 不得为空（否则签名仍塌缩）"
    print("✓ test_observe_step_populates_plan_fp_for_script")


# ──────────────────────────── 端到端：真 observe + 每步不同脚本 ────────────────────────────

def _q(category="crypto"):
    return SimpleNamespace(
        id="tsig",
        category=category,
        difficulty="EASY",
        description="解题题面信息（模拟有数据，专测纯 LLM 循环签名判重）",
        attachments=None,
        flag_pattern=r"flag\{[^}]+\}",
    )


async def _fake_supervise(*a, **k):
    return SupervisionVerdict(action="continue")


async def _fake_presolve(*a, **k):
    return None


def test_distinct_scripts_empty_output_not_deadlooped():
    """端到端核心回归：每步写**不同**脚本、stdout 全空——修复前 5 步内被误判死循环弃题；
    修复后应无强切、无误判，可推进到预算上限（>=8 步）。

    与 test_main_agent_e2_budget.py 的区别：本用例**不 patch observe_step**，走真
    observe_step 的 plan_fp 注入路径，直接锁住本次架构根因修复的端到端效果。
    """
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)
    counter = {"i": 0}

    async def _plan(agent, ctx, attempt):
        captured["ctx"] = ctx
        i = counter["i"]
        counter["i"] += 1
        # 每步不同算法/参数 → 不同 plan → 不同指纹
        return {"action": "script", "stage": "exploit",
                "code": f"import hashlib\nprint(variant_{i}(ct))",
                "hypothesis": f"try-algo-{i}"}

    async def _act(*a, **k):
        return {"kind": "script", "output": ""}   # 脚本静默/报错 → 无 stdout

    async def _run():
        with patch("core.phases.plan_step", _plan), \
             patch("core.phases.act_step", _act), \
             patch("core.phases.supervise_step", _fake_supervise), \
             patch("core.presolve.presolve", _fake_presolve):
            return await agent.solve(_q())
    asyncio.run(_run())

    ctx = captured["ctx"]
    assert ctx.strategy_switches == 0, (
        f"不同脚本空输出是正常探索，不应强切，实得 {ctx.strategy_switches}"
    )
    assert len(ctx.steps) >= 8, (
        f"修复后应能推进多步而非 3–5 步弃题，实得 {len(ctx.steps)} 步"
    )
    print(f"✓ test_distinct_scripts_empty_output_not_deadlooped (steps={len(ctx.steps)}, switches=0)")


def test_identical_script_empty_output_still_deadlooped():
    """对称哨兵：**完全相同**的脚本（同指纹）静默重复 —— 仍须被死循环检测拦截
    （证明修复只放行正常探索，未放过真空转）。"""
    captured = {}
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=12)

    async def _plan(agent, ctx, attempt):
        captured["ctx"] = ctx
        return {"action": "script", "stage": "exploit",
                "code": "print(repeated_identical_script())", "hypothesis": "same"}

    async def _act(*a, **k):
        return {"kind": "script", "output": ""}

    async def _run():
        with patch("core.phases.plan_step", _plan), \
             patch("core.phases.act_step", _act), \
             patch("core.phases.supervise_step", _fake_supervise), \
             patch("core.presolve.presolve", _fake_presolve):
            return await agent.solve(_q())
    asyncio.run(_run())

    ctx = captured["ctx"]
    assert len(ctx.steps) < 8, (
        f"同脚本空输出重复应被死循环检测快速止损，实得 {len(ctx.steps)} 步"
    )
    print(f"✓ test_identical_script_empty_output_still_deadlooped (steps={len(ctx.steps)})")


if __name__ == "__main__":
    test_no_payload_uses_plan_fp_to_distinguish()
    test_no_payload_same_plan_fp_still_collapses()
    test_payload_ignores_plan_fp_backward_compatible()
    test_rc_only_prefix_treated_as_no_payload()
    test_payload_with_rc_prefix_is_payload()
    test_plan_fingerprint_stable_and_distinct()
    test_observe_step_populates_plan_fp_for_script()
    test_distinct_scripts_empty_output_not_deadlooped()
    test_identical_script_empty_output_still_deadlooped()
    print("=== 策略签名空输出塌缩修复测试全部通过 ===")
