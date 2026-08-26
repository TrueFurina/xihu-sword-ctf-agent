# -*- coding: utf-8 -*-
"""MainAgent E6 few-shot 方向决策范例注入测试（2026-08-25 桶B攻坚）。

验证 E6（不依赖真 LLM/工具，全 mock / 纯函数）：
1. ctx.few_shot=True 时 build_plan_prompt 注入 FEW_SHOT_BANK（方向决策范例）
2. ctx.few_shot=False（默认）时不注入——保证基线 KPI（presolve 主导）不被改动
3. MainAgent 正确读 few_shot 形参与 env CTF_AGENT_FEWSHOT（默认关）
4. solve 循环把 self.few_shot 透传进 ctx，plan 提示按开关注入
"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace

from core.main_agent import MainAgent, AgentContext
from core.prompts import build_plan_prompt, FEW_SHOT_BANK


def _q(category="crypto", description="RSA 公钥 n,e,c 求解"):
    return SimpleNamespace(
        id="t",
        title="样本题",
        category=category,
        difficulty="EASY",
        description=description,
        attachments=None,
        flag_pattern=r"flag\{[^}]+\}",
    )


def test_plan_prompt_includes_fewshot_when_enabled():
    """few_shot=True → 提示含 FEW_SHOT_BANK 方向范例（例1 RSA 费马等）。"""
    ctx = AgentContext(question=_q(), few_shot=True)
    prompt = build_plan_prompt(ctx, 0)
    assert FEW_SHOT_BANK in prompt, "few_shot=True 时 plan 提示必须注入方向决策范例"
    assert "例1(crypto·RSA)" in prompt, "范例首条应为 RSA 方向决策"
    print("✓ test_plan_prompt_includes_fewshot_when_enabled")


def test_plan_prompt_excludes_fewshot_by_default():
    """few_shot=False（默认）→ 提示不含 FEW_SHOT_BANK，基线行为不变。"""
    ctx = AgentContext(question=_q(), few_shot=False)
    prompt = build_plan_prompt(ctx, 0)
    assert FEW_SHOT_BANK not in prompt, "few_shot=False 时不应注入范例（保基线）"
    print("✓ test_plan_prompt_excludes_fewshot_by_default")


def test_main_agent_fewshot_config_precedence():
    """形参 > env > 默认关。"""
    # 默认（env 未设）→ False
    a0 = MainAgent(per_question_wallclock=300)
    assert a0.few_shot is False, "默认应关"
    # 形参显式开
    a1 = MainAgent(per_question_wallclock=300, few_shot=True)
    assert a1.few_shot is True, "形参 few_shot=True 应开"
    # env 开、形参未给 → 跟随 env
    os.environ["CTF_AGENT_FEWSHOT"] = "1"
    try:
        a2 = MainAgent(per_question_wallclock=300)
        assert a2.few_shot is True, "env CTF_AGENT_FEWSHOT=1 应开"
    finally:
        del os.environ["CTF_AGENT_FEWSHOT"]
    # 形参关 + env 开 → 形参优先
    os.environ["CTF_AGENT_FEWSHOT"] = "1"
    try:
        a3 = MainAgent(per_question_wallclock=300, few_shot=False)
        assert a3.few_shot is False, "形参 few_shot=False 应压过 env"
    finally:
        del os.environ["CTF_AGENT_FEWSHOT"]
    print("✓ test_main_agent_fewshot_config_precedence")


async def _fake_supervise(*a, **k):
    from core.main_agent import SupervisionVerdict
    return SupervisionVerdict(action="continue")


def _fake_observe(agent, ctx, plan, act):
    from core.main_agent import StepRecord
    return StepRecord(stage="recon", action="reason", observation="x", error_category=None)


def test_solve_passes_fewshot_into_ctx_prompt():
    """solve 把 self.few_shot 透传 ctx，plan 提示按开关注入范例。"""
    from unittest.mock import patch
    captured = {}

    async def _fake_presolve(*a, **k):
        return None

    async def _plan(agent, ctx, attempt):
        captured["ctx"] = ctx
        from core.prompts import build_plan_prompt
        captured["prompt"] = build_plan_prompt(ctx, attempt)
        return {"action": "reason", "hypothesis": "x"}

    async def _act(*a, **k):
        return {}

    agent = MainAgent(per_question_wallclock=300, few_shot=True)
    with patch("core.phases.plan_step", _plan), \
         patch("core.phases.act_step", _act), \
         patch("core.phases.supervise_step", _fake_supervise), \
         patch("core.phases.observe_step", _fake_observe), \
         patch("core.presolve.presolve", _fake_presolve):
        asyncio.run(agent.solve(_q()))
    assert captured["ctx"].few_shot is True, "solve 应把 self.few_shot 透传 ctx"
    assert FEW_SHOT_BANK in captured["prompt"], "few_shot 开启时 plan 提示应含范例"
    print("✓ test_solve_passes_fewshot_into_ctx_prompt")


if __name__ == "__main__":
    test_plan_prompt_includes_fewshot_when_enabled()
    test_plan_prompt_excludes_fewshot_by_default()
    test_main_agent_fewshot_config_precedence()
    asyncio.run(test_solve_passes_fewshot_into_ctx_prompt())
    print("=== main_agent E6 few-shot 测试全部通过 ===")
