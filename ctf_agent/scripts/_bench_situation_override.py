"""态势接管闸门（CTF_AGENT_SITUATION_OVERRIDE）行为级验证 harness。

背景
----
上一轮落地了 race-intelligence 的「态势接管闸门」：单题信心过低(<0.3)且已过半
LLM 预算时，提前触发既有 _supervise 监督换策略。但代码库此前**并没有**任何
"主 Agent 空转占比"计算入口——那是一条比喻性说法。本脚本用**确定性、零 LLM、
可复现**的方式，真正驱动真实的 MainAgent.solve 控制流，验证该闸门。

重要设计事实（诚实披露）
----------------------
solve 循环里**本就有**「每 2 步常规监督咨询」(main_agent.py L644:
`if (step_index+1)%2==0: await self._supervise(...)`)，且默认监督兜底
(`supervise_step`) 在 stuck_count<2 时只返回 CONTINUE（不干预）。因此 override
闸门的**边际贡献**不是"首次引入监督"，而是：

  当信心过低(<0.3) + 已过半预算时，把"本会被常规监督 CONTINUE 放过"的状态
  **强制推成一次纠正性 SWITCH/换策略**，避免低信心题空转到预算耗尽。

本 harness 的 mock 监督据此实现：仅当检测到 override 触发条件（低信心+过半预算）
才返回 SWITCH，否则返回 CONTINUE（模拟默认监督兜底行为）。从而干净隔离 override
的真实贡献：
  - 关闭（默认）：常规咨询全 CONTINUE → 不换策略 → 振荡低信心题空转到预算耗尽 → 失败。
  - 开启（OVERRIDE=1）：过半预算+低信心时强制 SWITCH → 提前解出，空转步数显著减少。

注意：本 harness 是**控制流级**确定性验证（mock LLM 行为受脚本控制），并非
真实 LLM 跑真题的端到端 benchmark（后者需 API 预算，属下一步验证）。

用法
----
    .venv/Scripts/python.exe scripts/_bench_situation_override.py        # 打印 A/B 报表
    .venv/Scripts/python.exe -m pytest tests/test_situation_override_behavior.py -q
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.main_agent import (  # noqa: E402
    MainAgent,
    AgentContext,
    StepRecord,
    STAGE_RECON,
    VERDICT_SWITCH,
    SupervisionVerdict,
)


class _BenchQuestion:
    """极简 mock 题（EASY crypto，不触发重型升级/网络）。"""

    id = "bench_override"
    title = "bench override"
    category = "crypto"
    description = "bench"
    difficulty = "EASY"
    flag_pattern = r"flag\{[^}]+\}"
    attachments = []


def _build_agent(llm_call_budget: int = 10):
    """构造 MainAgent 并注入确定性 mock。

    模拟场景：前若干步每步换不同动作（reason/tool_a/tool_b/tool_c 轮换），
    既不报错（stuck_count 不累积）也无进展（信心保持低）→ 旧 stuck_count>=2
    逻辑与默认监督兜底都不会干预。一旦监督被推成 SWITCH（仅 override 条件成立时），
    立即切换策略并在下一步产出 flag。
    """
    agent = MainAgent(llm_client=None, llm_call_budget=llm_call_budget)
    agent.max_retries = 4  # _max_steps = min(4*3, budget) = min(12,10) = 10

    # 顶部 presolve 是确定性入口，用 async mock 跳过（避免真实文件分析副作用）
    import core.presolve as _cp

    async def _fake_presolve(*a, **k):
        return None

    _cp.presolve = _fake_presolve

    state = {
        "supervisor_calls": 0,
        "corrective_calls": 0,
        "first_corrective_step": None,
        "switched": False,
    }

    _actions = ["reason", "tool_a", "tool_b", "tool_c"]

    async def _fake_plan(ctx, attempt):
        i = len(ctx.steps) % len(_actions)
        return {"action": _actions[i], "tool": None,
                "observation": f"trying {_actions[i]}"}

    async def _fake_act(ctx, plan, attempt):
        return {"output": "no flag yet",
                "observation": f"no progress {len(ctx.steps)}"}

    def _fake_observe(ctx, plan, act):
        if state["switched"]:
            # 监督换策略后，下一步直接产出 flag（控制流级"解出"）
            ctx.candidate_flag = "BENCH_OVERRIDE_SOLVED"
            return StepRecord(stage=STAGE_RECON, action="tool_a",
                              observation="found BENCH_OVERRIDE_SOLVED")
        return StepRecord(stage=STAGE_RECON, action=plan.get("action", ""),
                          observation=f"no progress {len(ctx.steps) + 1}",
                          error_category=None)

    async def _fake_supervise(ctx):
        state["supervisor_calls"] += 1
        # 语义精确隔离：仅当 override 真正触发（_situation_override_triggered
        # 返回 True，已在下方包一层打标 ctx._override_fired）时，才把监督推成
        # 纠正性 SWITCH；否则模拟默认监督兜底 CONTINUE（不干预）。
        # 这样常规每2步监督咨询在 OFF 模式全为 CONTINUE，不与 override 混淆。
        if getattr(ctx, "_override_fired", False) and not state["switched"]:
            state["corrective_calls"] += 1
            if state["first_corrective_step"] is None:
                state["first_corrective_step"] = len(ctx.steps)
            state["switched"] = True
            ctx._override_fired = False  # 消费后复位，避免后续偶数步重复计数
            return SupervisionVerdict(action=VERDICT_SWITCH,
                                     suggestion="换切入点：直接对密文做数理变换")
        return SupervisionVerdict(action="continue")

    def _fake_log_situation(ctx):
        # 模拟"振荡无进展→低信心"：每步固定 0.1（<0.3 阈值）
        ctx.last_confidence = 0.1

    # 包一层 _situation_override_triggered：仅在它真正返回 True 时给 ctx 打标，
    # 使 mock 监督能精确区分"被 override 触发"与"被常规节奏触发"。
    _orig_override = agent._situation_override_triggered

    def _override_tagged(ctx):
        fired = _orig_override(ctx)
        if fired:
            ctx._override_fired = True
        return fired

    agent._plan = _fake_plan
    agent._act = _fake_act
    agent._observe = _fake_observe
    agent._supervise = _fake_supervise
    agent._log_situation = _fake_log_situation
    agent._situation_override_triggered = _override_tagged
    return agent, state


async def run_scenario(override_on: bool, llm_call_budget: int = 10) -> dict:
    """跑一个场景，返回可比较的指标字典。"""
    os.environ["CTF_AGENT_SITUATION_OVERRIDE"] = "1" if override_on else "0"
    agent, state = _build_agent(llm_call_budget)
    result = await agent.solve(_BenchQuestion())
    return {
        "override_on": override_on,
        "solved": result.get("flag") is not None,
        "flag": result.get("flag"),
        "total_steps": len(result.get("steps", [])),
        "llm_calls": result.get("llm_calls"),
        "supervisor_calls": state["supervisor_calls"],
        "corrective_calls": state["corrective_calls"],
        "first_corrective_step": state["first_corrective_step"],
        "budget": llm_call_budget,
        "idle_steps": (state["first_corrective_step"]
                       if state["first_corrective_step"] is not None
                       else len(result.get("steps", []))),
    }


def _assertions(on: dict, off: dict) -> list[str]:
    """返回违规消息列表（空=全部通过）。"""
    problems = []
    if not on["solved"]:
        problems.append("OVERRIDE=ON 本应解出，却未解")
    if off["solved"]:
        problems.append("OVERRIDE=OFF 本应失败（空转到预算耗尽），却解出")
    if on["corrective_calls"] < 1:
        problems.append("OVERRIDE=ON 未产生纠正性 SWITCH")
    if off["corrective_calls"] != 0:
        problems.append("OVERRIDE=OFF 不应产生纠正性 SWITCH（常规咨询均 CONTINUE）")
    if on["first_corrective_step"] is None:
        problems.append("OVERRIDE=ON 未记录首次纠正步")
    elif on["first_corrective_step"] > on["budget"] // 2:
        problems.append(
            f"OVERRIDE=ON 纠正触发过晚（步 {on['first_corrective_step']} "
            f"> 预算半 {on['budget'] // 2}）")
    if not (on["total_steps"] < off["total_steps"]):
        problems.append(
            f"OVERRIDE=ON 总步数应少于 OFF（{on['total_steps']} vs {off['total_steps']}）")
    if not (on["idle_steps"] < off["idle_steps"]):
        problems.append(
            f"OVERRIDE=ON 空转步数应少于 OFF（{on['idle_steps']} vs {off['idle_steps']}）")
    return problems


async def main() -> int:
    on = await run_scenario(True)
    off = await run_scenario(False)
    problems = _assertions(on, off)

    print("=" * 70)
    print("态势接管闸门 行为级 A/B 验证（确定性 mock，零 LLM）")
    print("=" * 70)
    for label, r in (("OFF（默认关）", off), ("ON （OVERRIDE=1）", on)):
        print(f"\n── {label} ──")
        print(f"  解出: {r['solved']}  flag={r['flag']}")
        print(f"  总步数: {r['total_steps']}   LLM调用: {r['llm_calls']}")
        print(f"  监督咨询总次数: {r['supervisor_calls']}"
              f"   纠正性SWITCH: {r['corrective_calls']}")
        print(f"  首次纠正步: {r['first_corrective_step']}")
        print(f"  空转步数(到首次纠正/预算耗尽): {r['idle_steps']}")
    print("\n" + "=" * 70)
    if problems:
        print("❌ 断言失败:")
        for p in problems:
            print(f"  - {p}")
        print("=" * 70)
        return 1
    print("✅ 全部断言通过：OVERRIDE=ON 在过半预算+低信心时把常规 CONTINUE 监督"
          "强制推成纠正性 SWITCH，将『空转到预算耗尽失败』转为『提前换策略解出』，"
          f"空转步数 {off['idle_steps']}→{on['idle_steps']}。")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
