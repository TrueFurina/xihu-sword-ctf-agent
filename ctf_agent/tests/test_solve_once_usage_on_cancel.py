# -*- coding: utf-8 -*-
"""solve_once 记账诚实性回归（2026-10-06）。

背景（真实事故）：glm 跑批里有 3 道题 `error=wallclock_timeout`、`duration≈180s`，
但报告 `per_question token = 0`。根因不是"没调 LLM"，而是 `run.py` 的 token 记账
原在 `try/finally` **之外** —— 被评测层墙钟 `asyncio.wait_for(...)` 取消
（CancelledError）时，该行根本执行不到 → 报告恒记 0 token，误导"钱/配额够不够"。

本用例证明：**被取消的求解同样入账**。

变异敏感性：若把记账移回 `try` 之外、或去掉 `finally` 里的记账调用，
本用例必红（`usage == 0`）。
"""
import asyncio
from types import SimpleNamespace

import core.main_agent as ma

from run import build_solver


class _SlowAgent:
    """假主 Agent：先写入一次"已发生 LLM 调用"的累计，再长睡以触发外层取消。"""

    def __init__(self, *a, **k):
        pass

    async def solve(self, question, attempt=0, hint=None, correction=None):
        # 无需注入 usage：total_tokens 保持 0 时，记账走兜底 est=200，同样 > 0，
        # 足以区分"取消路径是否入账"。若要验真实 usage 路径，另见预算测试。
        await asyncio.sleep(10)          # 交由外层 wait_for 取消
        return {"task_id": question.id, "flag": None, "error": None,
                "duration_ms": 0, "retries": attempt}


def test_usage_recorded_when_solver_cancelled(monkeypatch):
    monkeypatch.setattr(ma, "MainAgent", _SlowAgent)
    # use_mock=False 才走真实链路（solve_once→agent.solve）；mock 分支是另一条捷径，
    # 碰不到本用例要验的记账路径。假 MainAgent 已挡掉真实 LLM 调用，故仍 ¥0。
    solver = build_solver(use_mock=False, skip_presolve=True)
    q = SimpleNamespace(id="t_cancel", category="crypto",
                        to_prompt_text=lambda: "dummy")

    async def _run():
        try:
            await asyncio.wait_for(solver(q, 0), timeout=0.3)
        except asyncio.TimeoutError:
            return "timeout"
        return "returned"

    outcome = asyncio.run(_run())
    assert outcome == "timeout", f"前置条件未成立：求解未按预期被取消（{outcome}）"

    used = solver.budget.usage(q.id)
    assert used > 0, (
        "被取消的题未入账（usage=0）—— token 记账又回到 try 之外了？"
        "报告会恒记 0 token，误导「钱够不够」判断（回归！）"
    )
