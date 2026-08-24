# -*- coding: utf-8 -*-
"""P1 收敛回归（2026-08-21 赛后）：race 第 0 号选手改走 presolve 去重。

背景（QA 报告第 2 条）：run.py race() 第 0 号选手直调 MathEngineMatrix.solve，
绕过 core.presolve 的 per-question 去重标记 → race 模式下 math_engine 被嗅探
2 次（0 号一次 + 首个 provider solver 的 presolve 一次）。

覆盖：
1. race() 第 0 号选手调用 presolve（不再直调 MathEngineMatrix.solve）
2. presolve 同一附件只嗅探一次：第二次调用 math_engine 不再执行
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MissRegistry:
    """flag_scan/crypto_auto 都未命中的假注册表（逼 math_engine 执行）。"""

    def has(self, name):
        return name in ("flag_scan", "crypto_auto")

    async def run(self, name, params):
        out = type("Out", (), {"ok": False, "text": ""})()
        return out


def _question(attachments=("a.txt",), category="crypto", description=""):
    class Q:
        id = "race_q1"
        title = "t"
    q = Q()
    q.category = category
    q.description = description
    q.attachments = list(attachments)
    q.difficulty = "easy"
    q.flag_pattern = r"flag\{[^}]+\}"
    q.extra = {}
    return q


def test_race_zero_uses_presolve_not_direct_math_engine(monkeypatch):
    """race 第 0 号选手改走 presolve：不再直调 MathEngineMatrix.solve。"""
    import run
    import core.presolve as presolve_mod
    import agents.math_engine as math_mod

    presolve_calls = []
    math_calls = []

    async def fake_presolve(question, registry=None, sandbox=None, answers=None, force=False):
        presolve_calls.append(str(getattr(question, "id", "?")))
        return None

    def fake_math_solve(question, timeout=60):
        math_calls.append(str(getattr(question, "id", "?")))
        return (None, None)

    monkeypatch.setattr(presolve_mod, "presolve", fake_presolve)
    monkeypatch.setattr(math_mod.MathEngineMatrix, "solve", staticmethod(fake_math_solve))

    def fake_build_solver(use_mock, is_correct=None, provider=None,
                          model_override=None, validate_locally=True):
        async def solver(question, attempt, correction=None):
            return {"task_id": str(getattr(question, "id", "")), "flag": None,
                    "error": {"category": "no_solution", "detail": "fake"}}
        solver.budget = None
        return solver

    monkeypatch.setattr(run, "build_solver", fake_build_solver)

    race = run.build_race_solver(use_mock=False, providers=("baidu", "moonshot"),
                                 models=(), tokenhub_models=(), extra_models=())
    q = _question(attachments=["x.txt"], category="crypto")
    out = asyncio.run(race(q, 0, None))
    assert out is not None
    # 第 0 号选手走 presolve（≥1 次）；不再直调 MathEngineMatrix.solve（0 次）
    assert len(presolve_calls) >= 1
    assert len(math_calls) == 0


def test_presolve_math_engine_sniffed_once(monkeypatch):
    """presolve 去重：同一 question 第二次调用时 math_engine 不再执行。"""
    from core.presolve import presolve
    import agents.math_engine as math_mod

    math_calls = []

    def fake_math_solve(question, timeout=60):
        math_calls.append(str(getattr(question, "id", "?")))
        return (None, None)

    monkeypatch.setattr(math_mod.MathEngineMatrix, "solve", staticmethod(fake_math_solve))

    registry = MissRegistry()
    q = _question(attachments=["a.txt"], category="crypto")

    async def main():
        await presolve(q, registry=registry, answers=None)   # 第一次：math_engine 跑 1 次，打标记
        await presolve(q, registry=registry, answers=None)   # 第二次：标记 → 跳过
        return

    asyncio.run(main())
    assert len(math_calls) == 1
