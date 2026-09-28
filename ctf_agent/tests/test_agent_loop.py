"""G2 闭环骨架单测 · 全部 ¥0 / 零 token（mock llm + 真实/ mock Session）。

对应 `2027-prep/差异分析-SOTA对比-20260928.md` G2 项：
- planner 解析与"未接 LLM 显式报错"的诚实约束
- executor 真实命令执行（Windows 可跑 echo）
- reflect 三态（SUCCESS / FAIL_REPLAN / STUCK）
- AgentLoop 编排：一轮成功 / 重规划后成功 / 卡死停止
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

# ctf_agent 是 pytest 运行目录（cwd），core 作为顶层包可直接导入
from core.agent_loop import (
    AgentLoop, ExecutorAgent, LoopOutcome, PlannerAgent, Plan,
    Reflection, ReflectAgent, StepResult, Subtask, SubtaskKind, Verdict,
)
from core.session import Session


# ── Planner ─────────────────────────────────────────────────
def test_planner_parse_command_and_reason():
    raw = "先装工具\ncommand: echo hello\nreason: 分析密文结构\n无关说明"
    plan = PlannerAgent._parse(raw)
    assert len(plan.subtasks) == 2
    assert plan.subtasks[0].kind == SubtaskKind.COMMAND
    assert plan.subtasks[0].payload == "echo hello"
    assert plan.subtasks[1].kind == SubtaskKind.LLM_REASON
    assert plan.subtasks[1].payload == "分析密文结构"


def test_planner_requires_llm_is_honest():
    p = PlannerAgent(llm=None)
    with pytest.raises(NotImplementedError):
        p.plan("某 CTF 题", session=None)


def test_planner_uses_injected_llm():
    calls = {}

    def fake_llm(prompt):
        calls["prompt"] = prompt
        return "command: python solve.py"

    p = PlannerAgent(llm=fake_llm)
    plan = p.plan("挑战描述", session=None)
    assert p.call_count == 1
    assert plan.subtasks[0].payload == "python solve.py"
    assert "挑战描述" in calls["prompt"]


# ── Executor ────────────────────────────────────────────────
def test_executor_command_real_session(tmp_path):
    s = Session(str(tmp_path), "t")
    ex = ExecutorAgent(llm=None)
    res = ex.execute(Subtask(SubtaskKind.COMMAND, "echo hello_world"), s)
    assert res.ok is True
    assert "hello_world" in res.observation
    assert s.grep_output(r"hello_world") == "hello_world"


def test_executor_llm_reason_requires_llm():
    ex = ExecutorAgent(llm=None)
    with pytest.raises(NotImplementedError):
        ex.execute(Subtask(SubtaskKind.LLM_REASON, "推理"), session=None)


def test_executor_llm_reason_with_llm():
    ex = ExecutorAgent(llm=lambda p: "推理结论")
    res = ex.execute(Subtask(SubtaskKind.LLM_REASON, "推理"), session=None)
    assert res.ok is True
    assert res.observation == "推理结论"


# ── Reflect ─────────────────────────────────────────────────
class _FakeSession:
    def __init__(self, flag=None):
        self._flag = flag

    def grep_output(self, pattern):
        return self._flag

    def transcript(self):
        return "(mock transcript)"


def test_reflect_success_on_flag():
    r = ReflectAgent(flag_pattern=r"flag\{.*?\}").reflect(
        Plan(), _FakeSession(flag="flag{FOUND}"), [], 1, 5)
    assert r.verdict == Verdict.SUCCESS
    assert "确认" in r.reason or "命中" in r.reason


def test_reflect_fail_replan_with_feedback():
    rec_fail = StepResult(Subtask(SubtaskKind.COMMAND, "bad cmd"), None,
                          "command not found", False)
    r = ReflectAgent().reflect(Plan(), _FakeSession(flag=None),
                               [rec_fail], 1, 5)
    assert r.verdict == Verdict.FAIL_REPLAN
    assert r.feedback  # 必须有重规划反馈


def test_reflect_stuck_when_rounds_exhausted():
    rec_fail = StepResult(Subtask(SubtaskKind.COMMAND, "bad"), None,
                          "err", False)
    r = ReflectAgent().reflect(Plan(), _FakeSession(flag=None),
                               [rec_fail], 5, 5)
    assert r.verdict == Verdict.STUCK


# ── AgentLoop 编排 ──────────────────────────────────────────
def test_loop_success_first_round():
    planner = PlannerAgent(llm=lambda p: "command: echo done")
    # 让 executor 的执行结果带 flag，触发 reflect SUCCESS
    class _Ex(ExecutorAgent):
        def execute(self, st, session):
            return StepResult(st, None, "flag{WIN}", True)
    reflect = ReflectAgent()
    session = _FakeSession(flag=None)  # 注意：executor 不写真 session，靠 reflect 默认启发式
    # 这里 reflect 看不到 flag → 为让测试可控，直接 mock reflect
    reflect.reflect = lambda *a, **k: Reflection(Verdict.SUCCESS, "", "mock")

    loop = AgentLoop(planner, _Ex(), reflect, session, "挑战")
    out = loop.run(max_rounds=5)
    assert out.verdict == Verdict.SUCCESS
    assert out.rounds == 1
    assert planner.call_count == 1


def _mock_executor(result_ok: bool = True) -> MagicMock:
    ex = MagicMock(spec=ExecutorAgent)
    ex.execute.return_value = StepResult(
        Subtask(SubtaskKind.COMMAND, "x"), None, "out", result_ok)
    return ex


def test_loop_replan_then_success():
    planner = PlannerAgent(llm=lambda p: "command: retry")
    executor = _mock_executor()
    # reflect 第一轮回 FAIL_REPLAN，第二轮回 SUCCESS
    states = iter([Reflection(Verdict.FAIL_REPLAN, "反馈", "mock"),
                   Reflection(Verdict.SUCCESS, "", "mock")])
    reflect = ReflectAgent()
    reflect.reflect = lambda *a, **k: next(states)

    loop = AgentLoop(planner, executor, reflect, _FakeSession(), "挑战")
    out = loop.run(max_rounds=5)
    assert out.verdict == Verdict.SUCCESS
    assert out.rounds == 2
    assert planner.call_count == 2  # 重规划确实再次调用 planner
    assert executor.execute.call_count == 2  # 两轮各执行一次


def test_loop_stuck_stops_no_infinite():
    planner = PlannerAgent(llm=lambda p: "command: x")
    executor = _mock_executor()
    reflect = ReflectAgent()
    reflect.reflect = lambda *a, **k: Reflection(Verdict.STUCK, "", "mock")

    loop = AgentLoop(planner, executor, reflect, _FakeSession(), "挑战")
    out = loop.run(max_rounds=3)
    assert out.verdict == Verdict.STUCK
    assert out.rounds == 1  # 立即 STUCK，不浪费轮次
    assert planner.call_count == 1
