"""budget-reflection 单元测试（race-intelligence 第二层，纯规则、无 LLM）。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.budget_reflection import (  # noqa: E402
    reflect, BudgetState,
    DECISION_CONTINUE, DECISION_SWITCH, DECISION_ABANDON,
)
from core.main_agent import AgentContext, StepRecord, MainAgent  # noqa: E402


class _S:
    """最小步对象（仅 observation / error_category）。"""
    def __init__(self, obs="", err=None):
        self.observation = obs
        self.error_category = err


def _state(used, total=10):
    return BudgetState(budget_total=total, budget_used=used)


# ── 纯 reflect 决策 ──
def test_reflect_abandon_when_budget_exhausted_no_progress_low_conf():
    steps = [_S(obs="", err=None) for _ in range(9)]  # 全部无进展
    res = reflect(_state(used=9), steps, confidence=0.1)
    assert res.decision == DECISION_ABANDON
    assert res.metrics["budget_ratio"] == 0.9


def test_reflect_switch_when_half_budget_low_conf_trailing_stuck():
    # 前 2 步有进展，后 4 步连续无进展（trailing=4），过半预算，低信心
    steps = [_S(obs="found hint"), _S(obs="decoded part")] + [_S(obs="") for _ in range(4)]
    res = reflect(_state(used=6), steps, confidence=0.2)
    assert res.decision == DECISION_SWITCH
    assert res.metrics["trailing_no_progress"] == 4


def test_reflect_continue_early_high_conf():
    steps = [_S(obs="ok"), _S(obs="ok2")]
    res = reflect(_state(used=2), steps, confidence=0.7)
    assert res.decision == DECISION_CONTINUE


def test_reflect_continue_late_high_conf_progress():
    steps = [_S(obs="step") for _ in range(8)]
    res = reflect(_state(used=8), steps, confidence=0.8)
    assert res.decision == DECISION_CONTINUE


def test_reflect_default_continue_mid():
    steps = [_S(obs="x") for _ in range(5)]
    res = reflect(_state(used=5), steps, confidence=0.4)
    assert res.decision == DECISION_CONTINUE


def test_reflect_neutral_confidence_defaults_to_mid():
    steps = [_S(obs="x") for _ in range(5)]
    res = reflect(_state(used=5), steps, confidence=None)
    assert res.metrics["confidence"] == 0.5
    assert res.decision == DECISION_CONTINUE


# ── 集成：env 闸早停 ──
def _mk_ctx(n_no_progress=9, confidence=0.1):
    class Q:
        id = "t"
        difficulty = "EASY"
        category = "web"
    ctx = AgentContext(question=Q())
    for _ in range(n_no_progress):
        ctx.record(StepRecord(stage="recon", observation="", error_category=None))
    ctx.last_confidence = confidence
    return ctx


def test_abandon_env_on_triggers():
    os.environ["CTF_AGENT_BUDGET_REFLECTION"] = "1"
    try:
        a = MainAgent.__new__(MainAgent)
        a.llm_call_budget = 10
        ctx = _mk_ctx(9, 0.1)
        assert a._budget_reflection_should_abandon(ctx) is True
    finally:
        os.environ.pop("CTF_AGENT_BUDGET_REFLECTION", None)


def test_abandon_env_off_no_trigger():
    os.environ["CTF_AGENT_BUDGET_REFLECTION"] = "0"
    a = MainAgent.__new__(MainAgent)
    a.llm_call_budget = 10
    ctx = _mk_ctx(9, 0.1)
    assert a._budget_reflection_should_abandon(ctx) is False


def test_no_abandon_when_last_step_has_progress():
    os.environ["CTF_AGENT_BUDGET_REFLECTION"] = "1"
    try:
        a = MainAgent.__new__(MainAgent)
        a.llm_call_budget = 10
        ctx = _mk_ctx(9, 0.1)
        ctx.steps[-1] = StepRecord(stage="recon", observation="found flag候选", error_category=None)
        assert a._budget_reflection_should_abandon(ctx) is False
    finally:
        os.environ.pop("CTF_AGENT_BUDGET_REFLECTION", None)
