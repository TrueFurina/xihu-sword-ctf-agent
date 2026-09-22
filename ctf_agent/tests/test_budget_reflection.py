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


def test_no_abandon_when_candidate_flag_present():
    """2026-09-23 语义修正（本用例原为 test_no_abandon_when_last_step_has_progress）。

    原用例把最后一步 observation 设成文本「found flag候选」就断言不早停——
    但 ctx.candidate_flag 仍是 None。那正是本 bug 的源头：**文本像进展 ≠ 有进展**。
    真实链路里 agent 每步 observation 都非空（一直在读附件/打印），于是
    no_progress_recent 恒为 False，ABANDON 成了不可达死代码。
    现改为「真的持有候选 flag 才不早停」，与 _made_progress 的代理语义解耦。
    """
    os.environ["CTF_AGENT_BUDGET_REFLECTION"] = "1"
    try:
        a = MainAgent.__new__(MainAgent)
        a.llm_call_budget = 10
        ctx = _mk_ctx(9, 0.1)
        ctx.candidate_flag = "flag{real_candidate}"
        assert a._budget_reflection_should_abandon(ctx) is False
    finally:
        os.environ.pop("CTF_AGENT_BUDGET_REFLECTION", None)


# ── 2026-09-23 修复回归：真实链路（observation 恒非空）下 ABANDON 必须可达 ──
# 实证来源：held-out 17 池 / deepseek / 2026-09-22 跑批——
# 3 题各烧 19-22 万 token、候选全程 False、15/15 次反思全 CONTINUE，
# 最终全部 budget_exceeded。根因就是下面的场景在修复前判不出 ABANDON。
def _mk_ctx_realistic(n=6, confidence=0.75):
    """复刻真实链路形态：每步都有非空 observation，但全程零候选 flag。"""
    class Q:
        id = "t"
        difficulty = "EASY"
        category = "crypto"
    ctx = AgentContext(question=Q())
    for i in range(n):
        ctx.record(StepRecord(stage="recon", action="script",
                              observation=f"读取附件第{i}段，输出如下：....",
                              error_category=None))
    ctx.last_confidence = confidence
    return ctx


def test_reflect_abandon_zero_candidate_with_realistic_observations():
    """修复前：observation 非空 → no_progress_recent=False → 恒 CONTINUE（死代码）。
    修复后：候选口径命中 → ABANDON。"""
    steps = [_S(obs=f"读取附件第{i}段") for i in range(6)]
    res = reflect(BudgetState(budget_total=10, budget_used=6, candidates_found=0),
                  steps, confidence=0.75)
    assert res.decision == DECISION_ABANDON
    assert res.metrics["candidates_found"] == 0


def test_reflect_continue_when_candidate_found():
    """有候选 flag 时不得早停（防修复误杀正常收敛路径）。"""
    steps = [_S(obs=f"evidence {i}") for i in range(6)]
    res = reflect(BudgetState(budget_total=10, budget_used=6, candidates_found=1),
                  steps, confidence=0.75)
    assert res.decision == DECISION_CONTINUE


def test_reflect_abandon_rule_skipped_when_candidates_unknown():
    """candidates_found=None（老调用方）→ 零候选规则不参与，判据与修复前一致。"""
    steps = [_S(obs=f"evidence {i}") for i in range(8)]
    res = reflect(_state(used=8), steps, confidence=0.8)
    assert res.decision == DECISION_CONTINUE
    assert res.metrics["candidates_found"] is None


def test_abandon_gate_fires_on_realistic_zero_candidate():
    """端到端：env 闸开启 + 真实形态 ctx → 早停闸门必须为 True（修复前恒 False）。"""
    os.environ["CTF_AGENT_BUDGET_REFLECTION"] = "1"
    try:
        a = MainAgent.__new__(MainAgent)
        a.llm_call_budget = 10
        ctx = _mk_ctx_realistic(6, 0.75)
        assert ctx.candidate_flag is None
        assert a._budget_reflection_should_abandon(ctx) is True
    finally:
        os.environ.pop("CTF_AGENT_BUDGET_REFLECTION", None)
