"""race_intelligence 纯规则核心单元测试。

覆盖：classify_step / ConfidenceEstimator / MarginalValueEstimator /
RaceState.rpi / DecisionEngine 三态决策。零 LLM、零外部依赖。
"""
import math
import sys
from pathlib import Path

import pytest

# 让 `core` 可被 import（测试在 ctf_agent/ 下运行）
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.confidence import ConfidenceEstimator, classify_step, should_early_switch  # noqa: E402
from core.marginal_value import MarginalValueEstimator  # noqa: E402
from core.race_state import QuestionState, RaceState  # noqa: E402
from core.decision_engine import Allocation, DecisionEngine  # noqa: E402
from core.main_agent import AgentContext  # noqa: E402


# ── classify_step ──
def test_classify_step_error_mapping():
    assert classify_step("", "hallucination") == "hallucination"
    assert classify_step("", "tool_failure") == "stuck_loop"
    assert classify_step("", "ERR_STUCK_LOOP") == "stuck_loop"


def test_classify_step_clue_detection():
    assert classify_step("found https://example.com/api") == "continue"
    assert classify_step("register 0x401000 loaded") == "continue"
    assert classify_step("key=abcdef1234567890") == "continue"
    assert classify_step("no new info, same as before") == "stuck_loop"


# ── ConfidenceEstimator ──
def test_confidence_high_when_clues_present():
    est = ConfidenceEstimator()
    hist = ["found https://x", "key=abc", "0x401000", "func()", "done"]
    err = ["continue"] * 5
    c = est.estimate(hist, err, 0.1)
    assert c > 0.7, f"expected high confidence, got {c}"


def test_confidence_low_on_stuck_loop():
    est = ConfidenceEstimator()
    hist = ["nothing", "same", "no progress", "again", "stuck"]
    err = ["stuck_loop"] * 5
    c = est.estimate(hist, err, 0.9)
    assert c < 0.3, f"expected low confidence, got {c}"


def test_confidence_difficulty_decay():
    est = ConfidenceEstimator()
    # 相同 H/P，仅 budget_ratio 不同：消耗越多信心越低
    hist = ["key=abc"] * 5
    err = ["continue"] * 5
    low = est.estimate(hist, err, 0.0)
    high = est.estimate(hist, err, 1.0)
    assert low > high, f"budget_ratio 应使信心衰减: {low} vs {high}"
    # 边界 clamp
    assert 0.0 <= low <= 1.0 and 0.0 <= high <= 1.0


def test_confidence_empty_history_neutral():
    est = ConfidenceEstimator()
    # 无历史时 H/P 中性(0.5)，D 随 budget_ratio 衰减；整体应落在中性区间
    c = est.estimate([], [], 0.5)
    assert 0.4 <= c <= 0.6, f"无历史应中性，got {c}"
    assert 0.0 <= c <= 1.0


# ── MarginalValueEstimator ──
def test_marginal_value_unexplored_is_inf():
    mv = MarginalValueEstimator()
    # 从未拉臂 → +inf（优先探索）
    assert mv.estimate("q1", 100, 0.5, 10.0, 0.0) == float("inf")


def test_marginal_value_exploit_monotonic():
    mv = MarginalValueEstimator()
    mv.record_pull("q1")
    mv.record_pull("q1")
    # 高信心、低耗时 → 更高收益
    hi = mv.estimate("q1", 100, 0.9, 5.0, 1.0)
    lo = mv.estimate("q1", 100, 0.2, 5.0, 1.0)
    assert hi > lo, f"高信心应更高 MV: {hi} vs {lo}"
    assert math.isfinite(hi) and math.isfinite(lo)


def test_marginal_value_exploration_decreases():
    mv = MarginalValueEstimator()
    mv.record_pull("q1")
    first = mv.estimate("q1", 100, 0.5, 10.0, 1.0)   # n_i=1, 探索项大
    mv.record_pull("q1")
    second = mv.estimate("q1", 100, 0.5, 10.0, 1.0)  # n_i=2, 探索项变小
    assert second < first, f"探索项应随拉臂增多下降: {first} vs {second}"


# ── RaceState.rpi ──
def test_race_state_rpi():
    s = RaceState(time_remaining=30, budget_remaining=0.2, budget_rate=0.01)
    # rpi = 0.01 * 30 / 0.2 = 1.5 > 1 → 预算将耗尽
    assert s.rpi == pytest.approx(1.5)
    s2 = RaceState(time_remaining=180, budget_remaining=0.9, budget_rate=0.001)
    assert s2.rpi < 1.0


# ── DecisionEngine ──
def _q(qid, cat="misc", conf=0.8, mv=1.0):
    return QuestionState(qid=qid, category=cat, confidence=conf, marginal_value=mv)


def test_decision_normal_regime():
    eng = DecisionEngine()
    s = RaceState(
        time_remaining=180, budget_remaining=0.9, budget_rate=0.001,
        active_questions=[_q("a", "crypto"), _q("b", "web")],
        pending_questions=[_q("c", "reverse")],
    )
    alloc = eng.decide(s)
    assert isinstance(alloc, Allocation)
    assert alloc.model_map["a"] == "heavy"
    assert alloc.model_map["b"] == "light"
    assert alloc.concurrency >= 2


def test_decision_time_tight():
    eng = DecisionEngine()
    # 时间紧迫但预算充裕 → TIME_TIGHT；低信心题被剔除
    s = RaceState(
        time_remaining=20, budget_remaining=0.9, budget_rate=0.001,
        active_questions=[_q("low", "web", conf=0.1), _q("hi", "crypto", conf=0.9)],
    )
    alloc = eng.decide(s)
    assert "low" not in alloc.focus
    assert "hi" in alloc.focus


def test_decision_budget_tight():
    eng = DecisionEngine()
    # 预算紧迫 → BUDGET_TIGHT；全部降级 tiny，聚焦高 MV
    s = RaceState(
        time_remaining=180, budget_remaining=0.1, budget_rate=0.05,
        active_questions=[_q("x", "crypto", conf=0.9, mv=5.0), _q("y", "web", conf=0.9, mv=1.0)],
    )
    alloc = eng.decide(s)
    assert all(m == "tiny" for m in alloc.model_map.values())
    assert alloc.focus[0] == "x"  # 高 MV 优先


def test_decision_both_tight():
    eng = DecisionEngine()
    s = RaceState(
        time_remaining=10, budget_remaining=0.05, budget_rate=0.1,
        active_questions=[_q("x", "crypto", conf=0.9, mv=5.0), _q("y", "web", conf=0.9, mv=1.0)],
    )
    alloc = eng.decide(s)
    assert alloc.concurrency == 1  # 单线程集中火力
    assert alloc.focus[0] == "x"


def test_decision_regime_classification():
    eng = DecisionEngine()
    assert eng._classify_regime(
        RaceState(time_remaining=180, budget_remaining=0.9, budget_rate=0.001)
    ) == "NORMAL"
    assert eng._classify_regime(
        RaceState(time_remaining=10, budget_remaining=0.9, budget_rate=0.001)
    ) == "TIME_TIGHT"
    assert eng._classify_regime(
        RaceState(time_remaining=180, budget_remaining=0.1, budget_rate=0.2)
    ) == "BUDGET_TIGHT"
    assert eng._classify_regime(
        RaceState(time_remaining=10, budget_remaining=0.1, budget_rate=0.2)
    ) == "BOTH_TIGHT"


# ── should_early_switch（态势接管闸门，默认关）──
def test_should_early_switch_default_off():
    # override=False → 永不接管
    assert should_early_switch(0.1, 10, 12, override=False) is False
    assert should_early_switch(None, 10, 12, override=False) is False


def test_should_early_switch_triggers():
    # override 开 + 低信心 + 过半预算 → 接管
    assert should_early_switch(0.2, 7, 12, override=True) is True


def test_should_early_switch_no_trigger_high_conf():
    assert should_early_switch(0.9, 12, 12, override=True) is False


def test_should_early_switch_no_trigger_below_half_budget():
    # 预算未过半（6 < 0.5*12=6? 等于边界，用 5 明确低于）
    assert should_early_switch(0.1, 5, 12, override=True) is False


def test_situation_override_method_respects_env(monkeypatch):
    import os
    from core import main_agent as M

    # 默认无 env → 不接管
    monkeypatch.delenv("CTF_AGENT_SITUATION_OVERRIDE", raising=False)
    agent = M.MainAgent.__new__(M.MainAgent)
    ctx = AgentContext()
    ctx.last_confidence = 0.1
    ctx.llm_calls = 10
    agent.llm_call_budget = 12
    assert agent._situation_override_triggered(ctx) is False

    # 开启 env + 低信心过半 → 接管
    monkeypatch.setenv("CTF_AGENT_SITUATION_OVERRIDE", "1")
    assert agent._situation_override_triggered(ctx) is True


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
