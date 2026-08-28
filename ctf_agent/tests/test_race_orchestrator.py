"""race_orchestrator.RaceController 单元测试（接入 eval.benchmark，纯规则、零 LLM）。

覆盖：
  - plan()           构造 RaceState 并经 DecisionEngine 产出 Allocation
  - reflect_on_attempt() 预算反思早停：flag 解出→CONTINUE；预算将尽+无进展+低信心→ABANDON
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.race_orchestrator import RaceController  # noqa: E402


class _Q:
    def __init__(self, qid, category="misc"):
        self.id = qid
        self.category = category


def test_plan_returns_allocation():
    ctrl = RaceController()
    alloc = ctrl.plan([_Q("q1", "crypto"), _Q("q2", "web")])
    assert alloc.concurrency >= 1
    assert 0.0 <= alloc.per_question_budget <= 1.0
    assert isinstance(alloc.focus, list)


def test_reflect_continue_when_solved():
    ctrl = RaceController()
    out = {"flag": "flag{abc}", "solved_by": "main_agent_llm"}
    # flag 命中时 benchmark 循环已在 reflect 前 break；这里验证控制器对"已解出"判 CONTINUE
    decision = ctrl.reflect_on_attempt("q1", out, attempt_index=0, max_attempts=3)
    assert decision == "CONTINUE"


def test_reflect_abandon_when_budget_exhausted_no_progress_low_conf():
    ctrl = RaceController()
    # 最后一次 attempt、错误方向、无进展 → ratio=1.0 + conf=0.2 → ABANDON
    out = {"error": {"category": "wrong_direction", "detail": "走错路"}}
    decision = ctrl.reflect_on_attempt("q1", out, attempt_index=2, max_attempts=3)
    assert decision == "ABANDON"


def test_reflect_continue_on_early_attempt_with_timeout():
    ctrl = RaceController()
    # 早期 attempt、墙钟超时（conf=0.5，不满足 ABANDON 的 conf<0.4）→ CONTINUE
    out = {"error": {"category": "wallclock_timeout", "detail": "超 150s"}}
    decision = ctrl.reflect_on_attempt("q1", out, attempt_index=0, max_attempts=3)
    assert decision == "CONTINUE"
