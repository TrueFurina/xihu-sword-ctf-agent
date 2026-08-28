"""三态决策引擎（纯逻辑，可单测，无 LLM）。

来源：idea-stage/refine-logs/FINAL_PROPOSAL_RACE_INTELLIGENCE.md §4.2 DecisionEngine。
根据 RaceState 的态势，输出 Allocation（模型等级映射 / 并发数 / 聚焦题 / 单题预算）。
本模块只做决策计算，不触碰任何执行/网络，便于单元测试与后续接入主循环。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from core.race_state import QuestionState, RaceState


@dataclass
class Allocation:
    """一次资源分配决策的结果。"""

    model_map: dict = field(default_factory=dict)
    concurrency: int = 1
    focus: List[str] = field(default_factory=list)
    per_question_budget: float = 0.0


class DecisionEngine:
    """三态决策引擎。"""

    TIME_TIGHT = 30.0                       # 分钟
    BUDGET_TIGHT_RATIO = 0.25               # 剩余预算 < 25%
    CONFIDENCE_LOW = 0.3
    MV_THRESHOLD_PERCENTILE = 0.3           # 只做 MV 前 30% 的题

    # 题型 → 模型等级（默认映射，可被赛制覆盖）
    _HEAVY = ("crypto", "pwn", "reverse")
    _LIGHT = ("web", "misc")

    def decide(self, state: RaceState) -> Allocation:
        """主决策入口：先分类状态，再分发到对应分配策略。"""
        regime = self._classify_regime(state)
        if regime == "TIME_TIGHT":
            return self._time_tight_allocation(state)
        if regime == "BUDGET_TIGHT":
            return self._budget_tight_allocation(state)
        if regime == "BOTH_TIGHT":
            return self._emergency_allocation(state)
        return self._normal_allocation(state)

    # ── 状态分类 ──
    def _classify_regime(self, state: RaceState) -> str:
        time_tight = state.time_remaining < self.TIME_TIGHT
        budget_tight = (
            state.rpi > 1.0
            or (state.budget_remaining / max(state.budget_total, 1e-9)) < self.BUDGET_TIGHT_RATIO
        )
        if time_tight and budget_tight:
            return "BOTH_TIGHT"
        if time_tight:
            return "TIME_TIGHT"
        if budget_tight:
            return "BUDGET_TIGHT"
        return "NORMAL"

    # ── 模型等级映射 ──
    def _model_for(self, q: QuestionState) -> str:
        cat = str(q.category).lower()
        if cat in self._HEAVY:
            return "heavy"
        if cat in self._LIGHT:
            return "light"
        return "tiny"

    # ── 正常态：平衡攻难与扫易 ──
    def _normal_allocation(self, state: RaceState) -> Allocation:
        all_q = state.active_questions + state.pending_questions
        ranked = sorted(all_q, key=lambda q: q.marginal_value, reverse=True)
        concurrency = self._optimal_concurrency(state)
        model_map = {q.qid: self._model_for(q) for q in ranked}
        per_q = state.budget_remaining / max(len(ranked), 1) * 1.5 if ranked else 0.0
        return Allocation(
            model_map=model_map,
            concurrency=concurrency,
            focus=[q.qid for q in ranked[:concurrency]],
            per_question_budget=per_q,
        )

    # ── 时间紧急态：最大并发 + 只做高信心题 ──
    def _time_tight_allocation(self, state: RaceState) -> Allocation:
        viable = [q for q in state.active_questions if q.confidence > self.CONFIDENCE_LOW]
        viable += [
            q for q in state.pending_questions
            if q.marginal_value > self._mv_threshold(state)
        ]
        model_map = {q.qid: "light" for q in viable}
        return Allocation(
            model_map=model_map,
            concurrency=min(len(viable), 8),
            focus=[q.qid for q in sorted(viable, key=lambda q: q.marginal_value, reverse=True)[:8]],
            per_question_budget=state.budget_remaining / max(len(viable), 1),
        )

    # ── 预算紧急态：降级模型 + 减少并发 + 只做高 MV 题 ──
    def _budget_tight_allocation(self, state: RaceState) -> Allocation:
        all_q = state.active_questions + state.pending_questions
        ranked = sorted(all_q, key=lambda q: q.marginal_value, reverse=True)
        cutoff = max(1, int(len(ranked) * self.MV_THRESHOLD_PERCENTILE))
        focus = ranked[:cutoff]
        model_map = {q.qid: "tiny" for q in focus}
        return Allocation(
            model_map=model_map,
            concurrency=max(1, min(3, len(focus))),
            focus=[q.qid for q in focus[:3]],
            per_question_budget=state.budget_remaining / max(len(focus), 1) * 0.8,
        )

    # ── 双重紧急态：最小资源 + 最高收益题 ──
    def _emergency_allocation(self, state: RaceState) -> Allocation:
        all_q = state.active_questions + state.pending_questions
        ranked = sorted(all_q, key=lambda q: q.marginal_value, reverse=True)
        focus = ranked[:2]
        model_map = {q.qid: "tiny" for q in focus}
        return Allocation(
            model_map=model_map,
            concurrency=1,
            focus=[q.qid for q in focus],
            per_question_budget=state.budget_remaining / 2 if focus else 0.0,
        )

    # ── 最优并发（基于 RPI）──
    def _optimal_concurrency(self, state: RaceState) -> int:
        rpi = state.rpi
        if rpi < 0.3:
            return 8
        if rpi < 0.6:
            return 6
        if rpi < 0.8:
            return 4
        return 2

    def _mv_threshold(self, state: RaceState) -> float:
        all_q = state.active_questions + state.pending_questions
        mvs = sorted([q.marginal_value for q in all_q])
        idx = int(len(mvs) * self.MV_THRESHOLD_PERCENTILE)
        return mvs[idx] if mvs else 0.0
