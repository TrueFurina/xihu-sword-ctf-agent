"""Race-intelligence 编排适配器（接入 eval.benchmark 评测主循环，2026-08-28）。

把已有的纯逻辑模块（RaceState / DecisionEngine / budget_reflection）拼装成
benchmark 运行循环可直接调用的控制器：
  - plan(questions)          → DecisionEngine.decide → Allocation（并发 / 单题预算 / 聚焦题）
  - reflect_on_attempt(...)  → budget_reflection.reflect → CONTINUE / SWITCH / ABANDON

设计约束（与反注水法令同源：零 LLM、零外部依赖、可单测、可审计）：
- 默认关闭（eval.benchmark --race-intelligence），开启后只在每题 attempt 边界做
  早停决策，**不改变默认 15 题跑批的语义**（attempts 少时 reflect 不触发 ABANDON，
  零回归风险；仅在重试预算较大且持续无进展低信心时早停，避免空烧整段预算）。
- 所有决策走确定性规则，不调用任何 LLM / 网络。
"""
from __future__ import annotations

from typing import Any, List, Optional

from core.race_state import QuestionState, RaceState
from core.decision_engine import Allocation, DecisionEngine
from core.budget_reflection import reflect, BudgetState


class _Step:
    """最小步对象，满足 budget_reflection.reflect 的 .observation/.error_category 契约。

    benchmark 运行循环只产出最终 output dict（flag 或 error），没有逐 step 历史；
    这里把单次 attempt 的结果压缩成一个伪 step 供 reflect 决策。
    """

    __slots__ = ("observation", "error_category")

    def __init__(self, observation: str, error_category: Optional[str]):
        self.observation = observation
        self.error_category = error_category


class RaceController:
    """benchmark 评测主循环的 race-intelligence 控制器。"""

    def __init__(
        self,
        time_budget_min: float = 180.0,
        budget_total: float = 1.0,
        confidence_floor: float = 0.4,
    ):
        self._engine = DecisionEngine()
        self.time_budget_min = time_budget_min
        self.budget_total = budget_total
        self.confidence_floor = confidence_floor

    def plan(self, questions: List[Any]) -> Allocation:
        """基于题目清单构造 RaceState，经 DecisionEngine 输出资源分配方案。"""
        state = RaceState(
            time_remaining=self.time_budget_min,
            budget_remaining=self.budget_total,
            budget_total=self.budget_total,
            total_count=len(questions),
            solved_count=0,
        )
        for q in questions:
            qs = QuestionState(
                qid=getattr(q, "id", ""),
                category=getattr(q, "category", "misc"),
            )
            state.question_states[qs.qid] = qs
            state.pending_questions.append(qs)
        return self._engine.decide(state)

    @staticmethod
    def _confidence_from_output(output: Optional[dict]) -> float:
        """从单次 attempt 结果启发式估计信心（不调用 LLM）。"""
        if not output:
            return 0.5
        if output.get("flag"):
            return 0.9
        err = output.get("error") or {}
        cat = err.get("category")
        if cat in ("wrong_direction", "stuck_loop", "solver_exception"):
            return 0.2
        return 0.5

    def reflect_on_attempt(
        self,
        qid: str,
        output: Optional[dict],
        attempt_index: int,
        max_attempts: int,
    ) -> str:
        """对单题一次 attempt 的结果做预算反思，返回决策字符串。

        Args:
            qid: 题块 ID（仅用于日志/可追溯，当前实现未强依赖）。
            output: solver 本次返回 dict（含 flag 或 error）。
            attempt_index: 当前 attempt 序号（0-based）。
            max_attempts: 该轮最大重试次数（用作 budget_total 归一）。
        """
        total = max(int(max_attempts), 1)
        used = min(int(attempt_index) + 1, total)
        conf = self._confidence_from_output(output)
        err = (output or {}).get("error") or {}
        obs = (output or {}).get("flag") or err.get("detail", "")
        step = _Step(obs or "", err.get("category"))
        state = BudgetState(budget_total=total, budget_used=used)
        result = reflect(state, [step], confidence=conf)
        # 沉溺保护升级（2026-08-29 换题决策完整化）：信心低于阈值且已重试 ≥1 次
        # → SWITCH（换题），不再等墙钟/死循环才放弃——赛智「信心低于阈值换题」落地。
        # ABANDON（预算反思）优先；SWITCH 对 benchmark 的 run_benchmark 是无操作
        # （仅处理 ABANDON），对 FeedbackLoop/live 链路是提前换题。
        if result.decision != "ABANDON" and conf < self.confidence_floor and attempt_index >= 1:
            return "SWITCH"
        return result.decision
