"""竞赛全局/单题状态数据结构（态势感知载体）。

来源：idea-stage/refine-logs/FINAL_PROPOSAL_RACE_INTELLIGENCE.md §4.2 RaceState/QuestionState。
纯数据类，承载微观/中观/宏观三层态势的输入与中间量。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class QuestionState:
    """单题状态。"""

    qid: str = ""
    score: int = 100
    category: str = "misc"
    confidence: float = 0.5
    marginal_value: float = 0.0
    budget_consumed: float = 0.0
    time_consumed: float = 0.0
    steps_taken: int = 0
    error_history: List[str] = field(default_factory=list)


@dataclass
class RaceState:
    """竞赛全局状态。"""

    time_remaining: float = 180.0          # 分钟
    budget_remaining: float = 1.0          # 归一化 token 比例
    budget_total: float = 1.0
    budget_rate: float = 0.0               # tokens/min
    solved_count: int = 0
    total_count: int = 0
    active_questions: List[QuestionState] = field(default_factory=list)
    pending_questions: List[QuestionState] = field(default_factory=list)
    question_states: Dict[str, QuestionState] = field(default_factory=dict)

    @property
    def rpi(self) -> float:
        """资源压力指数 RPI = budget_rate · time_remaining / budget_remaining。

        RPI > 1 表示按当前速率预算将在赛前耗尽 → 触发降级。
        """
        denom = max(self.budget_remaining, 1e-9)
        return (self.budget_rate * self.time_remaining) / denom
