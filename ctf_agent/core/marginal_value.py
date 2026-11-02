"""宏观态势：边际收益估计 + MAB 探索（纯数学，零 LLM）。

来源：idea-stage/refine-logs/FINAL_PROPOSAL_RACE_INTELLIGENCE.md §4.4。

MV_i(t) = s_i · p̂_i / t̂_i + UCB 探索项
- 利用项：s_i · p̂_i / t̂_i（分数/时间 的边际收益）
- 探索项：sqrt(2·ln(N+1) / n_i)（UCB1 变体，鼓励尝试未探索的题）
"""
from __future__ import annotations

import math
from typing import Dict


class MarginalValueEstimator:
    """边际收益估计器（MAB 集成）。"""

    def __init__(self, exploration_factor: float = 1.0):
        self.exploration_factor = exploration_factor
        self.pull_counts: Dict[str, int] = {}
        self.total_pulls: int = 0

    def estimate(
        self,
        qid: str,
        score: float,
        confidence: float,
        avg_time: float,
        time_pulled: float,
    ) -> float:
        """返回 MV_i(t)。未探索过的题返回 +inf（优先探索）。"""
        p_hat = max(0.0, min(1.0, float(confidence)))
        t_hat = max(float(avg_time) * (1.0 - p_hat), 1.0)  # 信心越高，剩余时间越少
        exploit = (float(score) * p_hat) / t_hat

        n_i = self.pull_counts.get(qid, 0)
        if n_i == 0:
            # 未探索的题无条件优先。直接返回 inf，而不是 exploit + factor*inf ——
            # 后者在 exploration_factor=0（纯利用模式）时是 0*inf = nan，
            # NaN 与任何数比较都为 False，排序会静默失效（未探索题不再被优先）。
            return float("inf")
        n = self.total_pulls
        explore = math.sqrt(2.0 * math.log(n + 1) / n_i)
        return exploit + self.exploration_factor * explore

    def record_pull(self, qid: str) -> None:
        """记录一次拉臂（在分配/尝试该题后调用）。"""
        self.pull_counts[qid] = self.pull_counts.get(qid, 0) + 1
        self.total_pulls += 1
