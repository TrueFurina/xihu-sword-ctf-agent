"""微观态势：单题信心估计（纯规则，零 LLM，零外部依赖）。

来源：idea-stage/refine-logs/FINAL_PROPOSAL_RACE_INTELLIGENCE.md §4.3。
替代 proposal 引用的 error_classifier.py 外部依赖：内建轻量步骤分类启发式
（基于 StepRecord.observation / error_category），保持纯规则、可单测、无新增包。

信心分数 C_i(t) = α·H_i(t) + β·P_i(t) + γ·D_i(t)：
- H：最近 k 步中新线索比例（工具输出出现 URL/地址/函数/密钥）
- P：基于步骤错误分类的进展模式分数
- D：基于已消耗预算比例的指数衰减难度估计
"""
from __future__ import annotations

import math
import re
from typing import List, Optional, Sequence

# 步骤分类权重（proposal §4.3 weights）
_PATTERN_WEIGHTS = {
    "continue": 0.8,        # 正常进展
    "redirect": 0.6,        # 方向调整
    "switch_strategy": 0.4, # 策略切换
    "stuck_loop": 0.1,      # 卡住
    "hallucination": 0.2,   # 幻觉
}

# 新线索启发式（检测工具输出中是否出现之前未见的信号）
_CLUE_PATTERNS = [
    re.compile(r"https?://[^\s]+"),                 # URL
    re.compile(r"0x[0-9a-fA-F]+"),                  # 内存地址
    re.compile(r"[a-zA-Z_]\w*\("),                  # 函数调用
    re.compile(r"(?i)(key|flag|password|token|secret)\s*[:=]"),  # 密钥/flag 字段
]


def classify_step(output: str, error_category: Optional[str] = None) -> str:
    """内建轻量步骤分类（替代缺失的 error_classifier.py）。

    - 有明确错误类别 → 语义映射（tool_failure/stuck_loop → stuck_loop，
      hallucination → hallucination）
    - 否则看输出是否含新线索 → continue
    - 无新线索且无明显进展 → stuck_loop
    """
    if error_category:
        ec = str(error_category).lower()
        if "halluc" in ec:
            return "hallucination"
        if "tool" in ec or "stuck" in ec or "fail" in ec:
            return "stuck_loop"
    out = output or ""
    if any(p.search(out) for p in _CLUE_PATTERNS):
        return "continue"
    return "stuck_loop"


class ConfidenceEstimator:
    """单题信心估计器（纯规则）。"""

    def __init__(self, k: int = 5, alpha: float = 0.4, beta: float = 0.35, gamma: float = 0.25):
        self.k = k
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma

    def estimate(
        self,
        step_history: Sequence[str],
        error_history: Sequence[str],
        budget_ratio: float,
    ) -> float:
        """返回 C_i(t) ∈ [0, 1]。"""
        h = self._history_score(step_history)
        p = self._pattern_score(error_history)
        d = self._difficulty_score(budget_ratio)
        return max(0.0, min(1.0, self.alpha * h + self.beta * p + self.gamma * d))

    def _history_score(self, step_history: Sequence[str]) -> float:
        if not step_history:
            return 0.5  # 无历史时中性值
        recent = list(step_history)[-self.k:]
        new_clues = sum(1 for s in recent if self._has_new_clue(s))
        return new_clues / len(recent)

    @staticmethod
    def _has_new_clue(step_output: str) -> bool:
        return any(p.search(step_output or "") for p in _CLUE_PATTERNS)

    def _pattern_score(self, error_history: Sequence[str]) -> float:
        if not error_history:
            return 0.5
        recent = list(error_history)[-self.k:]
        scores = [_PATTERN_WEIGHTS.get(str(e), 0.5) for e in recent]
        return sum(scores) / len(scores)

    @staticmethod
    def _difficulty_score(budget_ratio: float) -> float:
        try:
            return math.exp(-2.0 * float(budget_ratio))
        except (TypeError, ValueError):
            return 0.5


def should_early_switch(
    confidence: Optional[float],
    llm_calls: int,
    llm_call_budget: int,
    override: bool = False,
) -> bool:
    """态势接管判定（默认关闭，需显式开启）。

    当 override 开启、且单题信心过低(<0.3)并已消耗过半 LLM 预算时，
    提前触发监督咨询换策略——避免低信心题空转到预算耗尽才放弃。

    纯函数、可单测；env 闸门在调用方（main_agent）处用
    CTF_AGENT_SITUATION_OVERRIDE=1 控制 override 入参，默认 False 不接管。
    """
    if not override:
        return False
    if confidence is None:
        return False
    cap = max(int(llm_call_budget) if llm_call_budget else 1, 1)
    return confidence < 0.3 and int(llm_calls) >= 0.5 * cap
