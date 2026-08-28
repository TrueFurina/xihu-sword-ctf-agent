"""预算熔断三级保护（v2.0 核心，防比赛中预算烧光/接口限流崩盘）。

三级保护：
1. 单题 token 上限（per_question_token_budget）：单题用量超上限 → 强制终止该题，
   防止「一道死循环的题烧光所有预算」。
2. 全局预算（global_token_budget）：全场总用量超上限 → 终止所有新任务，
   防止整场预算击穿。
3. 单题最大重试硬上限（max_retries_hard）：超出后不再重试（第三层兜底）。

降级策略：单题用量超过 downgrade_ratio × 上限时，提示调度层强制降级轻量模型，
而非直接终止（给简单题更多机会）。

用法（调度层集成）：
    tracker = BudgetTracker(config)
    if tracker.check(question_id) == "stop":
        return  # 终止该题
    ... 每次 LLM 调用后 tracker.record(question_id, tokens)
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)

from config import AppConfig

# 检查结果
BUDGET_OK = "ok"              # 正常
BUDGET_DOWNGRADE = "downgrade"  # 接近上限，建议降级轻量模型
BUDGET_STOP = "stop"          # 超限，必须终止


class BudgetExceeded(Exception):
    """步级硬停（2026-08-28 Claim 1 超调整改）：LLM 调用中途即达单题上限。

    由 run.py llm_client 闭包在每次调用累计后抛出，主循环兜底转成
    budget_exceeded 归因——避免「等 attempt 结束才 record/check」导致的
    超调（实测 vnctf_flag 超调至 139K，cap 仅 80K）。
    """

    category = "budget_exceeded"

    def __init__(self, question_id: str, used: int, cap: int):
        super().__init__(f"单题 token 预算超限（{question_id}: {used} >= {cap}），步级硬停")
        self.question_id = question_id
        self.used = used
        self.cap = cap


class BudgetTracker:
    """预算追踪与熔断器。"""

    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config or AppConfig.from_env()
        # {question_id: 累计 token}
        self._usage: dict[str, int] = {}
        self._global_usage: int = 0
        self._retries: dict[str, int] = {}
        self._started: float = time.time()
        self._stopped_questions: set[str] = set()

    # ── 记录 ────────────────────────────────────────────

    def record(self, question_id: str, tokens: int) -> None:
        """记录一次 LLM 调用的 token 消耗。"""
        tokens = max(int(tokens or 0), 0)
        self._usage[question_id] = self._usage.get(question_id, 0) + tokens
        self._global_usage += tokens

    def record_retry(self, question_id: str) -> int:
        """记录一次重试，返回当前重试次数。"""
        n = self._retries.get(question_id, 0) + 1
        self._retries[question_id] = n
        return n

    # ── 查询 ────────────────────────────────────────────

    def usage(self, question_id: str) -> int:
        return self._usage.get(question_id, 0)

    @property
    def global_usage(self) -> int:
        return self._global_usage

    def retries(self, question_id: str) -> int:
        return self._retries.get(question_id, 0)

    # ── 检查 ────────────────────────────────────────────

    def check(self, question_id: str) -> str:
        """检查该题是否还可继续。

        Returns:
            BUDGET_OK / BUDGET_DOWNGRADE / BUDGET_STOP
        """
        # 全局熔断：任何题目都先检查全场预算
        if self._global_usage >= self.config.global_token_budget:
            logger.warning("全局预算超限（%d >= %d），终止全场", 
                           self._global_usage, self.config.global_token_budget)
            return BUDGET_STOP

        # 已停的题直接返回 stop
        if question_id in self._stopped_questions:
            return BUDGET_STOP

        # 单题熔断：超过上限 → 终止该题
        q_usage = self._usage.get(question_id, 0)
        if q_usage >= self.config.per_question_token_budget:
            self._stopped_questions.add(question_id)
            logger.warning("单题预算超限（%s: %d >= %d），终止该题",
                           question_id, q_usage, self.config.per_question_token_budget)
            return BUDGET_STOP

        # 降级阈值：超过 downgrade_ratio 比例 → 建议降级轻量模型
        if q_usage >= self.config.per_question_token_budget * self.config.budget_downgrade_ratio:
            return BUDGET_DOWNGRADE

        return BUDGET_OK

    def check_retry(self, question_id: str) -> bool:
        """检查重试次数是否超过硬上限。"""
        return self._retries.get(question_id, 0) < self.config.max_retries_hard

    def reset_question(self, question_id: str) -> None:
        """重置题目预算跟踪（竞速多轮之间重置状态）。"""
        self._usage.pop(question_id, None)
        self._retries.pop(question_id, None)
        self._stopped_questions.discard(question_id)

    # ── 统计（看板/报表用）──────────────────────────────

    def describe(self) -> dict:
        return {
            "per_question_budget": self.config.per_question_token_budget,
            "global_budget": self.config.global_token_budget,
            "downgrade_ratio": self.config.budget_downgrade_ratio,
            "max_retries_hard": self.config.max_retries_hard,
            "global_usage": self._global_usage,
            "stopped_questions": sorted(self._stopped_questions),
        }
