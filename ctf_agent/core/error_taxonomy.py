"""错误分类单一真值源（2026-09-23 建立）。

为什么存在
----------
`NON_RETRYABLE_CATEGORIES`（终态失败口径）被**多层重试循环**共同消费：

  1. `eval/benchmark.py` 的 `for attempt in range(max_retries)`
  2. `verify/feedback.py` 的 `FeedbackLoop.run` 的 `for attempt in range(retries)`
  3. （未来新增的任何重试层）

任何一层漏判 → 终态失败在该层被重烧预算。这不是假想：

  2026-09-23 held-out 验证跑实测 `ext_gctf2023_cursved` 一题被重跑 4 段步循环
  （内层 `FeedbackLoop` 3 轮 × 每轮 8-9 步，每轮都以 ABANDON 结束），
  单题烧 111K tokens 却零候选。根因正是「口径散落在各处、每层各写一份」。

因此本模块是**该口径的唯一真值**：`eval/benchmark.py` 与 `verify/feedback.py`
必须从这里 import，不得各自复刻字面量（`tests/test_feedback_terminal.py` 有锁）。
"""

from __future__ import annotations

# ── 「被外部条件掐断」的错误分类 ──────────────────────────────────
# 这些题虽被计入分母，但并未走完正常求解流程，因此 solve_rate 对它们不构成能力度量。
# 注意：**不含** "no_output"（solver 正常跑完但没解出，是正常判负，不是错误），
# 也不含 None（解出）。混入它们会让告警天天响、沦为噪音。
TRUNCATED_ERROR_CATEGORIES = frozenset({
    "budget_exceeded",      # 预算耗尽（token/步数）——2026-09-22 held-out 17 池的主因
    "wallclock_timeout",    # 墙钟先到，确定性工具链没机会跑完
    "race_abandon",         # 预算反思早停
    "solver_exception",     # solver 抛异常
    "not_attempted",        # 显式未尝试
    "rate_limited",         # 限流
    "provider_error",       # provider 侧错误
    "infra_error",
    "INFRA_NO_CREDENTIAL",  # 无凭证（按项目铁律：不算推理失败）
})


# ── 终态失败：本轮内不可通过「立即重跑同一题」恢复 ──────────────────
# 重试只会把整段预算/墙钟再烧一遍（实证见模块 docstring）。遇到这些类别，
# **每一层**重试循环都必须短路。
# 注意：**不含** rate_limited / provider_error / infra_error / INFRA_NO_CREDENTIAL ——
# 属瞬时外部故障，保留原有重试行为（尽管无退避，改动最小化原则）。
NON_RETRYABLE_CATEGORIES = frozenset({
    "budget_exceeded",      # 预算已烧穿，再跑还是 budget_exceeded
    "wallclock_timeout",    # 墙钟已耗尽，确定性工具链都没机会跑完
    "race_abandon",         # 已主动早停（含 budget_reflection ABANDON）
    "solver_exception",     # solver 已抛异常
    "not_attempted",        # 显式未尝试
})


__all__ = [
    "TRUNCATED_ERROR_CATEGORIES",
    "NON_RETRYABLE_CATEGORIES",
]
