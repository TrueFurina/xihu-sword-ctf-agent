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
    "wallclock_timeout",    # Agent **内部**墙钟止损（题跑过了、用满设计窗口仍没解出）
                            #   ——2026-10-06 拆分后：由 eval/benchmark 的
                            #   MECHANISM_TERMINATED_CATEGORIES 从「真·掐断」中排除；
                            #   保留于此仅为与 budget_exceeded 同构（报告语义由那侧决定）。
    "wallclock_killed",     # 评测器**外部** wait_for 掐断（Agent 未跑完即被杀，真·infra 故障）
                            #   ——2026-10-06 从 wallclock_timeout 拆出，**不属**机制终结。
    "race_abandon",         # 预算反思早停
    "solver_exception",     # solver 抛异常
    "not_attempted",        # 显式未尝试
    "rate_limited",         # 限流
    "provider_error",       # provider 侧错误
    "provider_circuit_open",  # provider 熔断(401/402/403)打开——基础设施不可达，非 Agent 能力失败（2026-10-05 回填）
    "infra_error",
    "INFRA_NO_CREDENTIAL",  # 无凭证（按项目铁律：不算推理失败）
})


# ── 终态失败：本轮内不可通过「立即重跑同一题」恢复 ──────────────────
# 重试只会把整段预算/墙钟再烧一遍（实证见模块 docstring）。遇到这些类别，
# **每一层**重试循环都必须短路。
# 注意：**不含** rate_limited / provider_error / provider_circuit_open / infra_error /
# INFRA_NO_CREDENTIAL —— 属瞬时/外部故障，保留原有重试行为（尽管无退避，改动最小化原则）。
# 其中 provider_circuit_open 虽终态，但 relabel 发生在 FeedbackLoop 重试之后（run.py solver），
# 故在此不计入 NON_RETRYABLE 以避免改变重试层既有短路语义；其诚实口径由 TRUNCATED 保证
# （→ interpretable=False，不污染能力率）。
NON_RETRYABLE_CATEGORIES = frozenset({
    "budget_exceeded",      # 预算已烧穿，再跑还是 budget_exceeded
    "wallclock_timeout",    # Agent 内部墙钟已耗尽，重跑同样超限
    "wallclock_killed",     # 外部评测墙钟掐断：评测墙钟不变 → 重跑无益（2026-10-06 拆分补入）
    "race_abandon",         # 已主动早停（含 budget_reflection ABANDON）
    "solver_exception",     # solver 已抛异常
    "not_attempted",        # 显式未尝试
})


# ── provider 熔断根因回填（2026-10-05）──────────────────────────────
# 实证：provider 熔断(连续 3 次 401/402/403)后 ai_chat 直接返回 None → 主 Agent
# 退化成 race_abandon / budget_exceeded（自身失败模式），报告被误读为「Agent 能力失败」。
# 熔断打开即 provider 永久死亡（直至换 key），故把退化的失败桶回填为
# provider_circuit_open，使报告诚实标记「基础设施不可达，非能力测量」。
PROVIDER_CIRCUIT_OPEN = "provider_circuit_open"

# 会「假扮」成 Agent 自身失败的退化终态桶（仅在 provider 熔断打开时回填）。
# 🔴 2026-10-06 扩充：原只有 {race_abandon, budget_exceeded, solver_exception}，
#   实测漏判 wrong_direction——moonshot kimi-k2.6 余额耗尽（HTTP 429 伪装永久故障）
#   熔断打开后，主 Agent 拿不到任何 LLM 响应，监督裁决退化为「同参数重复→死循环止损」
#   落 wrong_direction；该桶不在退化集合 → 报告照标 interpretable=True，把
#   「基础设施彻底不可达」冒充成「Agent 能力测量」（复现实证：熔断已打开，run.py
#   relabel 未命中，报告 tokens=1806 兜底值 + interpretable=true）。wrong_direction
#   与 race_abandon 同属「LLM 死掉后 Agent 空转出的自身失败假象」，必须一并回填。
_CIRCUIT_DEGRADED_BUCKETS = frozenset({
    "race_abandon",
    "budget_exceeded",
    "solver_exception",
    "wrong_direction",
})


def relabel_circuit_breaker(error_category, circuit_open: bool) -> str:
    """provider 熔断打开时，把退化的 Agent 失败桶回填为 provider_circuit_open。

    - circuit_open=False → 原样返回（不误伤）。
    - error_category 为 None（已解出）/ 不在退化桶内（如 provider_error 本身已是
      基础设施类、hallucination 等）→ 原样返回。
    - 仅当 circuit_open=True 且 error_category ∈ {race_abandon, budget_exceeded,
      solver_exception, wrong_direction} 时返回 PROVIDER_CIRCUIT_OPEN。
    """
    if not circuit_open:
        return error_category
    if error_category in _CIRCUIT_DEGRADED_BUCKETS:
        return PROVIDER_CIRCUIT_OPEN
    return error_category


__all__ = [
    "TRUNCATED_ERROR_CATEGORIES",
    "NON_RETRYABLE_CATEGORIES",
    "PROVIDER_CIRCUIT_OPEN",
    "relabel_circuit_breaker",
]
