"""Budget-reflection（race-intelligence 第二层，2026-08-27 务实落地）。

基于「已消耗预算比例 + 近期进展信号 + 当前信心」做**无 LLM、确定性**的预算反思，
输出决策：CONTINUE / SWITCH / ABANDON。

设计定位（与已有模块互补，不重复）：
- confidence.py 估计单题信心（α·H+β·P+γ·D）；
- marginal_value.py 估计边际收益（MAB）；
- 本模块聚焦**预算维度的早停/换路**：当预算快烧完却零进展时，
  主动 ABANDON（早停）或 SWITCH（换策略），避免把整段预算空烧在 hopeless 路径上。

零依赖、纯逻辑、可单测；不调用任何 LLM / 外部模型。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

DECISION_CONTINUE = "CONTINUE"
DECISION_SWITCH = "SWITCH"
DECISION_ABANDON = "ABANDON"


@dataclass
class BudgetState:
    """预算/时间快照（由 AgentContext 在每步构造，传入 reflect）。"""
    budget_total: int = 12
    budget_used: int = 0
    elapsed: float = 0.0          # 秒（可选，当前决策未依赖，预留扩展）
    time_budget: float = 0.0      # 秒（可选，预留）
    # 本次求解至今的候选 flag 数（2026-09-23 新增）：
    # None = 未知（老调用方/单测）→ 零候选规则**不参与判定**，保证向后兼容；
    # 0    = 明确"至今零候选"，这是真实链路唯一可靠、不可自欺的进展信号。
    candidates_found: Optional[int] = None


@dataclass
class ReflectionResult:
    decision: str
    reason: str
    metrics: dict = field(default_factory=dict)


def _made_progress(step: Any) -> bool:
    """一步是否产生有效进展：有非空 observation 且无 error_category。"""
    obs = getattr(step, "observation", "") or ""
    err = getattr(step, "error_category", None)
    return bool(str(obs).strip()) and err is None


def reflect(state: BudgetState, steps: List[Any],
            confidence: Optional[float] = None) -> ReflectionResult:
    """核心反思函数（确定性、无 LLM）。

    入参：
      state      预算快照（budget_total / budget_used）
      steps      已记录步列表（StepRecord，需 .observation / .error_category）
      confidence 当前单题信心（0..1；None 视为 0.5 中性）
    出参：ReflectionResult(decision, reason, metrics)
    """
    total = max(int(getattr(state, "budget_total", 1) or 1), 1)
    used = min(int(getattr(state, "budget_used", 0) or 0), total)
    ratio = used / total
    conf = 0.5 if confidence is None else float(confidence)

    window = steps[-10:]
    prog = [s for s in window if _made_progress(s)]
    no_progress_recent = len(prog) == 0
    trailing = 0
    for s in reversed(steps):
        if _made_progress(s):
            break
        trailing += 1

    metrics = {
        "budget_ratio": round(ratio, 3),
        "confidence": round(conf, 3),
        "progress_in_window": len(prog),
        "trailing_no_progress": trailing,
        "candidates_found": getattr(state, "candidates_found", None),
    }

    # 候选 flag 硬信号（2026-09-23）：None=未知（不参与判定，向后兼容）；0=明确零候选
    cand = getattr(state, "candidates_found", None)
    has_cand = cand is not None and int(cand) > 0

    # ① 预算将尽 + 零进展 + 低信心 → 早停（避免空烧整段预算）
    # 已有候选 flag 时不早停：候选已在手，主循环会立即 break 收敛，早停只会误杀。
    if ratio >= 0.85 and no_progress_recent and conf < 0.4 and not has_cand:
        return ReflectionResult(
            DECISION_ABANDON,
            "预算将尽(>=85%)+近期零进展+低信心：早停避免空烧",
            metrics,
        )
    # ② 过半预算 + 低信心 + 连续无进展（>=4 步）→ 建议换策略（交给监督升级/切换）
    if ratio >= 0.5 and conf < 0.3 and trailing >= 4:
        return ReflectionResult(
            DECISION_SWITCH,
            "过半预算+低信心+连续>=4步无进展：建议换策略",
            metrics,
        )
    # ⑥ 全程零候选 + 消耗过半 → 早停（2026-09-23 修复：让 ABANDON 在真实链路可达）
    # 根因：真实链路里 observation 恒非空（agent 一直在读附件/打印输出），
    # 于是 ①/② 依赖的 no_progress_recent / trailing 恒为 0 假值，ABANDON 成了
    # 不可达的死代码；而 ④「预算偏紧但信心高」又恰好把"零候选却自我感觉良好"
    # 的路径判成 CONTINUE。实证（held-out 17 池 / deepseek / 2026-09-22）：
    # 3 题各烧 19-22 万 token、候选全程 False，15/15 次反思全 CONTINUE，
    # 直到预算耗尽报 budget_exceeded——钱烧光了，反思器还在说"预算充足"。
    # 候选 flag 数是不可自欺的硬信号：没有它就是没有，与"做了很多动作"无关。
    if cand is not None and int(cand) <= 0 and ratio >= 0.6 and used >= 5:
        return ReflectionResult(
            DECISION_ABANDON,
            "消耗>=60%且全程零候选 flag：无收敛信号，早停避免空烧（候选口径）",
            metrics,
        )
    # ③ 预算充足 + 信心尚可 → 继续
    if ratio < 0.5 and conf >= 0.5:
        return ReflectionResult(
            DECISION_CONTINUE, "预算充足+信心尚可：继续", metrics
        )
    # ④ 预算偏紧但信心高且有进展 → 继续收敛
    if ratio >= 0.7 and conf >= 0.6:
        return ReflectionResult(
            DECISION_CONTINUE, "预算偏紧但信心高+有进展：继续收敛", metrics
        )
    # ⑤ 默认继续
    return ReflectionResult(DECISION_CONTINUE, "默认继续", metrics)
