"""人工干预协调器（抄 CyberStrikeAI / NUS ctf-agent-orchestrator）。

核心：AI 自动执行 + 人工战略监督。

⚠️ 西湖论剑初赛/决赛合规警告 ⚠️
官方手册第八条第 3 款：「每支队伍仅允许一个 Agent 接入平台进行答题」
选手群官方回复（2026-08-17）：「我们不鼓励人工引导，希望选手主要关注
agent 自身的解题能力」+「与平台交互的所有流量以及 API 会话等将被记录」

→ 初赛/决赛实战中：
  - ❌ 禁止注入「解题方向」类提示（属人工引导，会被流量审计判定违规）
  - ❌ 禁止人工提交 flag（手册第 9 条：赛后不接受任何形式提交）
  - ✅ 仅可用于：开发调试期模拟卡壳、答辩演示展示人机协同、赛后复盘

→ 启用方式：默认关闭。开发/演示时设环境变量 CTF_AGENT_ALLOW_HUMAN=1 才生效；
  初赛部署时务必保持该变量未设置，让 coordinator 自动降级为 no-op。

核心能力（仅开发/演示用）：
- 人工可向运行中的任务（task_id）注入定向提示（高优先级上下文）
- MainAgent 每步轮询（poll），有新提示则注入 ctx.advisor_hint 修正路径
- 支持「连续失败自动标记待人工」：Agent 卡壳时置 need_human=True，Web 面板可看到并介入
- 所有干预操作记录审计日志（竞赛现场可追溯）

用法（Web 面板，仅开发/演示）：
    coordinator.inject_hint("crypto-006", "换个思路：先试小指数攻击")
    coordinator.request_human("crypto-006", reason="连续 3 步无进展")
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


def _human_intervention_allowed() -> bool:
    """是否允许人工干预（默认 False，开发/演示设 CTF_AGENT_ALLOW_HUMAN=1）。"""
    return os.getenv("CTF_AGENT_ALLOW_HUMAN", "0") == "1"


@dataclass
class InterventionState:
    """单个任务的干预状态。"""

    task_id: str
    pending_hints: list = field(default_factory=list)   # 待注入的人工提示队列
    need_human: bool = False                            # 是否等待人工介入（卡壳标记）
    reason: str = ""                                    # 请求人工介入的原因
    audit: list = field(default_factory=list)           # 审计日志 [(ts, event, detail)]
    _polled_ts: float = 0.0


class InterventionCoordinator:
    """人工干预协调器：task_id → 干预状态，Web/CLI 与 Agent 共享。"""

    def __init__(self) -> None:
        self._states: dict[str, InterventionState] = {}

    def _get(self, task_id: str) -> InterventionState:
        if task_id not in self._states:
            self._states[task_id] = InterventionState(task_id=task_id)
        return self._states[task_id]

    # ── 人工侧 API（Web 面板调用）────────────────────────

    def inject_hint(self, task_id: str, hint: str) -> bool:
        """人工向运行中的任务注入定向提示（高优先级上下文）。

        ⚠️ 初赛/决赛禁用！需先设 CTF_AGENT_ALLOW_HUMAN=1（开发/演示模式）。
        """
        if not _human_intervention_allowed():
            logger.warning(
                "[%s] 人工提示注入被拒绝（初赛合规模式，"
                "需 CTF_AGENT_ALLOW_HUMAN=1 才启用）: %s",
                task_id, (hint or "")[:60],
            )
            return False
        if not hint or not hint.strip():
            return False
        state = self._get(task_id)
        state.pending_hints.append(hint.strip())
        state.audit.append((time.time(), "human_hint", hint.strip()))
        logger.info("[%s] 人工注入提示: %s", task_id, hint.strip()[:60])
        return True

    def request_human(self, task_id: str, reason: str = "") -> None:
        """Agent 侧标记：任务卡壳，请求人工介入（幂等：已标记不重复审计）。"""
        state = self._get(task_id)
        if state.need_human:
            return
        state.need_human = True
        state.reason = reason or "未说明"
        state.audit.append((time.time(), "need_human", state.reason))

    def clear_human_flag(self, task_id: str) -> None:
        """人工介入后清除卡壳标记。"""
        state = self._get(task_id)
        state.need_human = False
        state.reason = ""
        state.audit.append((time.time(), "human_resolved", ""))

    # ── Agent 侧 API（MainAgent 每步轮询）────────────────

    def poll(self, task_id: str) -> Optional[str]:
        """取出待注入的提示（FIFO）；无则返回 None。"""
        state = self._get(task_id)
        state._polled_ts = time.time()
        if state.pending_hints:
            hint = state.pending_hints.pop(0)
            state.audit.append((time.time(), "agent_poll", hint[:60]))
            return hint
        return None

    def status(self, task_id: str) -> dict:
        """任务干预状态摘要（Web 面板展示）。"""
        state = self._get(task_id)
        return {
            "task_id": task_id,
            "need_human": state.need_human,
            "reason": state.reason,
            "pending_hints": list(state.pending_hints),
            "audit_count": len(state.audit),
        }

    def pending_tasks(self) -> list[dict]:
        """全部等待人工介入的任务（Web 面板列表）。"""
        return [
            self.status(tid) for tid, s in self._states.items() if s.need_human
        ]
