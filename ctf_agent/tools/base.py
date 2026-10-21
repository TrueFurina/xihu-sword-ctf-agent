"""ToolAdapter 抽象基类：所有工具适配器的统一接口。

职责：
- 封装具体工具（openssl/python/sqlmap/zsteg/binwalk...）的调用方式
- 输出过滤：只送关键数据进 LLM，减 token（v2.0 要点）
- 由 ToolRegistry 统一注册与按需调用
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


class ToolOutput:
    """工具执行结果（过滤后）。"""

    def __init__(self, text: str = "", raw: str = "", ok: bool = False):
        self.text = text      # 过滤后的关键输出（给 LLM 用）
        self.raw = raw        # 原始输出（日志用）
        self.ok = ok

    def __str__(self) -> str:
        return self.text


class ToolAdapter(ABC):
    """工具适配器抽象。"""

    #: 工具名称（注册表主键），子类必须定义
    name: str = ""
    #: 适用题型（web/crypto/misc/reverse/pwn；空=通用）
    categories: list = []
    #: plan 可透传的额外参数声明（键名 → 一句话说明）。空 = 只收 path。
    #:
    #: 背景（2026-10-20 接线审计）：`core/action_executor.execute_tool` 原先只把
    #: `path` 透传给适配器（其余 plan 字段全部丢弃），于是「带参数的通道」——
    #: 如 rea_probe 的 lane/selector、pcap_probe 的 flow/top_n——在主链上永远
    #: 走默认值，等于不可用。这里改成「适配器自己声明收哪些参数」，主链只转发
    #: 声明过的键：既恢复能力，又不让 LLM 的任意 plan 字段污染适配器签名。
    param_spec: dict = {}

    def __init__(self, sandbox=None) -> None:
        self.sandbox = sandbox  # 可选：沙盒执行器（用于跑命令/脚本）

    @abstractmethod
    async def run(self, params: dict) -> ToolOutput:
        """执行工具。

        Args:
            params: 工具参数（由主 Agent 的 plan 传入），如
                    {"question": Question, "payload": "...", "args": "..."}

        Returns:
            ToolOutput（text 为过滤后的关键输出）
        """
        raise NotImplementedError

    def can_handle(self, category: str) -> bool:
        """是否适用于某题型。"""
        return category in self.categories or not self.categories

    # ── 输出过滤辅助 ────────────────────────────────────

    @staticmethod
    def _truncate(text: str, limit: int = 500) -> str:
        return (text or "")[:limit]

    @staticmethod
    def _first_lines(text: str, n: int = 10) -> str:
        lines = [l for l in (text or "").splitlines() if l.strip()]
        return "\n".join(lines[:n])
