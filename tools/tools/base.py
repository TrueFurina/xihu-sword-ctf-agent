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
