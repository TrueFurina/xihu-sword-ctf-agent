"""工具注册表：主 Agent 按需调用工具（v2.0 要点：输出过滤，只送关键数据进 LLM）。

- register/get：注册与获取适配器
- suggest：按题型推荐可用工具
- run：执行工具并返回过滤后的输出
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

from tools.base import ToolAdapter, ToolOutput


class ToolRegistry:
    """工具注册表。"""

    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        """注册一个工具适配器（同名覆盖）。"""
        if not adapter.name:
            logger.warning("跳过注册：适配器缺少 name")
            return
        self._adapters[adapter.name] = adapter
        logger.debug("已注册工具: %s（题型: %s）", adapter.name, adapter.categories or "通用")

    def get(self, name: str) -> Optional[ToolAdapter]:
        return self._adapters.get(name)

    def has(self, name: str) -> bool:
        return name in self._adapters

    def names(self) -> list[str]:
        return sorted(self._adapters.keys())

    def suggest(self, category: str) -> list[str]:
        """按题型推荐可用工具名。"""
        return sorted(
            name for name, a in self._adapters.items() if a.can_handle(category)
        )

    async def run(self, name: str, params: dict) -> ToolOutput:
        """执行工具（找不到返回错误 ToolOutput，不抛异常）。

        抄 CTF-Buster：统一输出清洗层——工具原始输出自动过滤/格式化后再给模型，
        去空行/去重复行/截断，避免冗余信息干扰模型判断。

        HITL 敏感操作审批（2026-09-02，借鉴 SecAutoMind）：
        高危工具（任意代码执行/网络外联/文件写/任意读）默认记录审计日志不阻塞
        （保持自动化解题）；CTF_AGENT_HITL=1 时启用交互审批（倒计时+拒绝）。
        """
        adapter = self._adapters.get(name)
        if adapter is None:
            return ToolOutput(text=f"工具不存在: {name}", ok=False)
        # HITL 敏感操作审批钩子
        if not self._hitl_check(name, params):
            return ToolOutput(text=f"HITL 审批拒绝: {name}（高危操作未经批准）", ok=False)
        try:
            out = await adapter.run(params)
        except Exception as exc:  # noqa: BLE001 - 工具异常兜底
            logger.warning("工具 %s 执行异常: %s", name, exc)
            return ToolOutput(text=f"工具执行异常: {exc}", ok=False)
        # 统一清洗层：text 进 LLM 前自动过滤
        return ToolOutput(
            text=self._sanitize_output(out.text),
            raw=out.raw,
            ok=out.ok,
        )

    # ── HITL 敏感操作审批（2026-09-02）────────────────────────────
    # 高危工具名单：执行前需审批/记录。默认（CTF_AGENT_HITL 未设）仅记录审计日志
    # 不阻塞（保持自动化解题，以解题能力为最终目标）；CTF_AGENT_HITL=1 时交互审批。
    _HIGH_RISK_TOOLS = frozenset({
        "python_adapter",   # 任意 Python 代码执行
        "web_request",      # 网络外联（可访问任意 URL）
        "xxe",              # XXE 任意文件读
        "file_analysis",    # 文件读写（潜在覆盖）
        "bkcrack",          # 压缩包密钥爆破（算力开销大）
    })

    @staticmethod
    def _hitl_check(name: str, params: dict) -> bool:
        """高危工具审批：默认记录；CTF_AGENT_HITL=1 时交互审批（倒计时+拒绝）。

        Returns:
            True = 放行（默认记录模式）；False = 审批拒绝（仅 HITL 模式超时/拒绝时）。
        """
        if name not in ToolRegistry._HIGH_RISK_TOOLS:
            return True
        import os
        import time
        hitl = os.getenv("CTF_AGENT_HITL", "").strip() == "1"
        action = str(params.get("action", "") or "")
        detail = str(params)[:120]
        if not hitl:
            # 默认：记录审计日志（不阻塞自动化解题）
            logger.warning("[HITL] 高危工具 %s 已执行（action=%s，params=%s）——记录审计",
                           name, action, detail)
            return True
        # HITL 模式：交互审批（倒计时 15s，超时拒绝）
        logger.warning("[HITL] ⚠️ 高危操作需审批: %s action=%s params=%s",
                       name, action, detail)
        try:
            remaining = 15
            while remaining > 0:
                answer = input(f"[HITL] 批准执行 {name}? (y/N, {remaining}s): ").strip().lower()
                if answer in ("y", "yes"):
                    return True
                if answer in ("n", "no", ""):
                    return False
                remaining -= 1
        except EOFError:
            return False  # 非交互环境（CI/后台）默认拒绝
        return False  # 倒计时超时拒绝

    @staticmethod
    def _sanitize_output(text: str, limit: int = 2000) -> str:
        """统一输出清洗：去空行/去重复行/截断（抄 CTF-Buster 输出格式化）。

        Args:
            text: 工具原始输出（text 字段）
            limit: 保留最大字符数（默认 2000，防超长输出进 LLM 幻觉炸裂）
        """
        if not text:
            return ""
        lines = [ln.rstrip() for ln in text.splitlines()]
        # 去空行/纯空白行
        lines = [ln for ln in lines if ln.strip()]
        # 去连续重复行（防重复命令/循环输出污染上下文）
        deduped: list[str] = []
        for ln in lines:
            if not deduped or ln != deduped[-1]:
                deduped.append(ln)
        cleaned = "\n".join(deduped)
        if len(cleaned) <= limit:
            return cleaned
        # 超长截断：保留头部关键信息 + 尾部（flag 常在末尾）
        head = cleaned[: int(limit * 0.7)]
        tail = cleaned[-int(limit * 0.3) :]
        return head + "\n...[截断，共省略 %d 字符]...\n" % (len(cleaned) - limit) + tail

    def describe(self) -> dict:
        return {
            name: {"categories": a.categories}
            for name, a in self._adapters.items()
        }
