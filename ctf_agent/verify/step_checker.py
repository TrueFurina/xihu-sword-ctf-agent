"""步骤级校验：解析工具/脚本输出，提取关键信息（v2.0 核心）。

职责（对齐专家意见「不给模型原始日志，给结构化摘要」）：
- 裁剪超长输出（默认 500 字符）
- 正则抽取关键行（报错行/flag 特征/可打印字符串）
- 生成结构化摘要供监督 Agent 与主 Agent 下一步使用
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

MAX_OUTPUT_CHARS = 500


@dataclass
class ParsedOutput:
    """工具输出的结构化解析结果。"""

    text: str = ""                    # 裁剪后的文本（默认 500 字符）
    truncated: bool = False           # 是否被裁剪
    key_lines: list = field(default_factory=list)   # 关键行（错误/flag/数字特征）
    has_flag_like: bool = False       # 是否含 flag 特征
    has_error_marker: bool = False    # 是否含报错特征
    error_hint: str = ""              # 提取到的错误提示（若有）

    def to_prompt_snippet(self, limit: int = 300) -> str:
        """生成给 LLM 的摘要片段（不送原始全文）。"""
        parts = [self.text[:limit]]
        if self.key_lines:
            parts.append("关键行:\n" + "\n".join(self.key_lines[:5]))
        return "\n".join(parts)


class StepChecker:
    """步骤级校验器：解析输出、判断阶段。"""

    # 常见报错特征（用于错误分类辅助）
    ERROR_MARKERS = [
        r"(?i)(error|exception|traceback|failed|permission denied|not found|"
        r"segmentation fault|timeout|timed out|no such file|command not found)",
    ]

    def parse_tool_output(self, output: str, max_chars: int = MAX_OUTPUT_CHARS) -> ParsedOutput:
        """解析工具输出：裁剪 + 提取关键行。"""
        text = str(output or "")[:max_chars]
        parsed = ParsedOutput(text=text, truncated=len(str(output or "")) > max_chars)

        # 关键行提取：报错行 / flag 特征 / 数字特征
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if re.search(r"flag\{[^}]+\}|FLAG\{[^}]+\}", line):
                parsed.key_lines.append(line)
                parsed.has_flag_like = True
            elif re.search(r"(?i)error|exception|traceback|failed|timeout|denied", line):
                parsed.key_lines.append(line)
                parsed.has_error_marker = True
                if not parsed.error_hint:
                    parsed.error_hint = line[:200]

        return parsed

    def judge_stage(self, steps) -> str:
        """判断当前解题阶段（基于最近步骤特征）。"""
        from core.main_agent import STAGE_FLAG_EXTRACT, STAGE_RECON

        if not steps:
            return STAGE_RECON
        recent = steps[-3:]
        # 若最近步骤含 flag 特征 → flag_extract
        # 2026-08-21 P0：多格式 flag 检测（flag{/CTF{/DASCTF{，大小写不敏感），
        # 否则 DASCTF{} 的真题观测会被误判为"无 flag 特征"→ 监督阶段错判
        for s in recent:
            if s.error_category in ("hallucination", None) and re.search(
                    r"(?i)(?:flag|ctf|dasctf)\{", s.observation or ""):
                return STAGE_FLAG_EXTRACT
        return STAGE_RECON
