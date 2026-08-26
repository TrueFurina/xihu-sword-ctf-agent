"""flag 校验器：格式验证 + 多格式提取。

职责：
- 按题目 flag_pattern 校验候选 flag 是否合法
- 从 LLM 输出中提取 flag（支持代码围栏/引号/纯文本多种出现形式）
- 五层提取思路：正则预扫 → 明确格式 → 宽松提取（参考 LLM-CTF-Solver flag_detector）
- 校验门：REJECT/WARN/ACCEPT 三态（参考 hydra flag_gate）
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Union

logger = logging.getLogger(__name__)

DEFAULT_FLAG_PATTERN = r"flag\{[^}\s]+\}"

# 校验门三态（对齐 hydra flag_gate）
V_ACCEPT = "accept"      # 通过
V_WARN = "warn"          # 有瑕疵但可接受
V_REJECT = "reject"      # 拒绝（格式明显非法）


class FlagChecker:
    """flag 格式验证与提取。"""

    def __init__(
        self,
        default_pattern: str = DEFAULT_FLAG_PATTERN,
        min_len: int = 6,
        max_len: int = 512,
    ) -> None:
        self.default_pattern = default_pattern
        self.min_len = min_len
        self.max_len = max_len

    # ── 提取 ────────────────────────────────────────────

    def extract(self, raw: str, pattern: Optional[str] = None) -> Optional[str]:
        """从文本中提取 flag（找不到返回 None）。

        Args:
            raw: 模型输出/工具输出的原始文本
            pattern: 覆盖默认 flag 格式（如 DASCTF{...}）

        Returns:
            提取到的 flag 字符串；未找到返回 None
        """
        if not raw or not isinstance(raw, str):
            return None

        pat = pattern or self.default_pattern
        try:
            compiled = re.compile(pat)
        except re.error:
            compiled = re.compile(DEFAULT_FLAG_PATTERN)

        # 第一层：显式 pattern 匹配（优先题目自定义格式）
        m = compiled.search(raw)
        if m:
            return m.group(0).strip()

        # 第二层：宽松提取——仅匹配含 flag 关键词前缀的 {xxx} 结构
        # （避免把密文如 iodj{...} 误判为 flag：需 flag/ctf/dasctf 等前缀；
        #  排除空白字符，避免跨行贪婪匹配；大小写不敏感）
        m = re.search(r"(?i)(?:flag|ctf|dasctf)\{[^}\s]{4,}\}", raw)
        if m:
            return m.group(0).strip()

        return None

    # ── 验证（REJECT/WARN/ACCEPT 三态）──────────────────

    def validate(self, flag: str, pattern: Optional[str] = None) -> bool:
        """校验 flag 是否通过（bool 版本，兼容旧调用方）。"""
        return self.check(flag, pattern) in (V_ACCEPT, V_WARN)

    def check(self, flag: str, pattern: Optional[str] = None) -> str:
        """三态校验门。

        规则（对齐 hydra flag_gate）：
        - REJECT：空值 / 长度越界 / 未闭合括号 / 控制字符 / 非法字符 / 完全不符合 pattern
        - WARN：符合 pattern 但含可疑特征（如前后缀多余、长度临界）
        - ACCEPT：格式完全合法

        Args:
            flag: 候选 flag
            pattern: 覆盖默认 flag 格式

        Returns:
            V_ACCEPT / V_WARN / V_REJECT
        """
        if not flag or not isinstance(flag, str):
            return V_REJECT

        f = flag.strip()
        if not f:
            return V_REJECT

        _has_surrounding_ws = (f != flag)

        # 控制字符与非法字符
        if any(ord(c) < 32 or c in ('"', "'", "`", "\\") for c in f):
            return V_REJECT

        # 长度上下界
        if len(f) < self.min_len or len(f) > self.max_len:
            return V_REJECT

        # 花括号配对检查（未闭合括号直接拒绝）
        if f.count("{") != 1 or f.count("}") != 1:
            return V_REJECT
        if f.find("}") < f.find("{"):
            return V_REJECT

        # pattern 匹配
        pat = pattern or self.default_pattern
        try:
            matched = bool(re.fullmatch(pat, f))
        except re.error:
            matched = bool(re.fullmatch(DEFAULT_FLAG_PATTERN, f))

        # 宽松 fallback：平台 flag 可能是 DASCTF{}/CTF{} 等前缀（本地题库默认 flag{}）
        # （extract 已有此宽松逻辑，validate 必须对齐，否则平台题 DASCTF{} 会被格式拦截；大小写不敏感）
        if not matched:
            matched = bool(re.fullmatch(
                r"(?i)(?:flag|ctf|dasctf)\{[^}\s]{4,}\}", f))

        if not matched:
            return V_REJECT

        # WARN 特征：长度临界（靠近上下界 10%）、含明显占位特征、前后有空白
        if len(f) <= self.min_len + 2 or len(f) >= self.max_len * 0.9:
            return V_WARN
        if re.search(r"(?i)(todo|xxx|placeholder|待填|占位)", f):
            return V_WARN
        if _has_surrounding_ws:
            return V_WARN

        return V_ACCEPT

    # ── 摘要 ────────────────────────────────────────────

    def summarize(self, flag: str) -> str:
        """生成 flag 的安全摘要（答辩/日志用，避免完整泄露）。"""
        if not flag:
            return "(无)"
        return f"{flag[:8]}...({len(flag)}字符)"
