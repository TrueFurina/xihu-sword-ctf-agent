"""flag 解出的**外部校验闸门**（唯一可采信的"解出"判据）。

起因（2026-09-28 真机真题批次1 实锤）：
LLM 会 `echo "flag{...}"` 打印字面占位符，而"输出命中 flag 正则"会把它当真解出
→ 报出 2 个假 SUCCESS，被本地 sha256 比对逮住（真实成绩 0/3）。

结论（写进代码，防止后人再踩）：
> **正则命中 = 候选；sha256 比对 = 解出。**
> 没有可校验的答案基准时，只能报"无法核验"，**绝不**记为解出。

设计约束（与项目铁律一致）：
- **不猜 flag、不生成 flag**：只做比对，输入候选来自会话真实输出。
- **答案基准不上行**：`flag_sha256` 由调用方（本地）持有，不进 prompt、不上传远端。
- **零网络、零 token**：纯哈希计算。
- **fail-closed**：无基准 / 无候选 / 无匹配 → `verified=False`。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass
class GateResult:
    """闸门判定结果。"""

    verified: bool              # 唯一可采信的"已解出"
    flag: Optional[str] = None  # 通过校验的 flag（未通过则 None）
    reason: str = ""
    candidates: int = 0         # 检视过的候选数（占位符已剔除）

    def to_dict(self) -> dict:
        return {"verified": self.verified, "flag": self.flag,
                "reason": self.reason, "candidates": self.candidates}


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def matches_sha256(candidate: str, expected_sha256: str) -> bool:
    """大小写不敏感比较 sha256 十六进制串。"""
    if not candidate or not expected_sha256:
        return False
    return sha256_of(candidate).lower() == expected_sha256.strip().lower()


def extract_candidates(text: str, flag_pattern: str) -> list[str]:
    """从一段文本中抽取所有 flag 候选（按出现顺序去重）。"""
    if not text or not flag_pattern:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(flag_pattern, text):
        s = m.group(0)
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


class FlagGate:
    """解出闸门：候选 → 校验 → 结论。

    典型用法::

        gate = FlagGate(expected_sha256=meta["flag_sha256"])
        res = gate.judge(session_all_hits)
        if res.verified:        # 只有这里为 True 才能记"解出"
            ...
    """

    def __init__(self, expected_sha256: str = "", flag_pattern: str = r"flag\{.*?\}") -> None:
        self.expected_sha256 = (expected_sha256 or "").strip()
        self.flag_pattern = flag_pattern

    # ── 判定 ────────────────────────────────────────────
    def judge(self, candidates: Iterable[str]) -> GateResult:
        cands = [c for c in (candidates or []) if c]
        if not cands:
            return GateResult(False, None, "无候选 flag（会话输出未命中）", 0)
        if not self.expected_sha256:
            # fail-closed：没有可校验基准，绝不记为解出
            return GateResult(False, None,
                              "无答案基准（flag_sha256 缺失）→ 不可核验，不得记为解出",
                              len(cands))
        for c in cands:
            if matches_sha256(c, self.expected_sha256):
                return GateResult(True, c, "sha256 校验通过", len(cands))
        return GateResult(False, None,
                          f"{len(cands)} 个候选均未通过 sha256 校验（疑似占位符/幻觉）",
                          len(cands))

    def judge_text(self, text: str) -> GateResult:
        return self.judge(extract_candidates(text, self.flag_pattern))


__all__ = ["GateResult", "FlagGate", "sha256_of", "matches_sha256",
           "extract_candidates"]
