"""会话压缩 / 记忆管理（G5 抽象）· 长程记忆的抽取、压缩与检索。

补 `core/session.py` 的不足：``Session.transcript()`` 只是把所有 step 拼起来并截断，
长会话会爆 token，也没有"关键信息索引"。G5 提供：
- 规则式事实抽取（flag 片段 / 文件路径 / 错误 / 关键命令）
- 会话压缩（保留最近 N 条 + 命中关键事实的旧条；必要时注入 LLM 做语义压缩）
- 关键词检索（把"曾经见过的 flag 片段 / 文件路径"随时召回）

对应 SOTA：CAI 的 ``/compact``、EnIGMA 的 session memory / scratchpad
（见 ``2027-prep/差异分析-SOTA对比-20260928.md`` 第 G5 项）。

设计约束（与 G1 / 项目铁律一致）：
- **纯抽象、零 LLM 依赖**：语义压缩以可注入 ``callable`` 形式存在，默认 ``None`` 走规则式。
- **不烧 token**：规则式抽取/压缩零成本；仅当用户显式传入 ``llm_summarizer`` 才消耗模型。
- **不碰 KPI / 账本 / 治理闸门**：本模块只管"记忆怎么存、怎么压、怎么找"，不读任何 KPI 文件。
- **不伪造**：抽取器只搬运命令的真实输出，绝不生成/猜测 flag。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from core.session import CommandRecord  # noqa: E402

_FLAG_RE = re.compile(r"flag\{[^}]*\}")
_PATH_RE = re.compile(r"(?:/[\w.\-]+)+\.\w+|\b[\w.\-]+\.(?:py|txt|bin|pem|c|cpp|elf|exe|json|xml|csv|log)\b")
_ERR_RE = re.compile(r"(?i)(error|exception|traceback|segfault|no such file|permission denied|invalid|failed|denied|core dumped)")


@dataclass
class Fact:
    """从一条命令输出里抽取出的关键事实。"""

    kind: str          # "flag" | "path" | "error" | "cmd" | "info"
    text: str
    step: int          # 来自第几步（1-based）
    ts: str = ""

    def __str__(self) -> str:
        return f"[{self.kind}@{self.step}] {self.text}"


def _extract_facts(rec: CommandRecord, step: int) -> list[Fact]:
    """规则式事实抽取：只搬运命令的真实输出，绝不猜测/生成。"""
    facts: list[Fact] = []
    out = (rec.stdout or "") + (rec.stderr or "")
    ts = rec.ts

    for m in _FLAG_RE.finditer(out):
        facts.append(Fact("flag", m.group(0), step, ts))
    for m in _PATH_RE.finditer(out):
        facts.append(Fact("path", m.group(0), step, ts))
    for line in out.splitlines():
        if _ERR_RE.search(line):
            facts.append(Fact("error", line.strip()[:300], step, ts))
    # 命令本身作为可检索事实（证明"我做过什么"）
    facts.append(Fact("cmd", rec.cmd, step, ts))
    return facts


class SessionMemory:
    """一个会话的压缩记忆层。

    典型用法（赛道 A 抽象，不接活环境）：
        mem = SessionMemory("real_crypto_x")
        mem.add(session.history[0])          # 逐步喂入命令记录
        mem.add(session.history[1])
        summary = mem.compact(keep_recent=5) # 长会话压缩成摘要
        hit = mem.retrieve("flag")           # 随时召回关键信息
    """

    def __init__(self, session_id: str = "default", llm_summarizer: Optional[Callable[[str], str]] = None) -> None:
        self.session_id = session_id
        self.llm_summarizer = llm_summarizer  # 可选语义压缩器（默认 None = 规则式）
        self.raw_history: list[CommandRecord] = []
        self.facts: list[Fact] = []

    # ── 写入 ────────────────────────────────────────────────
    def add(self, rec: CommandRecord) -> list[Fact]:
        """消费一条命令记录，抽取事实并追加。返回本次新增的事实。"""
        step = len(self.raw_history) + 1
        new_facts = _extract_facts(rec, step)
        self.raw_history.append(rec)
        self.facts.extend(new_facts)
        return new_facts

    def from_session(self, session) -> "SessionMemory":
        """从已有 ``Session`` 构建记忆（消费其 history）。"""
        for rec in session.history:
            self.add(rec)
        return self

    # ── 压缩 ────────────────────────────────────────────────
    def compact(self, keep_recent: int = 10, keep_flag: bool = True,
                keep_error: bool = True, llm: Optional[Callable[[str], str]] = None) -> str:
        """生成压缩态会话摘要（供 planner 注入上下文）。

        - 保留最近 ``keep_recent`` 条完整历史；
        - 旧历史中命中"关键事实"（flag/error，按开关）的 step 保留摘要；
        - 其余旧 step 丢弃（规则式压缩，零 token）；
        - 若传入 ``llm``（或构造时的 ``llm_summarizer``），对已丢弃的旧 step 做语义摘要
          （仅在用户显式要求时消耗模型）。
        """
        n = len(self.raw_history)
        if n == 0:
            return f"# Memory {self.session_id} (empty)"

        llm_fn = llm or self.llm_summarizer
        recent_start = max(0, n - keep_recent)
        lines = [f"# Memory {self.session_id} (steps={n}, compacted)"]

        # 关键事实索引（先于压缩，保证可检索）
        if keep_flag:
            for f in self.facts:
                if f.kind == "flag":
                    lines.append(f"KEY_FACT {f}")
        if keep_error:
            for f in self.facts:
                if f.kind == "error":
                    lines.append(f"KEY_FACT {f}")

        # 旧历史（非最近）：保留命中关键事实的 step 摘要；否则丢弃（或 LLM 摘要）
        for i, rec in enumerate(self.raw_history[:recent_start], 1):
            step_facts = [f for f in self.facts if f.step == i and f.kind in ("flag", "error")]
            if step_facts:
                lines.append(f"## (old) step {i} kept: {'; '.join(str(x) for x in step_facts)}")
            elif llm_fn is not None:
                summary = llm_fn(rec.cmd + "\n" + (rec.stdout or "")[:800])
                lines.append(f"## (old) step {i} summary: {summary[:300]}")
            # 否则：丢弃（规则式压缩默认行为）

        # 最近历史：完整保留（但每步输出截断）
        for i, rec in enumerate(self.raw_history[recent_start:], recent_start + 1):
            out = (rec.stdout or "") + (rec.stderr or "")
            if len(out) > 1200:
                out = "...[truncated]...\n" + out[-1200:]
            lines.append(f"## step {i} $ {rec.cmd} (rc={rec.returncode})")
            lines.append(out.rstrip())

        return "\n".join(lines)

    # ── 检索 ────────────────────────────────────────────────
    def retrieve(self, query: str, top_k: int = 5, kinds: Optional[set[str]] = None) -> list[Fact]:
        """在全部抽取事实里按子串/关键词匹配召回（不区分大小写）。"""
        q = query.lower()
        hits = [
            f for f in self.facts
            if q in f.text.lower() and (kinds is None or f.kind in kinds)
        ]
        # 靠后 step 的事实优先（更可能相关）
        return sorted(hits, key=lambda f: f.step, reverse=True)[:top_k]

    def get_summary(self) -> str:
        """返回压缩态纯文本摘要（默认 keep_recent=10，规则式，零 token）。"""
        return self.compact()

    def fact_count(self) -> int:
        return len(self.facts)

    def step_count(self) -> int:
        return len(self.raw_history)
