"""题库口径统一层：可测性判定 + 跨库择优去重。

起因（2026-10-07）：能力兑现审计发现三类口径污染——
  ① 同一 id 在多个 data/questions* 目录下有副本，质量不齐；
     按「先到先得」去重会选中附件失效的坏副本，制造「能力未兑现」假象。
  ② 部分题目的附件指向已失效路径（仓库外的绝对路径 / 已被清理的
     data/attachments/），题目本身是 **input-less**——跑必然 0 分，
     属数据缺失，**不是**能力缺失，必须从 KPI 分母剔除。
  ③ 此前 NO_INPUT / no_truth 判定散落在 5+ 个一次性脚本里各自实现，
     口径不一致且无法复用（见 scripts/_online_ctf_validate.py、
     _bench_adapter.py、_scan_kpi_candidates.py 等）。

本模块把这三件事收敛为**单一真相源**，供评测 / 审计脚本共同调用。
纯本地判定，**零 LLM 成本**。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence

from eval.cases import load_questions

__all__ = [
    "AttachmentHealth",
    "CorpusEntry",
    "DEFAULT_ROOTS",
    "attachment_health",
    "has_input",
    "has_truth",
    "measurable",
    "fitness_score",
    "load_corpus",
    "corpus_report",
    "partition_measurable",
    "skip_reason",
    "apply_corpus_gate",
    "applicable_corpus_summary",
]

# 全仓题库目录（择优去重时的默认扫描范围）
DEFAULT_ROOTS: tuple[str, ...] = (
    "data/questions_real",        # 真赛题主库（质量最好，放首位）
    "data/questions_external",    # 外部公开池
    "data/questions_ext",
    "data/questions",             # 历史默认库，含大量失效副本，放末位
)


@dataclass(frozen=True)
class AttachmentHealth:
    """一道题附件的可用度快照。"""

    declared: int          # JSON 里登记的附件数
    existing: int          # 磁盘上真实存在的附件数
    missing: tuple = field(default_factory=tuple)  # 缺失的附件路径

    @property
    def ratio(self) -> float:
        """存在比例（无附件登记时记 1.0——纯文本题不因此被判不可测）。"""
        return 1.0 if self.declared == 0 else self.existing / self.declared


@dataclass(frozen=True)
class CorpusEntry:
    """去重后的一道 Unique 题目，携带溯源与可测性标记。"""

    question: Any
    source: str                      # 选中副本所在的数据集目录
    health: AttachmentHealth
    superseded: tuple = field(default_factory=tuple)  # 被它淘汰的其他副本所在目录


def attachment_health(q: Any) -> AttachmentHealth:
    """统计题目附件的磁盘可用情况（唯一的真理口径）。"""
    declared = list(getattr(q, "attachments", None) or [])
    existing, missing = [], []
    for a in declared:
        # pathlib.Path / str 一律转 str 后判定，覆盖两种形态
        if os.path.isfile(str(a)):
            existing.append(a)
        else:
            missing.append(str(a))
    return AttachmentHealth(
        declared=len(declared), existing=len(existing), missing=tuple(missing))


def has_input(q: Any) -> bool:
    """是否有可解题的输入。

    判定：登记了附件但一个都不存在 → 无输入（input-less，必然 0 分）。
    未登记附件（纯文本题，信息在 description 里）→ 视为有输入。
    """
    return attachment_health(q).existing > 0 or attachment_health(q).declared == 0


def has_truth(q: Any) -> bool:
    """是否有可校验真值。

    真值形态二选一：
      - flag_sha256（真 flag 红线后的推荐形态）
      - flag 明文（本地旧题仍在用，比对时 flag 入 git 属例外但确实是真值）
    只有 flag_pattern 而无任一真值 → **不可校验**（格式对 ≠ 内容对）。
    """
    return bool(getattr(q, "flag_sha256", None) or getattr(q, "flag", None))


def measurable(q: Any) -> bool:
    """能否作为一道有效计入 KPI 分母的题：有输入 **且** 有真值。"""
    return has_input(q) and has_truth(q)


def fitness_score(q: Any) -> tuple:
    """副本择优打分（元组越大越优，按字典序比较）。

    只比 **客观可验证** 的两项：附件可用数 > 有真值。
    ⚠️ 刻意 **不** 用 description 长度做 tie-break（2026-10-07 修正）：
    实测会让 data/questions（坏库）凭更长的题面描述淘汰
    data/questions_real（好库）的同附件数副本。打分相同时一律
    **保留 DEFAULT_ROOTS 中靠前的库**（roots 顺序即质量优先级）。
    改动本函数前请同步 tests/test_corpus_measurability.py。
    """
    h = attachment_health(q)
    return (h.existing, int(has_truth(q)))


def skip_reason(q: Any) -> Optional[str]:
    """返回该题应从跑批中剔除的原因，可跑则返回 None。

    两类缺陷都属**数据缺失**，不是能力缺失：
      - ``"no_input"``：登记了附件但磁盘上一个都不存在（input-less）。
        跑必然空转烧满预算再失败，直接跳过可省下真跑批 token。
      - ``"no_truth"``：无 flag_sha256 也无 flag 明文，解出也无法校验，
        计入分母只会制造不可复核的分数。
    """
    if not has_input(q):
        return "no_input"
    if not has_truth(q):
        return "no_truth"
    return None


def partition_measurable(questions: Iterable[Any]) -> tuple:
    """把题目分成「可跑」与「应剔除」两组（纯函数，便于单测）。

    Returns:
        (keep, skipped)：keep 为可跑题列表；
        skipped 为 [(question, reason)]，reason 见 skip_reason()。
    """
    keep, skipped = [], []
    for q in questions or []:
        reason = skip_reason(q)
        if reason:
            skipped.append((q, reason))
        else:
            keep.append(q)
    return keep, skipped


def apply_corpus_gate(questions: Iterable[Any],
                      include_unmeasurable: bool = False) -> tuple:
    """评测入库闸门：按可测性过滤题目（纯函数，CLI 与测试共用）。

    Args:
        questions: 原始题目列表。
        include_unmeasurable: True 则原样返回（对照测量用）。

    Returns:
        (keep, unmeasurable, raw_n)：
        keep=参与跑批的题；unmeasurable=[(q, reason)]；raw_n=原始题数。
    """
    raw = list(questions or [])
    keep, unmeasurable = partition_measurable(raw)
    if include_unmeasurable:
        return raw, unmeasurable, len(raw)
    return keep, unmeasurable, len(raw)


def applicable_corpus_summary(unmeasurable: Sequence[tuple]) -> dict:
    """把 [(q, reason)] 汇总成 {reason: count}（供日志/报告打印）。"""
    out: dict = {}
    for _q, reason in unmeasurable or []:
        out[reason] = out.get(reason, 0) + 1
    return out


def load_corpus(roots: Optional[Sequence[str]] = None,
                dedup: bool = True,
                verbose: bool = False
                ) -> list[CorpusEntry]:
    """跨数据集加载题库，按 id 去重并**择优保留最健康的副本**。

    Args:
        roots: 题库目录列表，默认 DEFAULT_ROOTS。
        dedup: 是否去重（False 则每个副本独立成条目，用于副本质量审计）。
        verbose: 打印被淘汰副本的提示。

    Returns:
        CorpusEntry 列表，按 roots 顺序 + 目录内原顺序排列。
    """
    chosen: dict[str, CorpusEntry] = {}
    for d in (roots if roots is not None else DEFAULT_ROOTS):
        try:
            qs = load_questions(d)
        except Exception as exc:  # noqa: BLE001
            if verbose:
                print("[skip] %s: %s" % (d, exc))
            continue
        for q in qs or []:
            key = getattr(q, "id", None) or getattr(q, "title", None)
            if key is None:
                continue
            entry = CorpusEntry(question=q, source=d,
                                health=attachment_health(q))
            if not dedup:
                chosen.setdefault(("#%d" % len(chosen)), entry)
                continue
            prev = chosen.get(key)
            if prev is None:
                chosen[key] = entry
                continue
            if fitness_score(q) > fitness_score(prev.question):
                if verbose:
                    print("[dedup] %s: %s(%d/%d 附件) 淘汰 %s(%d/%d)" % (
                        key, d, entry.health.existing, entry.health.declared,
                        prev.source, prev.health.existing, prev.health.declared))
                # frozen dataclass 不可改，统一构造新条目承载淘汰记录
                chosen[key] = CorpusEntry(
                    question=q, source=d, health=entry.health,
                    superseded=prev.superseded + (prev.source,))
            else:
                chosen[key] = CorpusEntry(
                    question=prev.question, source=prev.source,
                    health=prev.health, superseded=prev.superseded + (d,))
    return list(chosen.values())


def corpus_report(entries: Iterable[CorpusEntry]) -> dict:
    """产出分层报告：多少题真正可计入 KPI 分母。"""
    entries = list(entries)
    rows = []
    for e in entries:
        rows.append({
            "id": getattr(e.question, "id", ""),
            "source": e.source,
            "category": getattr(e.question, "category", ""),
            "provenance": getattr(e.question, "provenance", ""),
            "declared": e.health.declared,
            "existing": e.health.existing,
            "has_input": has_input(e.question),
            "has_truth": has_truth(e.question),
            "measurable": measurable(e.question),
        })
    total = len(rows)
    no_input = [r for r in rows if not r["has_input"]]
    no_truth = [r for r in rows if not r["has_truth"]]
    ok = [r for r in rows if r["measurable"]]
    real = [r for r in rows if r["provenance"] == "real_past_ctf"]
    real_ok = [r for r in real if r["measurable"]]
    return {
        "total": total,
        "measurable": len(ok),
        "unmeasurable": total - len(ok),
        "no_input": len(no_input),
        "no_truth": len(no_truth),
        "real_past_ctf_total": len(real),
        "real_past_ctf_measurable": len(real_ok),
        "rows": rows,
    }
