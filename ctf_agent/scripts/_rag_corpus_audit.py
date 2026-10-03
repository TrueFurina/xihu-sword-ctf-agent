"""_rag_corpus_audit：RAG 语料审计（P2 第四刀——RAG 抗幻觉的护栏验证，2026-10-03）。

审计两件事（零依赖、只读、不改语料）：
1. **held-out 泄漏审计（红线）**：knowledge/writeups_corpus.jsonl 不得含外部池
   （data/questions_external/ 41 跑池 + data/questions_ext/ NYU 池）题目的
   题名/描述特征串/flag 值——语料混入 held-out 解法 = 评测污染，比没有 RAG 更糟。
2. **台账对齐报告**：台账 offline_verified（A/B 类）题名 vs 语料 verified 条目，
   报告覆盖 gap（只报告，不自动补——解法摘要须真实攻击链背书，禁编造）。

用法：.venv/Scripts/python.exe scripts/_rag_corpus_audit.py
退出码：0=无泄漏（无论 gap 多少）；1=发现泄漏（fail-closed）。
"""

from __future__ import annotations

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

CORPUS = os.path.join(ROOT, "knowledge", "writeups_corpus.jsonl")
LEDGER = os.path.join(ROOT, "REAL_SOLVES_LEDGER.md")

# 特征串最小长度（短于该长度的 token 误报率高，跳过）
MIN_TOKEN_LEN = 5
# 描述特征串取样长度
DESC_SAMPLE = 100


def _load_corpus() -> list:
    items = []
    with open(CORPUS, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
                items.append((i, j))
            except Exception as exc:
                print(f"⚠️ 语料第 {i} 行 JSON 解析失败: {exc}")
    return items


def _collect_holdout_pools() -> dict:
    """收集两外部池的每题特征：{id: {"title":…, "desc":…, "flag":…}}。"""
    pools = {}
    for pat in ("data/questions_external/**/*.json", "data/questions_ext/**/*.json"):
        for p in glob.glob(os.path.join(ROOT, pat), recursive=True):
            if not p.endswith(".json"):
                continue
            try:
                j = json.load(open(p, encoding="utf-8"))
            except Exception:
                continue
            tid = str(j.get("id") or "")
            if not tid:
                continue
            pools[tid] = {
                "pool": "external41" if "questions_external" in p else "nyu",
                "title": str(j.get("title") or ""),
                "desc": str(j.get("description") or "")[:DESC_SAMPLE],
                "flag": str(j.get("flag") or ""),
            }
    return pools


def _significant_tokens(text: str) -> set:
    """提取显著 token（≥MIN_TOKEN_LEN 的字母数字连续段，小写化）。"""
    import re
    return {t.lower() for t in re.findall(r"[A-Za-z0-9_\-]{%d,}" % MIN_TOKEN_LEN, text or "")}


def audit_leak(corpus: list, pools: dict) -> list:
    """对每条语料 × 每道外部题做三层比对：题名 / 描述特征 token / flag 值。"""
    leaks = []
    for lineno, item in corpus:
        text = json.dumps(item, ensure_ascii=False).lower()
        for tid, info in pools.items():
            # ① 题名全串（非空且足够长才比）
            t = info["title"].strip().lower()
            if len(t) >= MIN_TOKEN_LEN and t in text:
                leaks.append((lineno, tid, info["pool"], f"题名命中: {t}"))
                continue
            # ② 描述显著 token 覆盖率（≥60% 命中视为疑似同题）
            dtoks = _significant_tokens(info["desc"])
            if len(dtoks) >= 4:
                hit = sum(1 for tok in dtoks if tok in text)
                if hit / len(dtoks) >= 0.6:
                    leaks.append((lineno, tid, info["pool"],
                                  f"描述特征 token 命中 {hit}/{len(dtoks)}"))
                continue
            # ③ flag 值（外部题基本无真值，有则强比对）
            fl = info["flag"].strip().lower()
            if len(fl) >= 8 and fl in text:
                leaks.append((lineno, tid, info["pool"], f"flag 值命中: {fl}"))
    return leaks


def ledger_verified_titles() -> list:
    """台账 offline_verified（A/B 类）题名（复用 _merge_gate 分类规则）。"""
    from scripts._merge_gate import _classify_entry
    titles, cur = [], None
    if not os.path.isfile(LEDGER):
        return titles
    with open(LEDGER, encoding="utf-8") as f:
        for line in f:
            if line.startswith("### "):
                cur = line
            elif cur and "- **状态**" in line and "✅ offline_verified" in line:
                if _classify_entry(cur) in ("A", "B"):
                    titles.append(cur[4:].strip())
    return titles


def main() -> int:
    corpus = _load_corpus()
    pools = _collect_holdout_pools()
    print(f"语料条数: {len(corpus)} ｜ 外部池题数: {len(pools)}"
          f"（external41 + nyu）")

    # ── 1. 泄漏审计 ──
    leaks = audit_leak(corpus, pools)
    if leaks:
        print(f"\n❌ 发现 {len(leaks)} 处 held-out 泄漏（fail-closed）：")
        for lineno, tid, pool, why in leaks[:20]:
            print(f"  语料#{lineno} × {pool}:{tid} — {why}")
        print("\n处置：立即从语料移除对应条目（评测污染红线）。")
        return 1
    print("✅ 泄漏审计通过：语料与两外部池零交集（题名/描述特征/flag 三层比对）")

    # ── 2. 台账对齐报告 ──
    verified = ledger_verified_titles()
    corpus_verified = [
        str(item.get("source") or "") for _, item in corpus
        if str(item.get("source") or "").startswith("verified:")
    ]
    print(f"\n台账 offline_verified（A/B 类）: {len(verified)} 题")
    print(f"语料 verified 条目: {len(corpus_verified)} 条")
    # 语料 source 形如 "verified: exciting_inverse"——报告式对齐（题名形态不同，人工核）
    print("语料 verified 来源:", sorted(set(corpus_verified)))
    print("\n（对齐说明：台账题名与语料 source 命名形态不同，此报告供人工核对；")
    print("  补齐原则——新条目必须有真实攻击链脚本背书，禁编造解法摘要。）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
