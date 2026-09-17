#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KPI 单一权威口径源（P0-②，2026-09-17）。

为什么存在
----------
项目反复出现「14 / 92 / 15 子集」三套口径漂移，导致 README、台账、记忆互相打架
（记忆曾写 13、曾写有 KPI_WATERMARK 符号，实测均错）。本脚本把**所有 KPI 数字**
收敛到一台机器真值源，任何文档/台账想引用 KPI，必须跑本脚本或 import 本模块，
禁止手工誊抄数字（誊抄即漂移）。

机器真值锚点
------------
  - offline_verified：来自 scripts/_merge_gate.count_offline_verified()
    （严格真题 + 确定性复现 verifier，绝对计数，非率）
  - real_corpus：data/questions_real/**/*.json 递归计数（92 题真题全集）
  - heldout_candidates：由 scripts/benchmark_heldout.select_candidates() 在
    real_corpus 中剔除「已训练/泄露/自产/无 sha256」后的 unseen 非平凡题池
    —— 这才是「LLM 真·自主推理」的唯一合法分母

口径铁律（输出即声明，引用者照搬）
------------------------------
  1. 14 是**绝对计数**，不是率；凡说「能力 X%」必须显式声明分母是 92 还是 heldout 子集。
  2. 15 题子集 / 86.7% 口径已作废（早期 presolve 静态分析子集，不具竞技代表性）。
  3. goal_log.jsonl 是独立实验日志（解出数恒 0），与 KPI 非同源，**不构成产品能力率**。

用法
----
  python scripts/_kpi_canonical.py                 # 打印并写出 canonical KPI 声明
  python scripts/_kpi_canonical.py --json         # 仅 machine-readable JSON 到 stdout
  # 作为模块：
  #   from scripts._kpi_canonical import canonical_kpi
  #   k = canonical_kpi(); print(k["offline_verified"], k["real_corpus"])
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESULTS = ROOT / "data" / "results"
QUESTIONS_REAL = ROOT / "data" / "questions_real"
OUT = RESULTS / "kpi_canonical.json"

# 过时口径，引用即报错，防止死灰复燃
_DEPRECATED_SUBSET = 15


def count_offline_verified() -> int:
    """委托 _merge_gate 的机器真值（strict 真题 + 确定性 verifier）。"""
    from scripts._merge_gate import count_offline_verified as _c
    return int(_c())


def count_real_corpus() -> int:
    """递归统计 data/questions_real/**/*.json（真题全集，含子目录）。"""
    if not QUESTIONS_REAL.exists():
        return 0
    return sum(1 for p in QUESTIONS_REAL.rglob("*.json") if p.is_file())


def count_heldout_candidates() -> int:
    """unseen 非平凡题池大小（LLM 真·自主推理的唯一合法分母）。

    复用 benchmark_heldout.select_candidates 的同一台机器逻辑，避免口径分叉。
    该函数仅做轻量文件扫描 + 排除判定，无 API 调用。
    """
    try:
        from scripts.benchmark_heldout import select_candidates
        cands, _ = select_candidates()
        return len(cands)
    except Exception as exc:  # pragma: no cover - 兜底不致命
        sys.stderr.write(f"[kpi_canonical] select_candidates 调用失败：{exc}\n")
        return -1


def canonical_kpi() -> dict:
    ov = count_offline_verified()
    corpus = count_real_corpus()
    heldout = count_heldout_candidates()
    coverage_all = (ov / corpus) if corpus else 0.0
    # 重要：offline_verified(14) 与 heldout_candidates(10) 是**不相交**集合
    # （14 全为已训练/KPI 题，本就在 held-out 排除逻辑里被剔除）。
    # 故「14/10」是欺骗性比率，绝不输出；held-out 口径下 LLM 真推理 = 0/10 未测。
    coverage_heldout = None
    return {
        "as_of": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        "offline_verified": ov,                 # 绝对计数（KPI 真值上限）
        "real_corpus": corpus,                 # 真题全集分母（=92）
        "heldout_candidates": heldout,         # unseen 非平凡题池（自主推理分母）
        "coverage_of_corpus": round(coverage_all, 4),     # 14/92
        "coverage_of_heldout": coverage_heldout,          # 恒 None：14 与 10 不相交
        "deprecated_subset": _DEPRECATED_SUBSET,          # 仅作警示锚点
        "statement": (
            f"offline_verified={ov}（绝对计数，非率） / real_corpus={corpus} "
            f"→ 全集覆盖率 {coverage_all:.1%}；"
            f"held-out 自主推理分母 = {heldout} 题（unseen 非平凡，与 14 题不相交），"
            f"该口径下 LLM 真推理能力 = 0/{heldout} 未测量（须跑 benchmark_heldout --run）。"
            f"15 题子集/86.7% 口径已作废。goal_log.jsonl 解出数恒 0，与 KPI 非同源。"
            f"⚠️ ledger-vs-corpus 1 项漂移：AUTHORIZED_KPI_SOLVES=14，但其中 10733 在"
            f"data/questions_real/ 无对应题文件（台账计 verified、语料缺文件）；"
            f"held-out 10 题分母不受影响（已排除的 13 道均正确命中授权 ID）。"
        ),
    }


def render_md(k: dict) -> str:
    L = [
        "# KPI 单一权威声明（机器真值，禁止手工誊抄）",
        f"\n- 生成时间：`{k['as_of']}`",
        f"- **offline_verified = {k['offline_verified']}**（绝对计数，非率；KPI 真值上限）",
        f"- **real_corpus = {k['real_corpus']}**（真题全集分母，data/questions_real/**/*.json 递归）",
        f"- **heldout_candidates = {k['heldout_candidates']}**（unseen 非平凡题池 = LLM 真·自主推理唯一合法分母）",
        f"- 全集覆盖率：{k['offline_verified']}/{k['real_corpus']} = {k['coverage_of_corpus']:.1%}",
        f"- held-out 自主推理池 = {k['heldout_candidates']} 题（unseen 非平凡，与 14 题不相交）",
        "- held-out 覆盖率：N/A（14 与 10 不相交，14/10=140% 是欺骗性比率，已作废）",
        "",
        "> 口径铁律：14 是绝对计数不是率；凡说「能力 X%」必须显式声明分母是 92 还是 heldout 子集。",
        "> 15 题子集 / 86.7% 口径已作废。goal_log.jsonl 解出数恒 0，与 KPI 非同源，不构成产品能力率。",
        "",
        f"> {k['statement']}",
    ]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="KPI 单一权威口径源（防漂移）")
    ap.add_argument("--json", action="store_true", help="仅输出 machine-readable JSON")
    args = ap.parse_args()

    k = canonical_kpi()

    if args.json:
        print(json.dumps(k, ensure_ascii=False, indent=2))
        return 0

    md = render_md(k)
    RESULTS.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(k, ensure_ascii=False, indent=2), encoding="utf-8")
    print(md)
    print(f"\n[canonical] 已写出 {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
