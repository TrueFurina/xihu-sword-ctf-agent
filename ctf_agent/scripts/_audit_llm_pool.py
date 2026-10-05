#!/usr/bin/env python3
"""LLM 评测池「真值来源 + 跨基准重叠」审计（跨项目支持 · 2026-10-05）。

为什么存在
----------
SecAutoMind 的 LLM 自主解题基线（`internal/ctfplatform/llm_autosolve_test.go`，
基线 6/13）在文档里写"13 个真实靶机、无专用求解器"。其中：
  - "真实靶机" = 真 HTTP 靶机（httptest 起服务），这点属实；
  - 但题本身是**自建 web 题**（flag 形如 flag{live_*_ok}，题面 WEB-01..WEB-13），
    因此 6/13 **不是外部真题口径**，与"外部公开真题 19/55"是两个不同口径，不可混用。
本脚本把这件事从"人工声明"变成机器可核对的报告：
  1. 解析 newLiveCases()，取出每题 (id, title, flag)；
  2. 计算 flag 的 SHA-256，与仓库内各 benchmark（real_benchmark / external_* /
     任何带 flag_sha256 的题集）逐一比对 → 判定该题是「自建」还是「与某基准重叠」；
  3. 与 external_westlake 基准交叉：若评测池题目真值出现在外部基准里，说明
     分母可能被训练数据污染 → 红线。
  4. 顺带核对池内 id 是否唯一、flag 是否重复（重复=同一答案复用，会虚高命中率）。

诚实边界（必须写进报告，避免过度解读）
  - 本脚本只能证明"真值是否同源/是否重叠"，**不能**证明"某求解器一定不会做某题"
    （求解器与题目的覆盖关系是语义问题，静态不可判）；
  - "自建"判定基于真值是否命中任何外部基准，**不否认**这些题是有效的端到端
    HTTP 靶机测试——它只声明口径。

用法
----
  python scripts/_audit_llm_pool.py --target "E:/Program/2026挑战杯：SecAutoMind-v1.7.17-share"
  python scripts/_audit_llm_pool.py --target <repo> --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

CASE_RE = re.compile(
    r'id:\s*"(?P<id>[^"]+)"\s*,\s*title:\s*"(?P<title>[^"]+)"\s*,\s*flag:\s*"(?P<flag>[^"]+)"',
    re.DOTALL,
)
POOL_FILE = Path("internal/ctfplatform/live_target_test.go")


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _problems_of(doc) -> dict:
    if isinstance(doc, dict):
        for key in ("problems", "cases", "questions", "items"):
            v = doc.get(key)
            if isinstance(v, dict):
                return v
    return {}


def load_pool(target: Path) -> list[dict]:
    src = (target / POOL_FILE)
    if not src.is_file():
        return []
    text = src.read_text(encoding="utf-8", errors="ignore")
    out = []
    for m in CASE_RE.finditer(text):
        out.append({"id": m.group("id"), "title": m.group("title"),
                    "flag_sha256": sha(m.group("flag"))})
    return out


def index_benchmarks(target: Path) -> dict[str, list[str]]:
    """真值哈希 -> 出现该真值的基准文件列表"""
    root = target / "data" / "ctf_benchmark"
    index: dict[str, list[str]] = {}
    if not root.is_dir():
        return index
    for p in sorted(root.rglob("*.json")):
        if "all_benchmarks_summary" in p.name:
            continue
        try:
            probs = _problems_of(json.loads(p.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            continue
        for qid, item in probs.items():
            if isinstance(item, dict):
                s = str(item.get("flag_sha256") or "").strip().lower()
                if re.fullmatch(r"[0-9a-f]{64}", s):
                    index.setdefault(s, []).append(f"{p.parent.name}/{p.name}:{qid}")
    return index


def audit(target: Path) -> dict:
    pool = load_pool(target)
    index = index_benchmarks(target)
    rows, overlap = [], []
    ids, flags = set(), set()
    dup_id, dup_flag = [], []
    for c in pool:
        hits = index.get(c["flag_sha256"], [])
        row = dict(c, sha256=c["flag_sha256"][:12], origin=("overlap" if hits else "self_authored"),
                   matched=hits[:3])
        rows.append(row)
        if hits:
            overlap.append(row)
        if c["id"] in ids:
            dup_id.append(c["id"])
        ids.add(c["id"])
        if c["flag_sha256"] in flags:
            dup_flag.append(c["id"])
        flags.add(c["flag_sha256"])

    n = len(pool)
    report = {
        "target": str(target),
        "pool_file": str(POOL_FILE),
        "pool_size": n,
        "self_authored": n - len(overlap),
        "overlap_with_benchmarks": len(overlap),
        "duplicate_ids": dup_id,
        "duplicate_flags": dup_flag,
        "rows": rows,
        "verdict": {
            "denominator_is_external_truth": bool(n) and len(overlap) == n,
            "note": ("评测池全部与外部基准同源=外部真题口径" if n and len(overlap) == n
                     else "评测池含自建题：该成绩是端到端靶机口径，"
                          "不可与『外部公开真题』数字混用或相加"),
        },
    }
    report["all_green"] = (not overlap) and (not dup_id) and (not dup_flag)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="LLM 评测池真值来源与重叠审计")
    ap.add_argument("--target", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    target = Path(args.target)
    if not target.is_dir():
        print(f"[audit] 目标不存在: {target}")
        return 2
    rep = audit(target)
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        print(f"[audit] 评测池 {rep['pool_size']} 题（{POOL_FILE}）")
        print(f"  自建题: {rep['self_authored']}｜与仓库基准重叠: {rep['overlap_with_benchmarks']}")
        print(f"  重复 id: {len(rep['duplicate_ids'])}｜重复 flag: {len(rep['duplicate_flags'])}")
        print(f"  口径判定: {rep['verdict']['note']}")
        for r in rep["rows"]:
            print(f"    {r['id']:>6} {r['title']:<8} sha={r['sha256']} {r['origin']}"
                  + (f" {r['matched']}" if r["matched"] else ""))
        print(f"[audit] 结论: {'全绿' if rep['all_green'] else '存在红线（重叠/重复）'}")
    return 0 if rep["all_green"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
