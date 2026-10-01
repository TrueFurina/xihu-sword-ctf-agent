"""求解器头对头对比：把 presolve 审计与朴素基线的 JSON 对齐，算集合差。

为什么需要它 —— 只看各自命中率会误读：
  「presolve 74/92、grep 62/92」看起来只是 +12，但真正要看的是**是不是同一批题**。
  本脚本把两解的命中集合拆成「都中 / A独中 / B独中 / 都不中」，
  只有 A独中 才是「分析带来的净增量」，B独中 是「分析漏了、grep 反而能中」的反例。

零成本（纯读 JSON 做集合运算）。

用法：
    python scripts/_compare_solvers.py \
        --presolve ../logs/presolve_audit_internal92_20261001.json \
        --baseline ../logs/baseline_naive_internal92_20261001.json \
        --label 内部92 --json ../logs/compare_internal92.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load_presolve(path: str) -> dict[str, bool]:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    # `_presolve_audit.py` 用 with_answers_verdict == 'TRUE' 表示真命中
    return {r["id"]: (r.get("with_answers_verdict") == "TRUE") for r in d["rows"]}


def _load_baseline(path: str) -> dict[str, bool]:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return {r["id"]: bool(r.get("hit_any")) for r in d["rows"]}


def compare(pres_path: str, base_path: str, label: str) -> dict:
    ps = _load_presolve(pres_path)
    ns = _load_baseline(base_path)
    ids = sorted(set(ps) | set(ns))
    a = {i for i in ids if ps.get(i)}
    b = {i for i in ids if ns.get(i)}
    both, only_a, only_b = a & b, a - b, b - a
    neither = set(ids) - a - b
    out = {
        "label": label, "n": len(ids),
        "presolve_hits": len(a), "baseline_hits": len(b),
        "both": sorted(both), "presolve_only": sorted(only_a),
        "baseline_only": sorted(only_b), "neither": sorted(neither),
        "net_analysis_gain": len(only_a) - len(only_b),
    }
    print(f"### {label}  n={len(ids)}")
    print(f"  presolve {len(a)} | 朴素基线 {len(b)} | 都中 {len(both)} | "
          f"presolve独中 {len(only_a)} | 基线独中 {len(only_b)} | 都不中 {len(neither)}")
    print(f"  → 净增量（presolve独中 − 基线独中）= {out['net_analysis_gain']:+d}")
    if only_a:
        print(f"  🔵 presolve 独中: {', '.join(sorted(only_a))}")
    if only_b:
        print(f"  🟡 基线独中(分析漏了): {', '.join(sorted(only_b))}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--presolve", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--label", default="")
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    out = compare(args.presolve, args.baseline, args.label or args.presolve)
    if args.json:
        Path(args.json).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print("->", args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
