"""干净口径对比：把「答案物理存在的题（泄漏）」从命中率里刨掉，再看两个解法的真实差距。

为什么需要它 —— 2026-10-01 复盘：
  朴素的「presolve 命中 74 / 基线命中 62」是不可解读的，因为题库里大量题目的
  真值 flag **物理上就躺在附件里**（本题库 68/92）。对这些题，任何工具「命中」
  都只等于 grep 成功，不含任何分析能力。

  于是本脚本把每道题按 _leak_provenance.py 的判定分档：
    att_leak / desc_leak   → 泄漏，从能力口径里剔除
    computed / unsolved    → 干净样本，纳入能力口径
  再在【干净样本】上重算 presolve / 基线的命中，才得到可解释的「确定性层实力」。

输入：三份 JSON（presolve 审计 / 朴素基线 / 答案来源）。
用法：
    python scripts/_clean_metric.py \
        --pool 内部92 --presolve ../logs/presolve_audit_internal92_20261001.json \
        --baseline ../logs/baseline_naive_internal92_20261001.json \
        --leak ../logs/leak_provenance_real92_20261001.json
零成本、纯本地。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(p: str) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def compute(pool: str, presolve: dict, baseline: dict, leak: dict) -> dict:
    pm = {r["id"]: (r.get("with_answers_verdict") == "TRUE") for r in presolve["rows"]}
    nm = {r["id"]: bool(r.get("hit_any")) for r in baseline["rows"]}
    prov = {r["id"]: r["provenance"] for r in leak["rows"]}
    ids = [r["id"] for r in leak["rows"]]

    leaky = [i for i in ids if prov.get(i) in ("att_leak", "desc_leak")]
    clean = [i for i in ids if prov.get(i) not in ("att_leak", "desc_leak")]

    return {
        "pool": pool,
        "n": len(ids),
        "att_leak": sum(1 for i in ids if prov.get(i) == "att_leak"),
        "desc_leak": sum(1 for i in ids if prov.get(i) == "desc_leak"),
        "clean": len(clean),
        "presolve_total": sum(pm.get(i, False) for i in ids),
        "presolve_clean": sum(pm.get(i, False) for i in clean),
        "baseline_total": sum(nm.get(i, False) for i in ids),
        "baseline_clean": sum(nm.get(i, False) for i in clean),
        "presolve_clean_ids": [i for i in clean if pm.get(i)],
        "baseline_clean_ids": [i for i in clean if nm.get(i)],
        "leaky_examples": leaky[:0],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", required=True)
    ap.add_argument("--presolve", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--leak", required=True)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    r = compute(args.pool, load(args.presolve), load(args.baseline), load(args.leak))
    print(f"### {r['pool']}  n={r['n']}")
    print(f"  泄漏: att_leak={r['att_leak']}  desc_leak={r['desc_leak']}  → 干净样本 {r['clean']}")
    print(f"  presolve: 全量 {r['presolve_total']}  | 干净集 {r['presolve_clean']}/{r['clean']}")
    print(f"  基线    : 全量 {r['baseline_total']}  | 干净集 {r['baseline_clean']}/{r['clean']}")
    if args.json:
        Path(args.json).write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  -> {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
