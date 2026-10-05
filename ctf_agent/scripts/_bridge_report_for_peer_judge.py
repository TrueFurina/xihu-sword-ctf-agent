#!/usr/bin/env python3
"""把本项目 benchmark 报告转成 SecAutoMind 判定器的输入格式（互操作桥，2026-10-06）。

为什么需要
----------
SecAutoMind 的 `external_westlake/judge_external_westlake.py` 吃的是
`{"<qid>": "flag{...}" 或 ["a","b"]}`；而本项目的 `eval.benchmark` 产出的是
`benchmark_report.json`（含 question_id / solved / flag 等字段）。两者字段名不同，
直接喂会判 0——这正是"口径对接处最容易静默失真"的地方，故显式写桥并在转换时
**保留未解出题**（只解出题会让命中率虚高，judge 的分母必须与跑批一致）。

用法
----
  python scripts/_bridge_report_for_peer_judge.py \
      --report data/results/L2_pure_llm_20261006/benchmark_report.json \
      --out data/results/L2_pure_llm_20261006/results_for_peer_judge.json
  # 然后
  python "E:/Program/2026挑战杯：SecAutoMind-v1.7.17-share/data/ctf_benchmark/external_westlake/judge_external_westlake.py" \
      --results data/results/L2_pure_llm_20261006/results_for_peer_judge.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def bridge(report_path: Path) -> dict:
    rep = json.loads(report_path.read_text(encoding="utf-8"))
    out: dict[str, list[str]] = {}
    for r in rep.get("results", []):
        qid = str(r.get("question_id") or "")
        if not qid:
            continue
        flag = (r.get("flag") or "").strip()
        # 未解出的题也必须占位（空列表）：否则 judge 的分母会缩小，命中率虚高
        out[qid] = [flag] if flag else []
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="转成本项目报告→对方判定器输入")
    ap.add_argument("--report", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    data = bridge(Path(args.report))
    Path(args.out).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    solved = sum(1 for v in data.values() if v)
    print(f"[bridge] 题目 {len(data)}｜本地产出 flag 的 {solved} 题｜空占位 {len(data)-solved} 题")
    print(f"[bridge] 已写出 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
