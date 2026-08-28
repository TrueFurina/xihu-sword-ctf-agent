"""Block 2 并发效率聚合：对比不同 --concurrency 的真实跑批吞吐。

用法：
    python -m scripts.block2_report \
        --serial  data/results/block2_c1/benchmark_report.json \
        --parallel data/results/block2_c4/benchmark_report.json \
        --serial-wallclock 120.5 --parallel-wallclock 41.3

说明：
- 报告 JSON 不存总墙钟，墙钟由外层 `Measure-Command` 实测传入（秒）。
- 吞吐 = 题数 / 墙钟秒；speedup = serial_wallclock / parallel_wallclock。
- KPI 仅取 by_provenance.real_past_ctf（自产训练题不计分）。
- 结论均可复现：同 questions-dir + 同 seed/provider + 同 wallclock 重跑即得。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load(p: str) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def _kpi(summary: dict) -> dict:
    bp = summary.get("by_provenance", {})
    rp = bp.get("real_past_ctf", {})
    return {
        "total": rp.get("total", summary.get("total", 0)),
        "solved": rp.get("solved", 0),
        "solve_rate": rp.get("solve_rate", summary.get("solve_rate", 0.0)),
    }


def _row(name: str, report_path: str, wallclock_s: float) -> dict:
    rep = _load(report_path)
    summary = rep.get("summary", {})
    total = summary.get("total", 0)
    kpi = _kpi(summary)
    tokens = summary.get("tokens", {})
    tok_total = tokens.get("global_total") if isinstance(tokens, dict) else None
    throughput = (total / wallclock_s * 3600.0) if wallclock_s > 0 else 0.0
    return {
        "name": name,
        "concurrency": rep.get("mode"),
        "total": total,
        "solved": summary.get("solved", 0),
        "solve_rate": summary.get("solve_rate", 0.0),
        "kpi_total": kpi["total"],
        "kpi_solved": kpi["solved"],
        "kpi_solve_rate": kpi["solve_rate"],
        "wallclock_s": round(wallclock_s, 1),
        "throughput_q_per_h": round(throughput, 1),
        "tokens_total": tok_total,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", required=True)
    ap.add_argument("--parallel", required=True)
    ap.add_argument("--serial-wallclock", type=float, required=True)
    ap.add_argument("--parallel-wallclock", type=float, required=True)
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    s = _row("serial(c=1)", args.serial, args.serial_wallclock)
    p = _row("parallel", args.parallel, args.parallel_wallclock)

    speedup = (s["wallclock_s"] / p["wallclock_s"]) if p["wallclock_s"] > 0 else 0.0
    print("=== Block 2 并发效率（真实链路，可引用）===")
    if args.label:
        print(f"标签: {args.label}")
    for r in (s, p):
        print(f"  [{r['name']}] 题数={r['total']} 解出={r['solved']}({r['solve_rate']}) "
              f"KPI(real)={r['kpi_solved']}/{r['kpi_total']}({r['kpi_solve_rate']}) "
              f"墙钟={r['wallclock_s']}s 吞吐={r['throughput_q_per_h']}题/时 "
              f"tokens={r['tokens_total']}")
    print(f"  → 墙钟加速比 speedup = {round(speedup, 2)}x "
          f"(serial {s['wallclock_s']}s / parallel {p['wallclock_s']}s)")
    # 诚实判定：并发是否牺牲解出率
    if s["kpi_solved"] != p["kpi_solved"]:
        print(f"  ⚠️ 并发改变 KPI 解出数（serial {s['kpi_solved']} vs parallel {p['kpi_solved']}）"
              f"→ 需排查 MainAgent 共享竞态")
    else:
        print(f"  ✅ 并发未牺牲 KPI 解出率（{s['kpi_solved']}/{s['kpi_total']} 一致）")


if __name__ == "__main__":
    main()
