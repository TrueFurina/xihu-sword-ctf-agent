#!/usr/bin/env python3
"""解析 held-out 自主解题基准报告，产出可引用摘要（防人工誊写漂移）。

读取 data/results/heldout/benchmark_report.json，打印：
  - 总题数 / 解出 / 解出率
  - 按类别(by_category)、按解法来源(by_solved_by：presolve vs 主 Agent LLM)
  - 逐题明细（id / 类别 / solved / solved_by / flag或error / 耗时 / 重试）
并写出 data/results/heldout/SUMMARY.md。

用法：
  python scripts/summarize_heldout.py [--report PATH] [--out PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "data" / "results"
DEFAULT_REPORT = RESULTS / "heldout" / "benchmark_report.json"
DEFAULT_OUT = RESULTS / "heldout" / "SUMMARY.md"


def _short(v, n=48):
    s = str(v if v is not None else "")
    return s if len(s) <= n else s[: n - 1] + "…"


def summarize(report: dict) -> str:
    s = report.get("summary", {})
    total = s.get("total", 0)
    solved = s.get("solved", 0)
    rate = s.get("solve_rate", 0.0)
    lines = []
    lines.append("# Held-out 未见题自主解题基准 · 结果摘要\n")
    lines.append(f"- 口径(mode): `{report.get('mode')}`")
    lines.append(f"- 总题数: **{total}**　解出: **{solved}**　解出率: **{rate:.1%}**")
    lines.append("")

    bc = s.get("by_category", {})
    if bc:
        lines.append("## 按类别（solved/total, 解出率）")
        for cat, v in sorted(bc.items(), key=lambda kv: -kv[1].get("solve_rate", 0)):
            tot = v.get("total", 0)
            sv = v.get("solved", 0)
            rate = v.get("solve_rate", 0.0)
            lines.append(f"- {cat}: {sv}/{tot}（{rate:.1%}）　均耗时 {v.get('avg_duration_ms',0):.0f}ms　均重试 {v.get('avg_retries',0)}")
        lines.append("")

    bs = s.get("by_solved_by", {})
    if bs:
        lines.append("## 按解法来源（区分 presolve 确定性 vs 主 Agent LLM）")
        for src, v in sorted(bs.items(), key=lambda kv: -kv[1].get("solve_rate", 0)):
            tot = v.get("total", 0)
            sv = v.get("solved", 0)
            rate = v.get("solve_rate", 0.0)
            solved_list = v.get("solved_list") or []
            extra = f" → {solved_list}" if solved_list else ""
            lines.append(f"- {src}: {sv}/{tot}（{rate:.1%}）{extra}")
        lines.append("")

    results = report.get("results", []) or []
    if results:
        lines.append("## 逐题明细")
        lines.append("| # | id | 类别 | solved | solved_by | flag/error | 耗时(ms) | 重试 |")
        lines.append("|---|----|------|--------|-----------|-----------|----------|------|")
        for i, r in enumerate(results, 1):
            rid = r.get("question_id", "?")
            cat = r.get("category", "?")
            sv = "✅" if r.get("solved") else "❌"
            sb = r.get("solved_by") or "-"
            detail = r.get("flag") or r.get("error") or ""
            if isinstance(detail, dict):
                detail = detail.get("detail") or detail.get("category") or json.dumps(detail, ensure_ascii=False)
            dur = r.get("duration_ms", 0)
            rt = r.get("retries", 0)
            lines.append(f"| {i} | {rid} | {cat} | {sv} | {sb} | {_short(detail)} | {dur} | {rt} |")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize held-out benchmark report")
    ap.add_argument("--report", default=str(DEFAULT_REPORT))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    try:
        rep = json.load(open(args.report, encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[summarize] 无法读取报告 {args.report}: {e}", file=sys.stderr)
        return 2

    md = summarize(rep)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(md, encoding="utf-8")
    # 同时打印到 stdout
    print(md)
    print(f"\n[summarize] 已写出 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
