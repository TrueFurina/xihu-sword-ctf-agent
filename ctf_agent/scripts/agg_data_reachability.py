# -*- coding: utf-8 -*-
"""数据可达率聚合统计（决赛答辩硬证据：修复前 0% → 修复后 X%，2026-08-21 产品官建议）。

输入：一个或多个 race 日志文件路径（含 "[数据可达]" 行），省略参数时自动扫描
      data/results/*.log 与根目录 *.log。
输出：每题维度 desc/附件/靶机 可达性 + 整体"数据可达率"。

"数据可达"日志锚点（ctfplatform/poller.py _handle_challenge 每题一行）：
    [数据可达] <id> desc=<N>字 att=<True/False> endpoints=<N> has_instance=<True/False>

完全可达判定：desc>0 且 (att=True 或 endpoints>0)——agent 有题面 + 至少一个抓手。

⚠️ 口径提醒（答辩诚信分）：修复前日志跑出 0 条 [数据可达] 行 ≠ 实测"可达率 0%"，
本质是"该指标修复前不存在"（锚点是 P0 修复后才加的）。答辩用双证据：
① 修复前复盘实证（brush_log 未解出/stuck_loop 计数、"累计已处理 62 题" 全 no-data）
② 修复后本工具产出 X%（真实场次/彩排日志）。详见 tests/README.md。

用法：
    .venv/Scripts/python.exe scripts/agg_data_reachability.py
    .venv/Scripts/python.exe scripts/agg_data_reachability.py data/results/race_20260821.log race.log
"""

import os
import re
import sys
from typing import Optional

LINE_RE = re.compile(
    r"\[数据可达\]\s+(\S+)\s+desc=(\d+)字\s+att=(True|False)\s+endpoints=(\d+)\s+has_instance=(True|False)"
)


def parse_line(line: str) -> Optional[dict]:
    """解析单行 [数据可达] 日志；不匹配返回 None。"""
    m = LINE_RE.search(line)
    if not m:
        return None
    cid, desc_s, att_s, ep_s, inst_s = m.groups()
    desc = int(desc_s)
    endpoints = int(ep_s)
    att = att_s == "True"
    return {
        "id": cid,
        "desc": desc,
        "att": att,
        "endpoints": endpoints,
        "has_instance": inst_s == "True",
        "fully_reachable": desc > 0 and (att or endpoints > 0),
    }


def aggregate(lines) -> dict:
    """聚合日志行 → 可达性统计 dict（total/desc_ok/att_ok/endpoints_ok/fully/...）。"""
    rows = [r for r in (parse_line(l) for l in lines) if r]
    n = len(rows)
    if n == 0:
        return {
            "total": 0, "desc_ok": 0, "att_ok": 0, "endpoints_ok": 0,
            "inst_ok": 0, "fully": 0, "fully_rate": 0.0, "unreachable": [],
        }
    desc_ok = sum(1 for r in rows if r["desc"] > 0)
    att_ok = sum(1 for r in rows if r["att"])
    ep_ok = sum(1 for r in rows if r["endpoints"] > 0)
    inst_ok = sum(1 for r in rows if r["has_instance"])
    fully = sum(1 for r in rows if r["fully_reachable"])
    unreachable = [r for r in rows if not r["fully_reachable"]]
    return {
        "total": n,
        "desc_ok": desc_ok,
        "att_ok": att_ok,
        "endpoints_ok": ep_ok,
        "inst_ok": inst_ok,
        "fully": fully,
        "fully_rate": round(fully / n, 3) if n else 0.0,
        "unreachable": unreachable[:5],  # 样例最多 5 条
    }


def format_report(agg: dict) -> str:
    """渲染可读报告。"""
    n = agg["total"]
    if n == 0:
        return "未在日志中找到 [数据可达] 行（可能是修复前日志，或日志未记录该锚点）"
    pct = lambda x: f"{x} ({round(x / n * 100, 1)}%)" if n else "0"
    lines = [
        f"数据可达率聚合报告（共 {n} 条 [数据可达] 日志行）",
        "=" * 46,
        f"题面 desc>0       : {pct(agg['desc_ok'])}",
        f"有附件 att=True   : {pct(agg['att_ok'])}",
        f"有靶机 endpoints>0: {pct(agg['endpoints_ok'])}",
        f"需实例 has_instance: {pct(agg['inst_ok'])}",
        f"★ 完全可达（题面+抓手）: {pct(agg['fully'])}  ← 数据可达率",
    ]
    if agg["unreachable"]:
        lines.append("未完全可达样例（最多 5 条）：")
        lines.append("  id      desc  att  endpoints  has_instance")
        for r in agg["unreachable"]:
            lines.append(
                f"  {r['id']:<7} {r['desc']:>4}  {str(r['att']):<5} "
                f"{r['endpoints']:>9}  {r['has_instance']}"
            )
    return "\n".join(lines)


def _default_log_paths() -> list:
    """无参数时扫描 data/results/*.log 与根目录 *.log（listdir 过滤，不用 glob）。"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = []
    for d in (os.path.join(root, "data", "results"), root):
        try:
            for fn in sorted(os.listdir(d)):
                if fn.endswith(".log"):
                    paths.append(os.path.join(d, fn))
        except OSError:
            pass
    return paths


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    paths = argv or _default_log_paths()
    if not paths:
        print("未找到任何 *.log 文件（可显式传入路径）")
        return 1
    all_lines = []
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                all_lines.extend(f)
        except OSError as exc:
            print(f"[warn] 读取失败 {p}: {exc}", file=sys.stderr)
    report = format_report(aggregate(all_lines))
    print(report)
    print(f"\n来源日志 {len(paths)} 个：{', '.join(os.path.basename(p) for p in paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
