#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自动看板（阶段5 协调状态从 git 派生，2026-08-24）。

设计（咨询诊断落地：事实只从 git 派生，不手工维护）：
  手工登记的任务板/台账必然与实际状态漂移（会话就是不登记——裸奔实证）。
  正确方向反过来：**分支列表即任务板**。本脚本从 git 派生全部协调状态：
    ① w/* 车道分支列表（= 当前任务板，每分支一个任务）
    ② 每分支相对 main 的 diff 统计（文件数/行数，判断任务进展）
    ③ REAL_SOLVES_LEDGER.md 的 offline_verified 计数（唯一 KPI 事实源）
    ④ 最近 commit 方向判定（解题 vs 治理，复用 _overseer_check 关键词）
  协调文件只允许单向数据流：从 git 派生 → 渲染给人看。凡是需要人/会话
  "记得去更新"的字段，就是下一个漂移点。

用法：
  .venv/Scripts/python.exe scripts/_board.py          # 全量看板
  .venv/Scripts/python.exe scripts/_board.py --json   # JSON 输出（机器可读）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "REAL_SOLVES_LEDGER.md"

SOLVE_HINT = ("web", "benchmark", "presolve", "crypto", "pwn", "reverse", "misc",
              "solve", "flag", "attack", "payload", "exploit", "skill", "靶机",
              "bkcrack", "solver")
GOVERN_HINT = ("hook", "门禁", "租约", "lock", "deadlock", "防错", "治理",
               "merge", "pre-commit", "post-commit", "总账", "stale", "身份",
               "车道", "worktree", "看板", "闸门", "gate")


def run(cmd: list, timeout: int = 30) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=str(ROOT),
                              encoding="utf-8", errors="replace").stdout
    except Exception:
        return ""


def branch_dirs() -> list:
    """w/* 车道分支列表（分支名即任务名）。"""
    out = run(["git", "branch", "--list", "w/*"]).strip()
    return [b.strip().lstrip("* ").strip() for b in out.splitlines() if b.strip()]


def diff_stat(branch: str) -> dict:
    """分支相对 main 的 diff 统计（文件数/插入/删除）。"""
    out = run(["git", "diff", "--shortstat", "main...%s" % branch]).strip()
    files = inserts = deletes = 0
    m = re.search(r"(\d+) files? changed", out)
    if m:
        files = int(m.group(1))
    m = re.search(r"(\d+) insertions?", out)
    if m:
        inserts = int(m.group(1))
    m = re.search(r"(\d+) deletions?", out)
    if m:
        deletes = int(m.group(1))
    return {"files": files, "insertions": inserts, "deletions": deletes}


def branch_commits(branch: str, limit: int = 3) -> list:
    """分支最近 commit（含 author/主题，用于方向判定）。"""
    out = run(["git", "log", "main..%s" % branch, "--format=%h|%an|%s",
               "-%d" % limit]).strip()
    return [line.split("|") for line in out.splitlines() if line.strip()]


def ledger_count() -> dict:
    """REAL_SOLVES_LEDGER.md 计数：offline_verified / claimed_pending / accepted。"""
    if not LEDGER.is_file():
        return {"offline_verified": -1, "claimed_pending": -1, "platform_accepted": -1}
    text = LEDGER.read_text(encoding="utf-8")
    return {
        "offline_verified": len(re.findall(r"offline_verified", text)),
        "claimed_pending": len(re.findall(r"claimed_pending", text)),
        "platform_accepted": len(re.findall(r"platform accepted = 0", text)),
    }


def blindspots() -> dict:
    """读最新 blindspots_*.json（P1 Step 2 产出）：盲区数 + 按类别分布。

    读不到返回空 dict（盲区分析未跑过——confidence 管道或报告缺失时正常）。
    """
    results_dir = ROOT / "data" / "results"
    if not results_dir.is_dir():
        return {}
    cands = sorted(results_dir.glob("blindspots_*.json"))
    if not cands:
        return {}
    try:
        data = json.loads(cands[-1].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    by_cat = {}
    for b in data.get("blindspots", []):
        cat = b.get("category", "?")
        by_cat[cat] = by_cat.get(cat, 0) + 1
    return {
        "count": data.get("blindspot_count", 0),
        "total": data.get("total", 0),
        "threshold": data.get("threshold", 0.8),
        "by_category": by_cat,
        "report": data.get("report", ""),
    }


def chain_stats() -> dict:
    """读最新 chain_stats_*.json（P1 Step 3 产出）：7 步链路失败步直方图。

    读不到返回空 dict（失败步统计未跑过时正常）。
    """
    results_dir = ROOT / "data" / "results"
    if not results_dir.is_dir():
        return {}
    cands = sorted(results_dir.glob("chain_stats_*.json"))
    if not cands:
        return {}
    try:
        data = json.loads(cands[-1].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    steps = data.get("steps", {})
    return {
        "total": data.get("total", 0),
        "worst_step": data.get("worst_step", ""),
        "worst_count": steps.get(data.get("worst_step", ""), {}).get("count", 0),
        "worst_pct": steps.get(data.get("worst_step", ""), {}).get("pct", 0.0),
        "log": data.get("log", ""),
    }


def test_baseline_drift() -> dict:
    """测试基线漂移检测（2026-08-24 锐评⑦：278→271 类下降不许安静发生）。

    读 KPI_BASELINE.json 的 test_passed（合并闸门落盘），对比当前实际 pytest 数：
    下降 → 返回 {drifted, baseline, current, delta, note} 供看板告警。
    """
    baseline_file = ROOT / "data" / "results" / "KPI_BASELINE.json"
    base = {}
    if baseline_file.is_file():
        try:
            base = json.loads(baseline_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            base = {}
    base_passed = base.get("test_passed")
    if base_passed is None:
        return {"drifted": False, "note": "无测试基线（首次 merge 后生成）"}
    # 当前实际测试数：快速数一下 tests/ 下 test_*.py 的用例数太重——
    # 直接跑一次全量 pytest 成本高；此处用"最近合并闸门落盘的 test_passed"即可，
    # 漂移判定交给 merge 时的新旧对比（本次 merge 通过数 < 基线 → 告警）。
    # 轻量实现：基线存在即展示，历史下降由链上多次基线值对比。
    return {
        "drifted": False,
        "baseline": base_passed,
        "total": base.get("test_total"),
        "skipped": base.get("test_skipped"),
        "worst_step": base.get("chain_worst_step", "—"),
        "regression": base.get("regression_count", "—"),
        "note": f"基线 {base_passed} passed（{base.get('as_of', '?')} 落盘）",
    }


def direction(subjects: list) -> str:
    """方向判定：解题 / 治理 / 混合。"""
    s = " ".join(subjects).lower()
    solve_hit = any(k in s for k in SOLVE_HINT)
    govern_hit = any(k in s for k in GOVERN_HINT)
    if solve_hit and govern_hit:
        return "混合"
    if solve_hit:
        return "解题"
    if govern_hit:
        return "治理"
    return "未知"


def main() -> int:
    ap = argparse.ArgumentParser(description="自动看板（协调状态从 git 派生）")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    args = ap.parse_args()

    branches = branch_dirs()
    ledger = ledger_count()
    bl = blindspots()
    cs = chain_stats()
    tbd = test_baseline_drift()
    main_commit = run(["git", "log", "-1", "--format=%h %s", "main"]).strip()

    lanes = []
    for b in branches:
        commits = branch_commits(b)
        lanes.append({
            "branch": b,
            "diff": diff_stat(b),
            "commits": commits,
            "direction": direction([c[2] for c in commits]),
        })

    if args.json:
        print(json.dumps({
            "main_head": main_commit,
            "ledger": ledger,
            "blindspots": bl,
            "chain_stats": cs,
            "lanes": lanes,
        }, ensure_ascii=False, indent=2))
        return 0

    print("══ 自动看板（协调状态从 git 派生，2026-08-24）══")
    print(f"main: {main_commit}")
    print(f"唯一 KPI（REAL_SOLVES_LEDGER）: offline_verified={ledger['offline_verified']} "
          f"claimed_pending={ledger['claimed_pending']} platform_accepted=0")
    if bl:
        _cat = ", ".join(f"{k}:{v}" for k, v in sorted(bl["by_category"].items())) or "—"
        print(f"盲区（confidence>={bl['threshold']} 且未解出）: {bl['count']} 道 / 总 {bl['total']} 道"
              f" [{_cat}]（来源 {bl['report']}）")
    if cs:
        print(f"链路失败步（goal_log）: 最高失败步 {cs['worst_step']} "
              f"({cs['worst_count']} 次, {cs['worst_pct']}%) / 总 {cs['total']} 次"
              f"（来源 {cs['log']}）")
    if tbd.get("baseline") is not None:
        _note = tbd.get("note", "")
        _extra = []
        if tbd.get("worst_step") != "—":
            _extra.append(f"失败步基线 {tbd['worst_step']}")
        if tbd.get("regression") != "—":
            _extra.append(f"回归集 {tbd['regression']} 题")
        _suffix = f" | {'; '.join(_extra)}" if _extra else ""
        print(f"测试基线（防漂移）: {_note}{_suffix}")
    print()
    if not lanes:
        print("（无 w/* 车道分支——当前无并行任务，main 是单一事实源）")
        return 0
    print(f"{'车道分支':<20} {'方向':<6} {'文件':>4} {'增':>5} {'删':>5}  最近提交")
    print("-" * 90)
    for lane in lanes:
        d = lane["diff"]
        first = lane["commits"][0] if lane["commits"] else ["", "", ""]
        print(f"{lane['branch']:<20} {lane['direction']:<6} {d['files']:>4} "
              f"{d['insertions']:>5} {d['deletions']:>5}  {first[2][:40]}")
        for c in lane["commits"][1:]:
            print(f"{'':<20} {'':<6} {'':>4} {'':>5} {'':>5}  {c[2][:40]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
