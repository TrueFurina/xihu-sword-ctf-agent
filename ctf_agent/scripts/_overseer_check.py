# -*- coding: utf-8 -*-
"""监督者持续观察脚本(2026-08-23 · 上帝视角)。

并行会话永不停止,监督就不能停。本脚本一键输出当前并行会话全貌:
  1. 活跃进程(解题/benchmark/靶机/会话)
  2. 租约持有者与 scope
  3. 最新提交(判断方向:解题 vs 治理)
  4. 在飞改动(未收口炸弹)
  5. 方向偏离判定(按关键词规则)

用法:
    .venv/Scripts/python.exe scripts/_overseer_check.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COOR = ROOT / ".atomcode" / "coordination.json"

# 方向判定:解题向关键词 vs 治理向关键词
SOLVE_HINT = ("web", "benchmark", "presolve", "crypto", "pwn", "reverse", "misc",
              "solve", "flag", "attack", "payload", "exploit", "skill", "靶机",
              "bkcrack", "solver")
GOVERN_HINT = ("hook", "门禁", "租约", "lock", "deadlock", "防错", "治理",
               "merge", "pre-commit", "post-commit", "总账", "stale", "身份")


def run(cmd: list, timeout: int = 30) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=str(ROOT),
                              encoding="utf-8", errors="replace").stdout
    except Exception:
        return ""


def scan_processes() -> list:
    """扫描活跃 python/会话进程(排除本脚本与扫描命令自身)。

    Windows PowerShell 5.1 默认输出 GBK,ConvertTo-Json 中文/长命令会乱码——
    前置 [Console]::OutputEncoding 强制 UTF-8,再配合 errors=replace 双保险。
    """
    ps = run(["powershell", "-NoProfile", "-Command",
              "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
              "Get-CimInstance Win32_Process | "
              "Where-Object {$_.CommandLine -match 'ctf_agent|python|benchmark'} | "
              "Select-Object ProcessId, @{N='Cmd';E={$_.CommandLine}} | "
              "ConvertTo-Json -Compress"])
    out = []
    try:
        for p in json.loads(ps) if ps.strip() else []:
            cmd = str(p.get("Cmd", ""))
            if "overseer_check" in cmd or "Get-CimInstance" in cmd:
                continue
            out.append({"pid": p.get("ProcessId"), "cmd": cmd[:120]})
    except Exception:
        pass
    return out


def scan_leases() -> list:
    if not COOR.exists():
        return []
    try:
        d = json.loads(COOR.read_text(encoding="utf-8"))
        return list(d.get("leases", {}).items())
    except Exception:
        return []


def scan_git() -> dict:
    log = run(["git", "log", "--oneline", "-6"])
    status = run(["git", "status", "--short"])
    return {"log": log, "status": status}


def classify(cmdline: str) -> str:
    """按关键词判定一个进程/提交的方向。"""
    s = cmdline.lower()
    if any(k in s for k in GOVERN_HINT):
        return "GOVERN(治理)"
    if any(k in s for k in SOLVE_HINT):
        return "SOLVE(解题)"
    return "UNKNOWN"


# ── 总账健康检查（2026-08-24 中心调控保障：总账必须被所有会话持续更新）──
TOP0 = ROOT.parent / "协同任务总账-TOP0.md"


def check_ledger() -> dict:
    """校验总账自动记账是否健康。

    1. 总账文件存在且新鲜(最后修改 < 24h,否则记账可能停摆)
    2. 最近 N 条 git commit 是否全部出现在总账(机器强制兜底是否生效)
    """
    report = {"ok": True, "issues": []}
    if not TOP0.exists():
        report["ok"] = False
        report["issues"].append(f"总账缺失: {TOP0}")
        return report
    mtime = datetime.fromtimestamp(TOP0.stat().st_mtime)
    age_h = (datetime.now() - mtime).total_seconds() / 3600
    if age_h > 24:
        report["ok"] = False
        report["issues"].append(f"总账最后更新 {age_h:.1f}h 前——可能停摆")
    log = run(["git", "log", "--format=%h", "-8"])
    commits = [c for c in log.strip().splitlines() if c.strip()]
    missing = []
    ledger_text = TOP0.read_text(encoding="utf-8", errors="replace")
    for c in commits:
        # 注意：--format=%h 默认输出 7 位短哈希，总账也记 7 位短哈希——
        # 直接用 c 匹配（勿用 %H 前 8 位，会与总账 7 位记录失配——2026-08-24 修复）
        if c not in ledger_text:
            missing.append(c)
    if missing:
        report["ok"] = False
        report["issues"].append(f"最近提交未入总账: {missing}")
    report["age_h"] = round(age_h, 1)
    report["commits_checked"] = len(commits)
    return report


def main() -> None:
    print(f"=== 监督观察 {datetime.now().strftime('%m-%d %H:%M:%S')} ===")
    print("\n── 1. 活跃进程 ──")
    procs = scan_processes()
    if not procs:
        print("  无活跃会话进程")
    for p in procs:
        print(f"  [{p['pid']}] {p['cmd']}  → {classify(p['cmd'])}")

    print("\n── 2. 租约 ──")
    leases = scan_leases()
    if not leases:
        print("  无租约")
    for sid, l in leases:
        print(f"  {sid}: scope={l.get('scope')}")

    print("\n── 3. 最新提交 ──")
    g = scan_git()
    for line in g["log"].strip().splitlines():
        print(f"  {line}")

    print("\n── 4. 在飞改动 ──")
    status_lines = [s for s in g["status"].strip().splitlines() if s.strip()]
    if not status_lines:
        print("  工作树 clean")
    for s in status_lines[:12]:
        print(f"  {s}")

    # 方向汇总
    gov = sum(1 for p in procs if classify(p["cmd"]) == "GOVERN(治理)")
    sol = sum(1 for p in procs if classify(p["cmd"]) == "SOLVE(解题)")
    print(f"\n── 5. 方向判定: {sol} 解题进程 / {gov} 治理进程 ──")
    if gov > sol:
        print("  ⚠️ 治理进程多于解题进程——考虑刹车(见 监督干预信号-20260823.md)")
    else:
        print("  ✅ 解题向占优,轨道正确")

    print("\n── 6. 总账健康检查(自动记账保障) ──")
    ledger = check_ledger()
    if ledger["ok"]:
        print(f"  ✅ 总账健康: {ledger['age_h']}h 前更新, 最近 {ledger['commits_checked']} 条提交全部入账")
    else:
        print("  ❌ 总账异常:")
        for issue in ledger["issues"]:
            print(f"     - {issue}")


if __name__ == "__main__":
    main()
