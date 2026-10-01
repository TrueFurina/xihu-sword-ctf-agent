"""抬预算重跑驱动：专门用于「排除预算因素」的对照实验。

为什么需要它（而不是直接用 benchmark_heldout.py）：
    `benchmark_heldout.py` 在子进程 env 里**强制写死** `CTF_AGENT_BUDGET_REFLECTION=1`
    （预算反思早停），且没有把 token 预算透传出来的参数。要测「是不是因为预算不够才没解出」，
    必须同时做到：① 关早停 ② 抬单题预算 ③ 全局预算仍硬封顶 —— 三者缺一不可，
    只抬预算不关早停会被早停提前掐掉，只关早停不抬预算等于没做对照。

    09-29 的 ceiling8（heldout 池）就是这么跑的，本脚本把它固化下来，避免每次手搓 env。

冷黑板：与 benchmark_heldout.py 同口径——备份 blackboard.json → 清空 presolve_cache
    → 跑 → 恢复。不清空会让上一轮的缓存命中变成假阳性。

用法（2.5× 抬预算 + 关早停的排除预算因素对照）：
    python scripts/_bench_ceiling.py --questions-dir data/questions_ext_A5_20261001 \
        --per-q 200000 --global 1000000 --wallclock 600 --tag ceiling_A5

默认（不传 --per-q）走 80K 同口径，可用于「只关早停」的单向对照。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "data" / "results"
BLACKBOARD = RESULTS / "blackboard.json"
OUT_DIR = RESULTS / "heldout"


def _backup_blackboard() -> Path | None:
    if not BLACKBOARD.exists():
        return None
    backup = RESULTS / f"blackboard.ceiling_bak_{datetime.now():%Y%m%d_%H%M%S}.json"
    shutil.copy(BLACKBOARD, backup)
    print(f"[ceiling] 备份黑板 -> {backup.name}（{BLACKBOARD.stat().st_size} bytes）")
    return backup


def _cold_blackboard() -> None:
    BLACKBOARD.write_text(
        json.dumps({"presolve_cache": {}, "known_failures": {}},
                   ensure_ascii=False, indent=1),
        encoding="utf-8")
    print("[ceiling] 黑板已冷启动（presolve_cache 清空）")


def _restore_blackboard(backup: Path | None) -> None:
    if backup is None:
        return
    if backup.exists():
        shutil.copy(backup, BLACKBOARD)
        print(f"[ceiling] 恢复原黑板 -> {BLACKBOARD.name}")
    else:
        print("[ceiling] 警告：备份不存在，跳过恢复")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--questions-dir", required=True)
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--per-q", type=int, default=80000,
                    help="单题 token 硬顶 CTF_AGENT_PER_Q_BUDGET（默认 80000 = 同口径）")
    ap.add_argument("--global", dest="global_budget", type=int, default=800000,
                    help="全局 token 硬顶 CTF_AGENT_GLOBAL_BUDGET（成本封顶，必须设）")
    ap.add_argument("--wallclock", type=float, default=300.0)
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--tag", default="ceiling")
    ap.add_argument("--reflection", action="store_true",
                    help="开启预算反思早停（默认关闭——本脚本的存在意义就是关它）")
    ap.add_argument("--no-e3", dest="e3", action="store_false",
                    help="关闭 E3 证据注入（默认 ON，与 heldout 同口径）")
    args = ap.parse_args()

    ts = time.strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"{args.tag}_{ts}"
    cmd = [
        sys.executable, "-m", "eval.benchmark",
        "--questions-dir", str(Path(args.questions_dir).resolve()),
        "--provider", args.provider,
        "--wallclock", str(args.wallclock),
        "--results-dir", str(out),
        "--limit", str(args.limit),
        "--concurrency", str(args.concurrency),
    ]

    env = dict(os.environ)
    env["CTF_AGENT_PER_Q_BUDGET"] = str(args.per_q)
    env["CTF_AGENT_GLOBAL_BUDGET"] = str(args.global_budget)
    # 关键：不设 CTF_AGENT_BUDGET_REFLECTION（关早停），或显式设为 0
    if args.reflection:
        env["CTF_AGENT_BUDGET_REFLECTION"] = "1"
    else:
        env.pop("CTF_AGENT_BUDGET_REFLECTION", None)
    if args.e3:
        env["CTF_AGENT_E3"] = "1"
    else:
        env.pop("CTF_AGENT_E3", None)

    print(f"[ceiling] 单题={args.per_q} 全局={args.global_budget} "
          f"wallclock={args.wallclock}s 早停={'ON' if args.reflection else 'OFF'} "
          f"E3={'OFF' if not args.e3 else 'ON'}")
    print(f"[ceiling] 运行: {' '.join(cmd)}")

    backup = _backup_blackboard()
    _cold_blackboard()
    try:
        rc = subprocess.call(cmd, cwd=str(ROOT), env=env)
    finally:
        _restore_blackboard(backup)
    print(f"[ceiling] 退出码 {rc}；报告见 {out}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
