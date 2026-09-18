#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对象库兜底快照（`git bundle`，2026-09-19 防复发）。

背景（架构师诊断 C2 层1②）：2026-09-19 的 refs 损坏暴露"本地对象库是唯一副本"的
根风险。`git bundle create <out> --all` 产出一个**自带全部 refs + 对象**的单文件
副本，可 `git clone <bundle>` 一键恢复——直接消灭该根风险。

落盘位置：`logs/git_bundles/`（`logs/` 已被 .gitignore 忽略，符合"不入库"）。
滚动保留最近 N 份（默认 10），按 mtime 从旧到新清理。

用法：
  python scripts/_git_snapshot.py                  # 落一份 bundle（滚动保留 10）
  python scripts/_git_snapshot.py --daily          # 24h 内已有则跳过（每日一次语义）
  python scripts/_git_snapshot.py --keep 20        # 保留 20 份
  python scripts/_git_snapshot.py --min-interval-hours 6
  python scripts/_git_snapshot.py --list           # 列出已有 bundle
  python scripts/_git_snapshot.py --strict         # 失败时 exit 1（默认 0，不阻断主流程）

失败语义：默认**不阻断**主流程（exit 0，仅打印错误）——快照是兜底，不应把主流程
拖下水；需要硬失败时加 `--strict`。`--daily` 命中"已有新快照"时返回 skip（非失败）。
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ctf_agent
DEFAULT_DIR = os.path.join(ROOT, "logs", "git_bundles")
NAME_PREFIX = "repo-"
NAME_SUFFIX = ".bundle"


# ── 纯函数（可单测）──────────────────────────────────────────────────────
def list_bundles(dirpath: str) -> list[str]:
    """列出目录下的 bundle，按 mtime 升序（旧→新）。"""
    if not os.path.isdir(dirpath):
        return []
    items: list[tuple[float, str]] = []
    for fn in os.listdir(dirpath):
        if fn.startswith(NAME_PREFIX) and fn.endswith(NAME_SUFFIX):
            p = os.path.join(dirpath, fn)
            try:
                items.append((os.path.getmtime(p), p))
            except OSError:
                pass
    items.sort()
    return [p for _, p in items]


def prune_bundles(dirpath: str, keep: int = 10) -> list[str]:
    """滚动保留最新 `keep` 份，删除更旧的。返回被删除的路径列表。"""
    keep = max(0, int(keep))
    bundles = list_bundles(dirpath)
    to_remove = bundles[:max(0, len(bundles) - keep)]
    removed: list[str] = []
    for p in to_remove:
        try:
            os.remove(p)
            removed.append(p)
        except OSError:
            pass
    return removed


def newest_age_hours(dirpath: str) -> float | None:
    """最新 bundle 距今小时数；无 bundle 返回 None。"""
    bundles = list_bundles(dirpath)
    if not bundles:
        return None
    return (time.time() - os.path.getmtime(bundles[-1])) / 3600.0


# ── 主流程 ────────────────────────────────────────────────────────────────
def make_bundle(out_dir: str = DEFAULT_DIR, keep: int = 10, daily: bool = False,
                min_interval_hours: float = 24.0,
                git_dir: str | None = None) -> tuple[str, str | None]:
    """产出 bundle。返回 (status, path)；status ∈ {"ok", "skip", "fail"}。"""
    os.makedirs(out_dir, exist_ok=True)

    if daily:
        age = newest_age_hours(out_dir)
        if age is not None and age < float(min_interval_hours):
            print(f"ℹ️ 距上次 bundle 仅 {age:.1f}h（< {min_interval_hours}h），跳过（--daily）")
            return "skip", None

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = os.path.abspath(os.path.join(out_dir, f"{NAME_PREFIX}{stamp}{NAME_SUFFIX}"))

    cmd = ["git"]
    if git_dir:
        cmd += ["--git-dir", git_dir]
    cmd += ["bundle", "create", out, "--all"]

    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=1800)
    except Exception as exc:  # noqa: BLE001 - git 不存在/超时
        print(f"❌ git bundle 调用失败：{exc}")
        return "fail", None

    if r.returncode != 0 or not os.path.isfile(out):
        msg = ((r.stderr or "") + (r.stdout or "")).strip()
        print(f"❌ git bundle 失败（exit={r.returncode}）：{msg[:300]}")
        try:
            if os.path.isfile(out):
                os.remove(out)
        except OSError:
            pass
        return "fail", None

    size_mb = os.path.getsize(out) / 1024 / 1024
    print(f"✅ bundle 已落盘：{out}（{size_mb:.2f} MB）")
    removed = prune_bundles(out_dir, keep=keep)
    if removed:
        print(f"🧹 滚动清理 {len(removed)} 份旧 bundle（保留最新 {keep}）")
    return "ok", out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="对象库兜底快照（git bundle，2026-09-19 防复发）")
    ap.add_argument("--dir", default=DEFAULT_DIR, help=f"输出目录（默认 {DEFAULT_DIR}）")
    ap.add_argument("--keep", type=int, default=10, help="滚动保留份数（默认 10）")
    ap.add_argument("--daily", action="store_true", help="间隔内已有快照则跳过")
    ap.add_argument("--min-interval-hours", type=float, default=24.0,
                    help="--daily 的最小间隔小时数（默认 24）")
    ap.add_argument("--list", action="store_true", help="列出已有 bundle")
    ap.add_argument("--strict", action="store_true", help="失败时 exit 1（默认 0，不阻断）")
    ap.add_argument("--git-dir", default=None, help="显式指定 .git（默认 cwd 发现）")
    args = ap.parse_args(argv)

    if args.list:
        bundles = list_bundles(args.dir)
        if not bundles:
            print(f"（无 bundle：{args.dir}）")
            return 0
        for p in bundles:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(p)))
            print(f"{ts}  {os.path.getsize(p) / 1024 / 1024:8.2f} MB  {p}")
        return 0

    status, _ = make_bundle(args.dir, keep=args.keep, daily=args.daily,
                            min_interval_hours=args.min_interval_hours,
                            git_dir=args.git_dir)
    if status == "fail" and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
