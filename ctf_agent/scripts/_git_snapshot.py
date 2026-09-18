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
  python scripts/_git_snapshot.py --daily          # 时间到 OR 落后 ≥1 提交才落（见下）
  python scripts/_git_snapshot.py --keep 20        # 保留 20 份
  python scripts/_git_snapshot.py --min-interval-hours 6
  python scripts/_git_snapshot.py --commit-lag 2   # 落后 ≥2 提交才强制补落
  python scripts/_git_snapshot.py --list           # 列出已有 bundle
  python scripts/_git_snapshot.py --strict         # 失败时 exit 1（默认 0，不阻断主流程）

节流语义（`--daily`，2026-09-19 修正）：**时间到 OR 落后 ≥ commit_lag 个提交**即补落。
  原为纯时间（24h），导致 bundle 落后多个提交——对象库真丢时会恢复到一个**不含
  防复发修复本身**的旧状态（"修事故的代码不在事故兜底范围内"）。修正后，任何一个
  新提交都会让"落后提交数"≥1 → 补落，故防复发提交自身被纳入兜底。
  每个 bundle 落盘时写 `.head` 边车（该 bundle 覆盖的 HEAD sha），供下次判定落后数。

失败语义：默认**不阻断**主流程（exit 0，仅打印错误）——快照是兜底，不应把主流程
拖下水；需要硬失败时加 `--strict`。节流命中时返回 skip（非失败）。
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
HEAD_SIDECAR_SUFFIX = ".head"  # 边车：记录该 bundle 覆盖的 HEAD sha（用于"落后 N 提交"判定）


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
    """滚动保留最新 `keep` 份，删除更旧的。返回被删除的路径列表。

    同时清理对应的 `.head` 边车文件（记录该 bundle 覆盖的 HEAD）。
    """
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
        try:
            os.remove(p + HEAD_SIDECAR_SUFFIX)
        except OSError:
            pass
    return removed


def newest_age_hours(dirpath: str) -> float | None:
    """最新 bundle 距今小时数；无 bundle 返回 None。"""
    bundles = list_bundles(dirpath)
    if not bundles:
        return None
    return (time.time() - os.path.getmtime(bundles[-1])) / 3600.0


def newest_bundle(dirpath: str) -> str | None:
    """最新（mtime 最大）bundle 路径；无则 None。"""
    bundles = list_bundles(dirpath)
    return bundles[-1] if bundles else None


def _unique_path(out_dir: str, stamp: str) -> str:
    """给出不冲突的 bundle 路径。

    2026-09-19 修：文件名时间戳精度仅到秒，而新节流会"每次提交都补落"——同一秒内的
    两次 bundle 会**同名互相覆盖**（实测：连做两次提交，第二次覆盖第一次，最终只剩 1 份）。
    冲突时追加 `-1/-2/...`。list_bundles 用前缀/后缀匹配，`repo-<stamp>-1.bundle` 仍被识别。
    """
    base = os.path.join(out_dir, f"{NAME_PREFIX}{stamp}{NAME_SUFFIX}")
    if not os.path.exists(base):
        return os.path.abspath(base)
    for n in range(1, 1000):
        cand = os.path.join(out_dir, f"{NAME_PREFIX}{stamp}-{n}{NAME_SUFFIX}")
        if not os.path.exists(cand):
            return os.path.abspath(cand)
    return os.path.abspath(base)


# ── HEAD / 落后提交数探测（含纯函数判定，便于单测）────────────────────────
def _rev_parse_head(git_dir: str | None = None) -> str | None:
    """当前 HEAD 的 sha；失败返回 None。"""
    cmd = ["git"] + (["--git-dir", git_dir] if git_dir else []) + ["rev-parse", "HEAD"]
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=30)
    except Exception:  # noqa: BLE001 - git 缺失/超时
        return None
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def bundle_tip(bundle_path: str, git_dir: str | None = None) -> str | None:
    """该 bundle 覆盖的 HEAD sha：优先读 `.head` 边车，回退 `git bundle list-heads`。"""
    side = bundle_path + HEAD_SIDECAR_SUFFIX
    try:
        if os.path.isfile(side):
            with open(side, encoding="utf-8") as f:
                v = f.read().strip()
            if v:
                return v
    except OSError:
        pass
    cmd = ["git"] + (["--git-dir", git_dir] if git_dir else []) + \
        ["bundle", "list-heads", bundle_path]
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
    except Exception:  # noqa: BLE001
        return None
    if r.returncode != 0:
        return None
    lines = [ln.split() for ln in (r.stdout or "").splitlines() if ln.strip()]
    for parts in lines:
        if len(parts) >= 2 and parts[1] == "HEAD":
            return parts[0]
    for parts in lines:  # 退而求其次：任一 ref 的 sha
        if parts:
            return parts[0]
    return None


def commits_between(old_sha: str | None, new_sha: str | None,
                    git_dir: str | None = None) -> int | None:
    """`git rev-list --count old..new`；无法判定返回 None。"""
    if not old_sha or not new_sha:
        return None
    cmd = ["git"] + (["--git-dir", git_dir] if git_dir else []) + \
        ["rev-list", "--count", f"{old_sha}..{new_sha}"]
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=60)
    except Exception:  # noqa: BLE001
        return None
    if r.returncode != 0:
        return None
    try:
        return int((r.stdout or "0").strip() or "0")
    except ValueError:
        return None


def should_bundle(age_hours: float | None, lag: int | None,
                  min_interval_hours: float, commit_lag: int) -> tuple[bool, str]:
    """节流判定（纯函数）：**时间到** OR **落后 ≥ commit_lag 个提交** 即需补落。

    背景（team-lead 发现的缺口）：原节流纯时间（24h），导致 bundle 落后多个提交——
    对象库真丢时会恢复到一个**不含防复发修复本身**的旧状态。故加"落后即补"这一半：
      · age 未知（无 bundle）→ 必须落；
      · 距上次 ≥ min_interval_hours → 落（时间到）；
      · 时间未到，但无法确认已覆盖 HEAD（lag 未知）→ 落（保守）；
      · 时间未到，且落后提交数 < commit_lag → 跳过（唯一可跳过的情形）。
    返回 (是否需落盘, 原因)。
    """
    if age_hours is None:
        return True, "尚无 bundle"
    if age_hours >= float(min_interval_hours):
        return True, f"距上次 {age_hours:.2f}h ≥ {min_interval_hours}h（时间到）"
    if lag is None:
        return True, "时间未到，但无法确认最新 bundle 已覆盖 HEAD → 保守补落"
    if lag < max(1, int(commit_lag)):
        return False, (f"距上次 {age_hours:.2f}h < {min_interval_hours}h 且仅落后 "
                       f"{lag} 提交 < {commit_lag} → 跳过")
    return True, f"时间未到但已落后 {lag} 提交 ≥ {commit_lag} → 补落"


# ── 主流程 ────────────────────────────────────────────────────────────────
def make_bundle(out_dir: str = DEFAULT_DIR, keep: int = 10, daily: bool = False,
                min_interval_hours: float = 24.0, commit_lag: int = 1,
                git_dir: str | None = None) -> tuple[str, str | None]:
    """产出 bundle。返回 (status, path)；status ∈ {"ok", "skip", "fail"}。

    `daily=True` 时节流为 **时间到 OR 落后 ≥ commit_lag 个提交**（见 should_bundle）。
    """
    os.makedirs(out_dir, exist_ok=True)
    head = _rev_parse_head(git_dir)

    if daily:
        age = newest_age_hours(out_dir)
        newest = newest_bundle(out_dir)
        lag = commits_between(bundle_tip(newest, git_dir), head, git_dir) if newest else None
        do_bundle, reason = should_bundle(age, lag, min_interval_hours, commit_lag)
        if not do_bundle:
            print(f"ℹ️ 跳过 bundle 快照：{reason}")
            return "skip", None
        print(f"ℹ️ 需补落 bundle：{reason}")

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = _unique_path(out_dir, stamp)

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

    # 边车：记录本 bundle 覆盖的 HEAD，供下次"落后 N 提交"判定（无需再解析 bundle 内部）
    if head:
        try:
            with open(out + HEAD_SIDECAR_SUFFIX, "w", encoding="utf-8") as f:
                f.write(head + "\n")
        except OSError:
            pass

    size_mb = os.path.getsize(out) / 1024 / 1024
    tip = (head or "?")[:12]
    print(f"✅ bundle 已落盘：{out}（{size_mb:.2f} MB，HEAD={tip}）")
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
    ap.add_argument("--commit-lag", type=int, default=1,
                    help="--daily 时：最新 bundle 落后 ≥ 此提交数即强制补落（默认 1）")
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
                            commit_lag=args.commit_lag, git_dir=args.git_dir)
    if status == "fail" and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
