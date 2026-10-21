#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对象库兜底快照（`git bundle`，2026-09-19 防复发；2026-10-12 增量制 + 目录唯一化）。

背景（架构师诊断 C2 层1②）：2026-09-19 的 refs 损坏暴露"本地对象库是唯一副本"的
根风险。`git bundle create <out> --all` 产出一个**自带全部 refs + 对象**的单文件
副本，可 `git clone <bundle>` 一键恢复——直接消灭该根风险。

落盘位置：**主工作树**的 `ctf_agent/logs/git_bundles/`（`logs/` 已被 .gitignore 忽略，
符合"不入库"）。目录经 `git rev-parse --git-common-dir` 解析到主工作树——worktree 与
主仓共享同一对象库，bundle 内容逐字相同；各写各的目录只会重复占盘（2026-10-12 实测：
两个已合并 worktree 各存 7/3 份全量 bundle，与主仓 5 份合计 ≈41G，其中 27G 纯重复）。

**增量制（2026-10-12）**：每次提交后打**增量** bundle（`--all ^<上一份 tip>`，仅含新
对象，通常 KB 级），每累计 `full_every` 份增量后重打一份**全量**重置恢复链。全量命名
`repo-full-<stamp>.bundle`、增量 `repo-inc-<stamp>.bundle`；旧格式 `repo-<stamp>.bundle`
视为全量（兼容既有文件与 `list_bundles` 的 `repo-` 前缀匹配）。背景：全量单份 ≈2.8G
（对象库 2.6G），post-commit `--commit-lag 1` 语义下"每次提交一份全量" → 密集提交
轮次 1 小时 7 份 = 19G。

保留策略（`prune_bundles`）：保留最新 `keep` 份**全量** + 最新全量之后的**全部增量**
（活恢复链）；被新全量覆盖的旧增量内容已含于后续全量 → 可删。`keep=0` → 全清。

灾难恢复（对象库全丢时）：
  1. 取最新全量：`git clone <repo-full-*.bundle> recover`
  2. 按 mtime 顺序依次拉增量：`cd recover && git fetch <repo-inc-*.bundle> "+refs/*:refs/*"`
  增量的 prerequisite 由前序 bundle 提供，**必须按序**；`git bundle verify` 可验链。

用法：
  python scripts/_git_snapshot.py                  # 落一份（auto：增量，每 full_every 份转全量）
  python scripts/_git_snapshot.py --daily          # 时间到 OR 落后 ≥1 提交才落（见下）
  python scripts/_git_snapshot.py --full           # 强制全量
  python scripts/_git_snapshot.py --keep 2         # 保留几份全量（默认 2）
  python scripts/_git_snapshot.py --full-every 20  # 每 20 份增量转一份全量（默认 20）
  python scripts/_git_snapshot.py --list           # 列出已有 bundle（标 full/inc）
  python scripts/_git_snapshot.py --strict         # 失败时 exit 1（默认 0，不阻断主流程）
  python scripts/_git_snapshot.py --dir <path>     # 显式指定目录（默认自动解析主工作树）

节流语义（`--daily`，2026-09-19 修正）：**时间到 OR 落后 ≥ commit_lag 个提交**即补落。
  原为纯时间（24h），导致 bundle 落后多个提交——对象库真丢时会恢复到一个**不含
  防复发修复本身**的旧状态（"修事故的代码不在事故兜底范围内"）。修正后，任何一个
  新提交都会让"落后提交数"≥1 → 补落，故防复发提交自身被纳入兜底。增量制下每次提交
  只落 KB 级增量，该语义零成本成立。
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
DEFAULT_DIR = os.path.join(ROOT, "logs", "git_bundles")  # 解析失败时的回退目录
NAME_PREFIX = "repo-"
FULL_PREFIX = "repo-full-"  # 全量 bundle（自包含，可独立恢复）
INC_PREFIX = "repo-inc-"   # 增量 bundle（prerequisite 指前序 bundle）
NAME_SUFFIX = ".bundle"
HEAD_SIDECAR_SUFFIX = ".head"  # 边车：记录该 bundle 覆盖的 HEAD sha（用于"落后 N 提交"判定）
DEFAULT_KEEP = 2        # 默认保留几份全量
DEFAULT_FULL_EVERY = 20  # auto 模式：每累计几份增量转一份全量


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


def _is_incremental(path: str) -> bool:
    """增量 bundle 判定（按文件名前缀；旧格式 repo-<stamp> 视为全量）。"""
    return os.path.basename(path).startswith(INC_PREFIX)


def prune_bundles(dirpath: str, keep: int = DEFAULT_KEEP) -> list[str]:
    """滚动保留（2026-10-12 增量制）：最新 `keep` 份**全量** + 最新全量之后的全部**增量**。

    语义：全量自包含、可独立恢复；增量 prerequisite 指前序 bundle，只有与基点链同在
    才有恢复价值。被新全量覆盖的旧增量内容已含于后续全量 → 可删。
    keep=0 → 全清（含 .head 边车）。返回被删除的路径列表。
    """
    keep = max(0, int(keep))
    bundles = list_bundles(dirpath)
    if keep <= 0:
        to_remove = bundles
    else:
        fulls = [b for b in bundles if not _is_incremental(b)]
        kept = set(fulls[-keep:]) if fulls else set()
        if fulls:
            # 最新全量之后的增量 = 活恢复链（prerequisite 链的当前段），必须保留
            kept.update(bundles[bundles.index(fulls[-1]) + 1:])
        else:
            kept.update(bundles)  # 无全量 → 保守全留
        to_remove = [b for b in bundles if b not in kept]
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
    """最新（mtime 最大）bundle 路径；无 bundle 返回 None。"""
    bundles = list_bundles(dirpath)
    return bundles[-1] if bundles else None


def _incrementals_since_full(dirpath: str) -> int:
    """最新全量之后的增量份数（auto 模式的"转全量"计数）。无全量 → 全部增量计数。"""
    bundles = list_bundles(dirpath)
    if not bundles:
        return 0
    fulls = [b for b in bundles if not _is_incremental(b)]
    if not fulls:
        return len(bundles)
    return sum(1 for b in bundles[bundles.index(fulls[-1]) + 1:] if _is_incremental(b))


def _unique_path(out_dir: str, stamp: str, prefix: str = FULL_PREFIX) -> str:
    """给出不冲突的 bundle 路径。

    2026-09-19 修：文件名时间戳精度仅到秒，而新节流会"每次提交都补落"——同一秒内的
    两次 bundle 会**同名互相覆盖**（实测：连做两次提交，第二次覆盖第一次，最终只剩 1 份）。
    冲突时追加 `-1/-2/...`。list_bundles 用前缀/后缀匹配，`repo-inc-<stamp>-1.bundle` 仍被识别。
    """
    base = os.path.join(out_dir, f"{prefix}{stamp}{NAME_SUFFIX}")
    if not os.path.exists(base):
        return os.path.abspath(base)
    for n in range(1, 1000):
        cand = os.path.join(out_dir, f"{prefix}{stamp}-{n}{NAME_SUFFIX}")
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


def resolve_shared_bundle_dir(cwd: str | None = None, git_dir: str | None = None) -> str:
    """bundle 目录唯一化：解析到**主工作树**的 ctf_agent/logs/git_bundles。

    worktree 与主仓共享同一对象库（`.git` 指针），bundle 内容逐字相同；各写各的目录
    只会重复占盘（2026-10-12 实测：两个已合并 worktree 与主仓合计 ≈41G / 27G 纯重复）。
    经 `git rev-parse --git-common-dir`（恒指向主 .git）取主工作树。
    解析失败（git 缺失/非仓库/非本布局）→ 回退 DEFAULT_DIR（fail-safe，不造新目录）。
    """
    base = os.path.abspath(cwd or ROOT)
    cmd = ["git"] + (["--git-dir", git_dir] if git_dir else []) + \
        ["rev-parse", "--git-common-dir"]
    try:
        r = subprocess.run(cmd, cwd=base, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=30)
    except Exception:  # noqa: BLE001 - git 缺失/超时
        return DEFAULT_DIR
    if r.returncode != 0 or not r.stdout.strip():
        return DEFAULT_DIR
    common = r.stdout.strip()
    if not os.path.isabs(common):
        # 主工作树内 git 打印相对路径（如 `.git` / `../.git`，相对 cwd）→ 按 cwd 拼接
        common = os.path.join(base, common)
    common = os.path.abspath(common)
    main_wt = os.path.dirname(common)
    candidate = os.path.join(main_wt, "ctf_agent", "logs", "git_bundles")
    if os.path.isdir(os.path.join(main_wt, "ctf_agent")):
        return candidate
    return DEFAULT_DIR


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


def bundle_tips(bundle_path: str, git_dir: str | None = None) -> list[str]:
    """该 bundle 覆盖的**全部 ref tips**（list-heads 全量解析）。

    增量 bundle 的排除集必须用全部 ref tips 而非单个 HEAD：仓库常有孤立历史
    ref（archive/*、backup/* 等），`--all ^<master_tip>` 只排除 master 祖先，
    其他 refs 的大对象会被每次全量重打（2026-10-12 实测：全量 2680MB，
    五份"增量"各 2676MB，目录反涨到 16G）。
    """
    cmd = ["git"] + (["--git-dir", git_dir] if git_dir else []) + \
        ["bundle", "list-heads", bundle_path]
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
    except Exception:  # noqa: BLE001
        return []
    if r.returncode != 0:
        return []
    tips = []
    for ln in (r.stdout or "").splitlines():
        parts = ln.split()
        if parts and parts[0] not in tips:
            tips.append(parts[0])
    return tips


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
    """节流判定（纯函数）：**时间到** OR **落后 ≥ commit_lag 个提交**即需补落。

    背景（team-lead 发现的缺口）：原节流纯时间（24h），导致 bundle 落后多个提交——
    对象库真丢时，bundle 会恢复到一个**不含防复发修复本身**的旧状态。故加"落后即补"这一半：
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
def make_bundle(out_dir: str | None = None, keep: int = DEFAULT_KEEP, daily: bool = False,
                min_interval_hours: float = 24.0, commit_lag: int = 1,
                git_dir: str | None = None, mode: str = "auto",
                full_every: int = DEFAULT_FULL_EVERY) -> tuple[str, str | None]:
    """产出 bundle。返回 (status, path)；status ∈ {"ok", "skip", "fail"}。

    mode: "auto"（默认）＝每累计 full_every 份增量转一份全量；"full" 强制全量；
    "incremental" 强制增量（无基点/无新对象时退化为全量或 skip）。
    `daily=True` 时节流为 **时间到 OR 落后 ≥ commit_lag 个提交**（见 should_bundle）。
    `out_dir=None` → 解析到主工作树共享目录（见 resolve_shared_bundle_dir）。
    """
    out_dir = out_dir or resolve_shared_bundle_dir(git_dir=git_dir)
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

    prev = newest_bundle(out_dir)
    prev_tip = bundle_tip(prev, git_dir) if prev else None

    # ── full / incremental 决策 ──
    if mode == "full":
        want_full = True
    elif prev is None or prev_tip is None or head is None:
        want_full = True  # 无基点/边车缺失/无 HEAD → 只能全量（保守）
    elif head == prev_tip:
        print("ℹ️ 跳过 bundle 快照：最新 bundle 已覆盖当前 HEAD（无新对象）")
        return "skip", None
    elif mode == "incremental":
        want_full = False
    else:  # auto
        want_full = _incrementals_since_full(out_dir) >= max(1, int(full_every))

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    if want_full:
        # 全量：自包含，可独立恢复（仅首次 / 每 full_every 份增量 / --full / 无基点时）
        out = _unique_path(out_dir, stamp, FULL_PREFIX)
        rev_args = ["--all"]
        kind = "全量"
    else:
        # 增量基点必须是上一份 bundle 的**全部 ref tips**（孤立历史 ref 的对象
        # 不在 master 祖先里，只排除 HEAD 会把它们每次全量重打）。
        prev_tips = bundle_tips(prev, git_dir) if prev else []
        if not prev_tips:
            # 修复（2026-10-19）：上一份 bundle 存在却读不到 refs tips（list-heads 返回空/
            # 超时）→ 旧逻辑会 fallback 成整份全量（≈2.7G），每提交堆一份 → 曾炸到 19G。
            # 改为跳过：最新全量仍可作有效兜底，list-heads 恢复后下次会正常打 KB 级增量。
            # 绝不静默生成 2.7G 全量。
            print("⚠️ 跳过增量快照：上一份 bundle 读取 refs tips 失败（list-heads 为空），"
                  "为避免静默生成整份全量（≈2.7G）已跳过；最新全量仍可用作兜底。")
            return "skip", None
        out = _unique_path(out_dir, stamp, INC_PREFIX)
        rev_args = ["--all"] + [f"^{t}" for t in prev_tips]  # 增量：排除上份全部对象
        kind = "增量"

    cmd = ["git"]
    if git_dir:
        cmd += ["--git-dir", git_dir]
    cmd += ["bundle", "create", out, *rev_args]

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
    print(f"✅ {kind} bundle 已落盘：{out}（{size_mb:.2f} MB，HEAD={tip}）")
    removed = prune_bundles(out_dir, keep=keep)
    if removed:
        print(f"🧹 滚动清理 {len(removed)} 份旧 bundle（保留最新 {keep} 份全量 + 活链）")
    return "ok", out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="对象库兜底快照（git bundle，2026-09-19 防复发）")
    ap.add_argument("--dir", default=None,
                    help="输出目录（默认自动解析主工作树共享目录）")
    ap.add_argument("--keep", type=int, default=DEFAULT_KEEP,
                    help=f"滚动保留几份全量（默认 {DEFAULT_KEEP}；增量活链始终保留）")
    ap.add_argument("--daily", action="store_true", help="间隔内已有快照则跳过")
    ap.add_argument("--min-interval-hours", type=float, default=24.0,
                    help="--daily 的最小间隔小时数（默认 24）")
    ap.add_argument("--commit-lag", type=int, default=1,
                    help="--daily 时：最新 bundle 落后 ≥ 此提交数即强制补落（默认 1）")
    ap.add_argument("--mode", choices=["auto", "full", "incremental"], default="auto",
                    help="auto=每 full-every 份增量转全量（默认）；full=强制全量；incremental=强制增量")
    ap.add_argument("--full-every", type=int, default=DEFAULT_FULL_EVERY,
                    help=f"auto 模式每几份增量转一份全量（默认 {DEFAULT_FULL_EVERY}）")
    ap.add_argument("--list", action="store_true", help="列出已有 bundle")
    ap.add_argument("--strict", action="store_true", help="失败时 exit 1（默认 0，不阻断主流程）")
    ap.add_argument("--git-dir", default=None, help="显式指定 .git（默认 cwd 发现）")
    args = ap.parse_args(argv)

    if args.list:
        d = args.dir or resolve_shared_bundle_dir(git_dir=args.git_dir)
        bundles = list_bundles(d)
        if not bundles:
            print(f"（无 bundle：{d}）")
            return 0
        for p in bundles:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(p)))
            kind = "inc " if _is_incremental(p) else "full"
            print(f"{ts}  {kind}  {os.path.getsize(p) / 1024 / 1024:10.2f} MB  {p}")
        return 0

    status, _ = make_bundle(args.dir, keep=args.keep, daily=args.daily,
                            min_interval_hours=args.min_interval_hours,
                            commit_lag=args.commit_lag, git_dir=args.git_dir,
                            mode=args.mode, full_every=args.full_every)
    if status == "fail" and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
