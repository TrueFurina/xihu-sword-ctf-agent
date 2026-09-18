#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""git 仓库健康门禁 L0/L1 + refs 快照 + 灾难重建（2026-09-19 防复发）。

背景（2026-09-19 事故，架构师诊断报告 git损坏根因与防复发-架构师-20260919.md）：
  并发会话的破坏性 ref 操作删除了 `.git/refs/` 目录与 `packed-refs`。git 的仓库
  合法性校验 `is_git_directory()` 要求 `.git/` 下**同时存在 `refs/` 目录与
  `objects/` 目录**（外加 HEAD）。`refs/` 目录整个消失 → git 报
  `fatal: not a git repository` —— 于是**所有依赖 git 的门禁脚本（_session_boot /
  _merge_gate / pre-commit 里的一切 git 调用）连启动都做不到**，故障被放大为
  "整仓不可用"。

核心原则（来自架构师诊断 A5，务必遵守）：
  ⚠️ 健康检查必须**纯文件系统判断**（os.path），**绝不调用任何 git 命令**——
      因为 git 命令在损坏态本就失败；用 git 检查健康 = 检查器自己先崩（G5 缺口）。

两级检查：
  L0（纯文件系统，零 git 依赖，本案关键）：
    ① `.git/HEAD` 存在且非空
    ② `.git/objects` 是目录
    ③ `.git/refs` 是目录            ← 2026-09-19 事故的直接判据（整个目录缺失）
    ④ `packed-refs` 存在 或 `refs/` 下有内容（ref 存储非空）
  L1（git 存活时才有意义）：
    · `git show-ref` 非空
    · `git rev-parse HEAD` 可达
    · `git fsck --connectivity-only` 无 missing/broken/corrupt

用法：
  python scripts/_git_guard.py                 # L0 健康检查（默认）；健康 exit 0 / 损坏 exit 1
  python scripts/_git_guard.py --l1            # L0 + L1（L1 会调用 git）
  python scripts/_git_guard.py --json          # 机器可读输出
  python scripts/_git_guard.py --quiet         # 仅失败时输出
  python scripts/_git_guard.py --snapshot      # 落 refs 快照到 logs/git_refs_snapshot/
  python scripts/_git_guard.py --rebuild       # 灾难恢复：从最新快照重建 refs/ + packed-refs
  python scripts/_git_guard.py --rebuild --from <snapshot.json> [--dry-run]
  python scripts/_git_guard.py --git-dir <path>  # 显式指定 .git（测试/非标准布局）

硬约束（本环境沙箱特性，来自 git-refs-remotes-vanish skill）：
  **绝不写 loose 的 `.git/refs/remotes/**`**——沙箱安全层会静默回滚并可能连坐删掉
  整个 `refs/` 树。远程跟踪引用一律只写 `packed-refs`（`--rebuild` 已强制此规则）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ctf_agent
SNAP_DIR_DEFAULT = os.path.join(ROOT, "logs", "git_refs_snapshot")


# ── 通用工具 ──────────────────────────────────────────────────────────────
def _iso_utc(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if ts is None else ts))


def _stamp_utc(ts: float | None = None) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(time.time() if ts is None else ts))


def _read_text(path: str) -> str | None:
    """安全读取文本文件（不存在/不可读返回 None）。"""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _common_dir(git_dir: str) -> str:
    """关联 worktree（`.git/worktrees/<n>`）的 refs/objects 在 common dir。

    若 `<git_dir>/commondir` 存在，读其指向的主 `.git`；否则返回原目录。
    """
    cd = os.path.join(git_dir, "commondir")
    if os.path.isfile(cd):
        c = (_read_text(cd) or "").strip()
        if c:
            if not os.path.isabs(c):
                c = os.path.normpath(os.path.join(git_dir, c))
            return os.path.abspath(c)
    return git_dir


def _gitdir_from_entry(entry: str) -> str:
    """从一个 `.git` 条目（目录或 worktree 的 gitdir 文件）解析出真实 git 目录。"""
    entry = os.path.abspath(entry)
    if os.path.isdir(entry):
        return _common_dir(entry)
    # `.git` 文件（linked worktree / submodule）：内容形如 "gitdir: <path>"
    txt = (_read_text(entry) or "").strip()
    m = re.match(r"gitdir:\s*(.+)$", txt)
    if not m:
        return entry
    gd = m.group(1).strip()
    if not os.path.isabs(gd):
        gd = os.path.normpath(os.path.join(os.path.dirname(entry), gd))
    return _common_dir(os.path.abspath(gd))


def resolve_git_dir(explicit: str | None = None) -> str:
    """定位 git 目录（优先 git 自身解析；损坏态回退纯文件系统向上查找）。

    返回的是 **common dir**（refs/objects/HEAD 所在），以便 worktree 也能正确判据。
    """
    if explicit:
        return os.path.abspath(explicit)
    env = os.environ.get("GIT_DIR")
    if env:
        return _common_dir(os.path.abspath(env))
    # 1) git 自身解析（健康态可用；正确处理 worktree）——损坏态会失败，故随后回退。
    for args in (["rev-parse", "--path-format=absolute", "--git-common-dir"],
                 ["rev-parse", "--absolute-git-dir"]):
        try:
            r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                return _common_dir(os.path.abspath(r.stdout.strip()))
        except Exception:  # noqa: BLE001 - 探测失败一律回退
            pass
    # 2) 损坏态回退（git 命令全线失败）：从仓库根候选向上找 `.git` 条目。
    start = os.path.dirname(ROOT)  # ROOT=.../ctf_agent → start=仓库根
    d = start
    for _ in range(32):
        cand = os.path.join(d, ".git")
        if os.path.isdir(cand) or os.path.isfile(cand):
            return _gitdir_from_entry(cand)
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return os.path.abspath(os.path.join(start, ".git"))


# ── L0：纯文件系统健康检查（零 git 依赖）────────────────────────────────────
def _refs_entries(refs_dir: str) -> list[str]:
    """`refs/` 下所有 ref 文件（相对 refs_dir 的路径，正斜杠）。"""
    out: list[str] = []
    if not os.path.isdir(refs_dir):
        return out
    for base, _dirs, files in os.walk(refs_dir):
        for fn in files:
            rel = os.path.relpath(os.path.join(base, fn), refs_dir)
            out.append(rel.replace(os.sep, "/"))
    return sorted(out)


def check_l0(git_dir: str) -> list[dict]:
    """L0 检查：纯 `os.path`/文件读写，**零 git 依赖**。返回逐项结果（有序 list）。"""
    head = os.path.join(git_dir, "HEAD")
    objects = os.path.join(git_dir, "objects")
    refs = os.path.join(git_dir, "refs")
    packed = os.path.join(git_dir, "packed-refs")

    head_txt = (_read_text(head) or "").strip()
    head_ok = os.path.isfile(head) and bool(head_txt)
    objects_ok = os.path.isdir(objects)
    refs_ok = os.path.isdir(refs)
    refs_files = _refs_entries(refs) if refs_ok else []
    packed_ok = os.path.isfile(packed)
    populated_ok = bool(refs_files) or packed_ok

    if head_ok:
        head_detail = f"HEAD 存在且非空（{head_txt}）"
    else:
        head_detail = f"HEAD 缺失或为空：{head}"
    if objects_ok:
        objects_detail = f"objects/ 是目录（{objects}）"
    else:
        objects_detail = f"objects/ 不是目录：{objects}"
    if refs_ok:
        refs_detail = f"refs/ 是目录（含 {len(refs_files)} 个 ref）"
    else:
        refs_detail = f"refs/ 不是目录（缺失=2026-09-19 事故特征，致命）：{refs}"
    if populated_ok:
        bits = []
        if packed_ok:
            bits.append("packed-refs 存在")
        if refs_files:
            bits.append(f"refs/ 下 {len(refs_files)} 项")
        populated_detail = "；".join(bits)
    else:
        populated_detail = "refs/ 下无任何 ref 且无 packed-refs（ref 存储为空）"

    return [
        {"id": "HEAD", "ok": head_ok, "detail": head_detail},
        {"id": "objects", "ok": objects_ok, "detail": objects_detail},
        {"id": "refs", "ok": refs_ok, "detail": refs_detail},
        {"id": "refs-populated", "ok": populated_ok, "detail": populated_detail},
    ]


def all_ok(results: list[dict]) -> bool:
    return all(bool(r.get("ok")) for r in results)


# ── L1：git 存活时的深度检查 ───────────────────────────────────────────────
def _run_git(git_dir: str, explicit: bool, args: list[str],
             timeout: int = 60) -> subprocess.CompletedProcess | None:
    """运行 git。explicit=True 时用 `--git-dir`，否则靠 cwd 发现（健康态更稳）。"""
    cmd = (["git", "--git-dir", git_dir] if explicit else ["git"]) + args
    try:
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except Exception:  # noqa: BLE001 - git 不存在/超时统一返回 None
        return None


def check_l1(git_dir: str, explicit: bool = False, deep: bool = True) -> list[dict]:
    """L1：`show-ref` / `rev-parse HEAD` /（deep 时）`fsck --connectivity-only`。"""
    results: list[dict] = []

    r = _run_git(git_dir, explicit, ["show-ref"])
    ok = bool(r and r.returncode == 0 and (r.stdout or "").strip())
    n = len([l for l in (r.stdout or "").splitlines() if l.strip()]) if r else 0
    results.append({"id": "show-ref", "ok": ok,
                    "detail": f"show-ref 非空（{n} 条）" if ok else "show-ref 为空或失败"})

    r2 = _run_git(git_dir, explicit, ["rev-parse", "HEAD"])
    ok2 = bool(r2 and r2.returncode == 0 and (r2.stdout or "").strip())
    results.append({"id": "rev-parse-HEAD", "ok": ok2,
                    "detail": f"HEAD={r2.stdout.strip()[:12]}…" if ok2 else "rev-parse HEAD 失败"})

    if deep:
        r3 = _run_git(git_dir, explicit, ["fsck", "--connectivity-only", "--no-progress"],
                      timeout=300)
        text = ((r3.stdout or "") + (r3.stderr or "")) if r3 else ""
        bad = [ln for ln in text.splitlines()
               if re.search(r"\b(missing|broken|corrupt)\b", ln, re.IGNORECASE)]
        ok3 = r3 is not None and not bad
        detail = "fsck 无 missing/broken/corrupt" if ok3 else \
            f"fsck 报告 {len(bad)} 条对象问题：" + " | ".join(bad[:3])
        results.append({"id": "fsck-connectivity", "ok": ok3, "detail": detail})
    return results


# ── 报告 ──────────────────────────────────────────────────────────────────
def recovery_hint(git_dir: str) -> list[str]:
    """损坏态恢复提示：从权威源（纯只读文件）给出重建目标值来源。"""
    lines = ["── 恢复目标值来源（架构师三源交叉，纯只读）──"]
    orig = (_read_text(os.path.join(git_dir, "ORIG_HEAD")) or "").strip()
    if orig:
        lines.append(f"  · .git/ORIG_HEAD            : {orig}")
    fetch = (_read_text(os.path.join(git_dir, "FETCH_HEAD")) or "").strip()
    if fetch:
        first = fetch.split()[0] if fetch.split() else ""
        lines.append(f"  · .git/FETCH_HEAD (远程)    : {first}")
    ir = (_read_text(os.path.join(git_dir, "info", "refs")) or "").strip()
    if ir:
        for ln in ir.splitlines()[:5]:
            lines.append(f"  · .git/info/refs            : {ln.strip()}")
    headlog = (_read_text(os.path.join(git_dir, "logs", "HEAD")) or "").strip()
    if headlog:
        last = [l for l in headlog.splitlines() if l.strip()]
        if last:
            parts = last[-1].split()
            tgt = parts[1] if len(parts) > 1 else ""
            lines.append(f"  · .git/logs/HEAD 末条目标   : {tgt}")
    lines.append(f"  · 一键重建                  : python scripts/_git_guard.py --rebuild"
                 f"   # 从 {os.path.join(SNAP_DIR_DEFAULT, 'latest.json')}")
    return lines


def print_report(results: list[dict], git_dir: str, stream=sys.stdout,
                 quiet: bool = False) -> bool:
    """打印 L0 报告；quiet=True 时仅失败才输出。返回健康与否。"""
    ok = all_ok(results)
    if quiet and ok:
        return True
    for r in results:
        stream.write(f"{'✅' if r.get('ok') else '❌'} L0[{r['id']}] {r['detail']}\n")
    if not ok:
        stream.write(f"\n❌ 仓库健康门禁 L0 未过（git_dir={git_dir}）\n")
        stream.write("   含义：git 元数据损坏。git 的 is_git_directory() 要求 .git/refs 必须是目录，\n")
        stream.write("         缺失即报 `fatal: not a git repository`，所有 git 命令/门禁全线失效。\n")
        for ln in recovery_hint(git_dir):
            stream.write(ln + "\n")
    return ok


# ── refs 快照 ─────────────────────────────────────────────────────────────
def build_manifest(git_dir: str, note: str = "", explicit: bool = False) -> dict:
    """构建 refs 快照清单（纯文件读取 + 可选 git show-ref 附加信息）。"""
    refs_dir = os.path.join(git_dir, "refs")
    refs_files: dict[str, str] = {}
    for rel in _refs_entries(refs_dir):
        content = (_read_text(os.path.join(refs_dir, rel)) or "").strip()
        refs_files["refs/" + rel] = content

    show_ref: list[str] = []
    r = _run_git(git_dir, explicit, ["show-ref"])
    if r and r.returncode == 0:
        show_ref = [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
    head_sha = ""
    r2 = _run_git(git_dir, explicit, ["rev-parse", "HEAD"])
    if r2 and r2.returncode == 0:
        head_sha = (r2.stdout or "").strip()

    return {
        "schema": "git_refs_snapshot/1",
        "created_utc": _iso_utc(),
        "git_dir": git_dir,
        "note": note,
        "head": (_read_text(os.path.join(git_dir, "HEAD")) or "").strip(),
        "packed_refs": (_read_text(os.path.join(git_dir, "packed-refs")) or None),
        "refs_files": refs_files,
        "show_ref": show_ref,
        "rev_parse_head": head_sha,
    }


def write_snapshot(git_dir: str, out_dir: str | None = None, note: str = "",
                   explicit: bool = False) -> tuple[str, str, dict]:
    """落一份 refs 快照：`refs-<UTCstamp>.json` + `latest.json`（滚动最新指针）。"""
    out_dir = out_dir or SNAP_DIR_DEFAULT
    os.makedirs(out_dir, exist_ok=True)
    man = build_manifest(git_dir, note=note, explicit=explicit)
    path = os.path.join(out_dir, f"refs-{_stamp_utc()}.json")
    latest = os.path.join(out_dir, "latest.json")
    payload = json.dumps(man, ensure_ascii=False, indent=2)
    for p in (path, latest):
        with open(p, "w", encoding="utf-8") as f:
            f.write(payload)
    return path, latest, man


# ── 灾难重建 ──────────────────────────────────────────────────────────────
def _parse_packed_line(ln: str) -> tuple[str, str] | None:
    ln = ln.strip()
    if not ln or ln.startswith("#"):
        return None
    parts = ln.split(None, 1)
    if len(parts) == 2:
        return parts[0], parts[1].strip()
    return None


def rebuild(git_dir: str, manifest: dict, apply: bool = True) -> list[str]:
    """从快照重建 `refs/` + `packed-refs`。返回动作描述列表。

    硬约束：远程引用（`refs/remotes/**`）**绝不写 loose**，一律并入 `packed-refs`
    （本环境沙箱会静默回滚 loose 的 refs/remotes 写入并可能连坐删整棵 refs 树）。
    """
    actions: list[str] = []
    refs_root = os.path.join(git_dir, "refs")

    packed_out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _add_packed(sha: str, refname: str) -> None:
        if refname in seen:
            return
        seen.add(refname)
        packed_out.append((sha, refname))

    # 1) 既有 packed-refs 原样保留
    for ln in (manifest.get("packed_refs") or "").splitlines():
        pr = _parse_packed_line(ln)
        if pr:
            _add_packed(*pr)

    # 2) 快照里的 refs_files
    for rel, content in (manifest.get("refs_files") or {}).items():
        rel = str(rel).replace("\\", "/")
        if rel.startswith("refs/"):
            rel = rel[len("refs/"):]
        content = (content or "").strip()
        if not content or content.startswith("ref:"):
            continue
        refname = "refs/" + rel
        if rel.startswith("remotes/"):
            _add_packed(content, refname)
            actions.append(f"[packed] {refname} = {content}（远程引用禁写 loose）")
        else:
            p = os.path.join(refs_root, *rel.split("/"))
            if apply:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content + "\n")
            actions.append(f"[loose]  {refname} = {content}")

    # 3) 确保 refs 目录结构存在（git 的 is_git_directory 要求 refs/ 是目录）
    if apply:
        for sub in ("heads", "tags", "remotes"):
            os.makedirs(os.path.join(refs_root, sub), exist_ok=True)
    actions.append("mkdir refs/{heads,tags,remotes}")

    # 4) 写 packed-refs（裸行，无 `# pack-refs with:` 头——本环境带空尾缀头会报错）
    if packed_out:
        if apply:
            p = os.path.join(git_dir, "packed-refs")
            with open(p, "w", encoding="utf-8") as f:
                for sha, name in packed_out:
                    f.write(f"{sha} {name}\n")
        actions.append(f"[packed-refs] 写入 {len(packed_out)} 条（远程引用落此）")
    return actions


# ── CLI ───────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="git 仓库健康门禁 L0/L1 + refs 快照 + 灾难重建（2026-09-19 防复发）")
    ap.add_argument("--git-dir", default=None, help="显式指定 .git（默认自动定位）")
    ap.add_argument("--l1", action="store_true", help="L0 之后追加 L1（会调用 git）")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--quiet", action="store_true", help="仅失败时输出")
    ap.add_argument("--snapshot", action="store_true", help="落 refs 快照到 logs/git_refs_snapshot/")
    ap.add_argument("--out-dir", default=None, help="快照输出目录（默认 logs/git_refs_snapshot）")
    ap.add_argument("--note", default="", help="快照备注")
    ap.add_argument("--rebuild", action="store_true", help="从快照重建 refs/ + packed-refs")
    ap.add_argument("--from", dest="from_json", default=None, help="指定快照 JSON（配合 --rebuild）")
    ap.add_argument("--dry-run", action="store_true", help="--rebuild 只打印动作不落盘")
    args = ap.parse_args(argv)

    git_dir = resolve_git_dir(args.git_dir)
    explicit = bool(args.git_dir)

    # ── 快照 ──
    if args.snapshot:
        path, latest, man = write_snapshot(git_dir, out_dir=args.out_dir,
                                           note=args.note, explicit=explicit)
        if not args.quiet:
            print(f"✅ refs 快照已落盘：{path}")
            print(f"   最新指针：{latest}")
            print(f"   refs 项：{len(man.get('refs_files') or {})}；"
                  f"show-ref：{len(man.get('show_ref') or [])} 条")
        return 0

    # ── 重建 ──
    if args.rebuild:
        src = args.from_json or os.path.join(args.out_dir or SNAP_DIR_DEFAULT, "latest.json")
        if not os.path.isfile(src):
            print(f"❌ 找不到快照文件：{src}")
            print("   处置：先在有快照时跑 `python scripts/_git_guard.py --snapshot` 建立基线")
            return 1
        with open(src, encoding="utf-8") as f:
            man = json.load(f)
        actions = rebuild(git_dir, man, apply=not args.dry_run)
        print(f"{'（dry-run）' if args.dry_run else ''}从快照重建 refs/ + packed-refs：{src}")
        for a in actions:
            print(f"  · {a}")
        if args.dry_run:
            return 0
        ok = print_report(check_l0(git_dir), git_dir)
        print("✅ 重建后仓库健康" if ok else "❌ 重建后仍不健康，请人工介入")
        return 0 if ok else 1

    # ── 默认：L0（+L1）健康检查 ──
    l0 = check_l0(git_dir)
    ok = all_ok(l0)
    l1: list[dict] = []
    if args.l1 and ok:
        l1 = check_l1(git_dir, explicit=explicit, deep=True)
        ok = ok and all_ok(l1)

    if args.json:
        print(json.dumps({"git_dir": git_dir, "ok": ok, "l0": l0, "l1": l1},
                         ensure_ascii=False, indent=2))
    else:
        print_report(l0, git_dir, quiet=args.quiet)
        for r in l1:
            print(f"{'✅' if r.get('ok') else '❌'} L1[{r['id']}] {r['detail']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
