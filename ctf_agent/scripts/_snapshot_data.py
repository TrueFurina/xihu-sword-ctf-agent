#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""data/ 全量快照（对策：2026-10-12 / 2026-10-20 两次数据丢失事故）。

为什么需要它
------------
`data/` 全在 .gitignore 里（题库、附件、跑分结果、KPI 基线）。两次事故
（10-12 删了 50 题池 + 5 道真题附件；10-20 清空整棵 data/）都只能靠
「兄弟 worktree 恰好有副本」这种运气恢复——10-20 那次就因此永远丢了
`10725_cmsms-2.2.8-install.expanded.zip`。没有版本控制兜底时，唯一可靠
的保险是「定期落一份带 sha256 清单的物理副本」。

设计口径（与本仓治理习惯一致）
----------------------------
1. **只追加，不删除**。目标目录已存在即拒绝，绝不覆盖、绝不清理旧快照。
   保留策略交人决定：脚本只在快照数超过 `--warn-after` 时打印提醒。
2. **清单即真值**。每份快照带 `MANIFEST.json`：相对路径、字节数、mtime、
   sha256。恢复时按清单逐文件核对，不靠目录大小判断「看起来一样」。
3. **写完就验**。复制后重新遍历快照目录、逐文件重算 sha256 与源清单比对，
   不一致即返回非零——不允许"复制成功"这种没人验过的结论。
4. 默认落到 `E:/Program/西湖论剑/backups/`（仓外，不会被 git clean 波及）。

用法
----
    python scripts/_snapshot_data.py                      # 默认目标
    python scripts/_snapshot_data.py --out D:/bk         # 自定义根
    python scripts/_snapshot_data.py --verify-only <dir>  # 只校验已有快照
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(_ROOT, "data")
# 仓外默认落点：与 data/ 同级工程的 backups/，避免与仓库清理动作耦合
_DEFAULT_OUT = os.path.join(os.path.dirname(_ROOT), "backups")

MANIFEST_NAME = "MANIFEST.json"
_CHUNK = 1 << 20


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk(root: str):
    """按稳定顺序产出相对路径（POSIX 分隔符，跨平台清单可比）。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            ap = os.path.join(dirpath, fn)
            rel = os.path.relpath(ap, root).replace(os.sep, "/")
            out.append((rel, ap))
    return out


def build_manifest(root: str, exclude_dirs=()) -> dict:
    """遍历 root 生成清单。exclude_dirs 用相对路径前缀（快照目录自排除）。

    清单同时记 `dirs`（含空目录）：本仓 2026-10-21 实测过一条教训——
    `data/questions_external/` 变成空目录后 ~24 条用例连带失败。空目录是
    语义的一部分，恢复时不能省，所以校验要能发现「目录没了」。
    """
    files = []
    dirs = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for dn in dirnames:
            rel_d = os.path.relpath(os.path.join(dirpath, dn), root).replace(os.sep, "/")
            if any(rel_d == d or rel_d.startswith(d.rstrip("/") + "/") for d in exclude_dirs):
                continue
            dirs.append(rel_d)
        for fn in sorted(filenames):
            ap = os.path.join(dirpath, fn)
            rel = os.path.relpath(ap, root).replace(os.sep, "/")
            if any(rel == d or rel.startswith(d.rstrip("/") + "/") for d in exclude_dirs):
                continue
            st = os.stat(ap)
            item = {
                "path": rel,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
                "sha256": _sha256(ap),
            }
            files.append(item)
            total += st.st_size
    return {
        "schema": "data_snapshot/v1",
        "source": os.path.abspath(root),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "file_count": len(files),
        "dir_count": len(dirs),
        "total_bytes": total,
        "dirs": dirs,
        "files": files,
    }


def snapshot(src: str = DATA, out_root: str = _DEFAULT_OUT,
             name: str | None = None) -> str:
    """把 src 全量复制到 out_root/<name>，写清单并自校验，返回快照目录。

    目标已存在 → 抛 FileExistsError（只追加，绝不覆盖）。
    """
    if not os.path.isdir(src):
        raise FileNotFoundError(f"源目录不存在：{src}")
    os.makedirs(out_root, exist_ok=True)
    name = name or time.strftime("data_snapshot_%Y%m%d_%H%M%S")
    dst = os.path.join(out_root, name)
    if os.path.exists(dst):
        raise FileExistsError(f"快照目标已存在，按只追加口径拒绝覆盖：{dst}")

    manifest = build_manifest(src)

    # 先按清单建目录（含空目录），再逐个复制文件；copy2 保留 mtime
    os.makedirs(dst, exist_ok=True)
    for rel_d in manifest["dirs"]:
        os.makedirs(os.path.join(dst, rel_d.replace("/", os.sep)), exist_ok=True)
    for item in manifest["files"]:
        rel = item["path"]
        src_path = os.path.join(src, rel.replace("/", os.sep))
        target = os.path.join(dst, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(src_path, target)

    with open(os.path.join(dst, MANIFEST_NAME), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)

    problems = verify(dst)
    if problems:
        # 校验失败不回滚（不删任何东西），但必须让调用方看见
        raise RuntimeError(
            "快照自校验失败（快照保留在盘，请人工核对）：\n  "
            + "\n  ".join(problems[:10]))
    return dst


def verify(dst: str) -> list:
    """按清单逐文件重算 sha256，返回问题列表（空 = 全绿）。

    同时检查清单外的多余文件：快照目录里出现清单没有的文件也算异常
    （说明复制过程中源目录在变，这份快照不能当基线）。
    """
    mpath = os.path.join(dst, MANIFEST_NAME)
    if not os.path.isfile(mpath):
        return [f"缺清单：{mpath}"]
    with open(mpath, encoding="utf-8") as f:
        manifest = json.load(f)
    problems = []
    listed = set()
    for rel_d in manifest.get("dirs", []):
        ap = os.path.join(dst, rel_d.replace("/", os.sep))
        if not os.path.isdir(ap):
            problems.append(f"缺目录：{rel_d}")
    for item in manifest.get("files", []):
        rel = item["path"]
        listed.add(rel)
        ap = os.path.join(dst, rel.replace("/", os.sep))
        if not os.path.isfile(ap):
            problems.append(f"缺文件：{rel}")
            continue
        if os.path.getsize(ap) != item["size"]:
            problems.append(f"大小不符：{rel}")
            continue
        if _sha256(ap) != item["sha256"]:
            problems.append(f"哈希不符：{rel}")
    for rel, _ap in _walk(dst):
        if rel != MANIFEST_NAME and rel not in listed:
            problems.append(f"清单外多余文件：{rel}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="data/ 全量快照（只追加，带 sha256 清单）")
    ap.add_argument("--src", default=DATA, help="源目录（默认 ctf_agent/data）")
    ap.add_argument("--out", default=_DEFAULT_OUT, help="快照根目录（仓外）")
    ap.add_argument("--name", default=None, help="快照名（默认时间戳）")
    ap.add_argument("--warn-after", type=int, default=10,
                    help="快照数超过该值时提醒（不自动删）")
    ap.add_argument("--verify-only", default=None, metavar="DIR",
                    help="只校验已有快照目录，不复制")
    args = ap.parse_args(argv)

    if args.verify_only:
        problems = verify(args.verify_only)
        if problems:
            print(f"[snapshot] 校验失败 {len(problems)} 项：")
            for p in problems[:20]:
                print("  -", p)
            return 1
        print(f"[snapshot] 校验通过：{args.verify_only}")
        return 0

    try:
        dst = snapshot(args.src, args.out, args.name)
    except (FileExistsError, FileNotFoundError, RuntimeError) as e:
        print(f"[snapshot] 失败：{e}", file=sys.stderr)
        return 1

    with open(os.path.join(dst, MANIFEST_NAME), encoding="utf-8") as f:
        m = json.load(f)
    print(f"[snapshot] 完成：{dst}")
    print(f"[snapshot] {m['file_count']} 文件 / {m['total_bytes']:,} 字节 / "
          f"逐文件 sha256 校验通过")

    try:
        n = len([d for d in os.listdir(args.out)
                 if os.path.isdir(os.path.join(args.out, d))])
    except OSError:
        n = 0
    if n > args.warn_after:
        print(f"[snapshot] 提醒：{args.out} 已有 {n} 份快照（> {args.warn_after}）。"
              f"按只追加口径脚本不删旧快照，清理请人工决定。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
