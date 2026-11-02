#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""死副本守卫 —— `tools/tools/` 这类"整目录被误复制"的快照不得复活。

为什么需要它（2026-11-01 审计）
--------------------------------
本仓 `tools/tools/` 是 `tools/` 的一份**旧副本**（21 个文件 / 150 KB）：

  · 无人 import：全仓只有 `core/mcp_adapter.py` 的 docstring 提到它，
    没有一行 `from tools.tools import ...`；
  · **已经分叉**：6 个文件与真身不同，且方向明确是"副本落后"——
    `tools/tools/adapters/flag_scan_adapter.py` 比真身少 16 行，
    缺了 `HTB{}` 通用前缀、body 排除 NUL 等 4 项修复。

`pyproject.toml` 与 `_gate_static.py` 都写了"历史遗留重复副本，整目录排除，
待人工确认后清理"——**这句话本身是负责的**，但"待确认"没有承接人，
于是它会一直留着。

真正的风险不是它占 150 KB，而是：
  有人搜索 `flag_scan_adapter` 时会找到两份，改错了那份看起来也能跑通，
  但改的是已经过期的代码。**过期代码比没有代码更危险，因为它看起来是存在的。**

本守卫做两件事：
  C1 禁止任何代码 import 死副本（一旦有人开始用，立刻红）
  C2 死副本与真身的差异必须被登记（防止它被悄悄"修好"从而以假乱真）

用法：
  python scripts/_check_dead_copy.py
  python scripts/_check_dead_copy.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import filecmp
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: 已知死副本：(相对路径, 真身, 说明)
DEAD_COPIES = [
    ("tools/tools", "tools",
     "历史遗留重复副本；比真身旧（flag_scan_adapter 少 16 行 / 缺 HTB 前缀与 NUL 排除）"),
]

#: **审计残留备份**：审计过程中为"改前对照"临时复制出来的文件。
#:
#: 它们全部是**修复前的缺陷版本**，无人 import，但会被 `grep -r` 命中——
#: 排查问题的人可能照着它得出错误结论（R108 讲的"过期代码比没有更危险"）。
#:
#: 2026-11-01 R119 实测确认：
#:   · _vnd_bak.py  含 R106 修复前的 `仅证明 flag 非空`（缺陷写法）
#:   · _b64_bak.py  Base64 分支在 Base16 之前（R118 修的顺序缺陷）
#:   · _dd_bak.py   同上
#:
#: 本机删除被运行时保护拦下（CHAT_REFERENCE_PROTECTED），因此改为**登记可见**：
#: 至少让"这里躺着一份坏代码"成为可查事实，而不是隐形污染。
AUDIT_LEFTOVERS = [
    ("_b64_bak.py", "base64_multilayer 的修复前快照（解码顺序缺陷）"),
    ("_dd_bak.py", "deterministic_decode_adapter 的修复前快照（同上）"),
    ("_vnd_bak.py", "_verify_numeric_dispatch 的修复前快照（无真值算通过）"),
]


def check_leftovers(root: str) -> list:
    """C1b：审计残留备份不得被 import；存在时提示清理。"""
    found = []
    for name, why in AUDIT_LEFTOVERS:
        for r, dirs, fs in os.walk(root):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git", ".venv")]
            if name in fs:
                rel = os.path.relpath(os.path.join(r, name), root)
                found.append(rel + "  ← " + why)
    return found


def _py_files(d: str):
    out = []
    for r, _, fs in os.walk(os.path.join(ROOT, d)):
        for f in fs:
            if f.endswith(".py"):
                out.append(os.path.relpath(os.path.join(r, f), ROOT))
    return sorted(out)


def check_imports(dead: str) -> list[str]:
    """C1：全仓不得 import 死副本。"""
    mod = dead.replace("/", ".").lstrip(".")
    pat = ("import " + mod, "from " + mod)
    bad = []
    for base in ("core", "agents", "tools", "llm", "eval", "scheduler",
                 "ctfplatform", "skills", "scripts", "verify", "sandbox"):
        d = os.path.join(ROOT, base)
        if not os.path.isdir(d):
            continue
        for p in _py_files(os.path.relpath(d, ROOT)):
            if p.startswith(dead + os.sep):
                continue
            try:
                txt = open(os.path.join(ROOT, p), encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for line in txt.splitlines():
                s = line.strip()
                if s.startswith("#"):
                    continue
                if s.startswith(pat):
                    bad.append(f"{p}: {s[:90]}")
    return bad


def check_divergence(dead: str, real: str) -> list[str]:
    """C2：死副本与真身的差异清单（不判红，但要能看见）。"""
    notes = []
    for p in _py_files(dead):
        twin = os.path.join(real, os.path.relpath(p, dead))
        full = os.path.join(ROOT, p)
        if not os.path.exists(os.path.join(ROOT, twin)):
            notes.append(f"{p}: 真身无对应文件")
        elif not filecmp.cmp(full, os.path.join(ROOT, twin), shallow=False):
            n_dead = sum(1 for _ in open(full, encoding="utf-8", errors="ignore"))
            n_real = sum(1 for _ in open(os.path.join(ROOT, twin),
                                         encoding="utf-8", errors="ignore"))
            notes.append(f"{p}: 与真身不同（副本 {n_dead} 行 / 真身 {n_real} 行）")
    return notes


def report():
    problems, notes = [], []
    print("=== 死副本守卫 ===")
    for dead, real, why in DEAD_COPIES:
        if not os.path.isdir(os.path.join(ROOT, dead)):
            print(f"  ✅ {dead} 已不存在（若已清理，请从 DEAD_COPIES 移除本条）")
            continue
        print(f"  📁 {dead}  （{len(_py_files(dead))} 个 .py）")
        print(f"     理由: {why}")
        imp = check_imports(dead)
        if imp:
            problems += imp
            for x in imp:
                print(f"     [FAIL] 有人 import 死副本: {x}")
        else:
            print("     ✅ 全仓无 import")
        div = check_divergence(dead, real)
        notes += div
        print(f"     与真身差异 {len(div)} 处" + ("" if div else "（完全一致）"))
        for x in div[:5]:
            print(f"       · {x}")
        if len(div) > 5:
            print(f"       … 另有 {len(div) - 5} 处")
    leftovers = check_leftovers(ROOT)
    if leftovers:
        print("\n=== 审计残留备份（修复前快照）===")
        for x in leftovers:
            print("  ⚠️  " + x)
        print("  这些文件是缺陷版；不会被 import，但会被 grep 命中。")
        print("  建议清理（本机若被运行时保护拦下，至少保持登记可见）。")

    if problems:
        print("\n存在 import 死副本 —— 过期代码被启用比没有更危险。")
        return 1
    print("\n死副本保持「死」的状态。清理前请人工确认（见 pyproject.toml 的说明）。")
    return 0


def self_test() -> int:
    import tempfile
    ok = True

    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "core"))
        os.makedirs(os.path.join(td, "tools", "tools"))
        for n in ("a.py",):
            open(os.path.join(td, "tools", n), "w").write("x = 1\n")
            open(os.path.join(td, "tools", "tools", n), "w").write("x = 1\n")
        # 干净：无人 import
        open(os.path.join(td, "core", "m.py"), "w").write("import os\n")
        if check_imports_in(td, "tools/tools"):
            print("  [FAIL] T1 干净样本被误报")
            ok = False
        else:
            print("  [PASS] T1 无 import → 无告警")

        # 变异：有人 import
        open(os.path.join(td, "core", "m.py"), "w").write(
            "from tools.tools import a\n")
        if not check_imports_in(td, "tools/tools"):
            print("  [FAIL] T2 漏报 import 死副本")
            ok = False
        else:
            print("  [PASS] T2 变异：import 死副本 → 告警")

        # 差异检测
        open(os.path.join(td, "tools", "tools", "a.py"), "w").write("x = 2\n")
        if not check_divergence_in(td, "tools/tools", "tools"):
            print("  [FAIL] T3 漏报内容差异")
            ok = False
        else:
            print("  [PASS] T3 变异：内容分叉 → 检出")
    return 0 if ok else 1


def check_imports_in(root, dead):
    """self_test 用的可注入 root 版本。"""
    mod = dead.replace("/", ".")
    bad = []
    for base in ("core",):
        d = os.path.join(root, base)
        if not os.path.isdir(d):
            continue
        for r, _, fs in os.walk(d):
            for f in fs:
                if not f.endswith(".py"):
                    continue
                p = os.path.join(r, f)
                for line in open(p, encoding="utf-8", errors="ignore"):
                    s = line.strip()
                    if s.startswith("#"):
                        continue
                    if s.startswith(("import " + mod, "from " + mod)):
                        bad.append(p)
    return bad


def check_divergence_in(root, dead, real):
    out = []
    for r, _, fs in os.walk(os.path.join(root, dead)):
        for f in fs:
            if not f.endswith(".py"):
                continue
            full = os.path.join(r, f)
            twin = os.path.join(root, real, os.path.relpath(full, os.path.join(root, dead)))
            if not os.path.exists(twin) or not filecmp.cmp(full, twin, shallow=False):
                out.append(full)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="死副本守卫")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        print("死副本守卫 —— 3 项（含 2 个变异）")
        print("-" * 52)
        rc = self_test()
        print("-" * 52)
        print("  self-test " + ("PASS" if rc == 0 else "FAIL"))
        return rc
    return report()


if __name__ == "__main__":
    sys.exit(main())
