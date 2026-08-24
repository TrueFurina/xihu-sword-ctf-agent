#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Reviewer 验收门禁（T-10，2026-08-23）。

白皮书 §6.2 设计：机器门禁管「形式上必然错」（二值/事前/可回归），Reviewer 管
「语义上错」（假解出/逻辑/正确性，机器管不了）。本脚本做 merge 前的**三项机器
检查**，第四项语义正确性留给人工单点 integrator（唯一 Reviewer，其余会话只读审查）。

三项机器检查：
1. pytest 全绿（回归基线，自动化）
2. diff 全在租约 scope 内（复用 `_lease.path_in_scope` + `_lease.load`）
3. 诚实口径（复用 `_honesty_scan.py`）

为什么单点而非多点：多 reviewer = 协调成本（谁先审/意见冲突），正是 Cognition
反方「写保持单点收敛、只读并行」的教训。Reviewer 是唯一 integrator。

用法：
    python scripts/_reviewer_gate.py --session <sid> [--base <base-commit>]
    python scripts/_reviewer_gate.py --session <sid> --skip-pytest   # 只查 scope+honesty（快）
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import _lease  # noqa: E402
import _honesty_scan  # noqa: E402


def out_of_scope_files(files: List[str], scope: List[str]) -> List[str]:
    """返回不在 scope 内的文件列表（纯函数，供单测）。"""
    return [f for f in files if not _lease.path_in_scope(f, scope)]


def check_pytest() -> Tuple[bool, str]:
    """跑 pytest -m 'not slow'，全绿返回 True。"""
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-m", "not slow", "-q", "--no-header"],
        cwd=ROOT, capture_output=True, text=True,
    )
    ok = r.returncode == 0
    tail = "\n".join((r.stdout or "").splitlines()[-3:])
    return ok, tail.strip() or "(无输出)"


def check_scope(session: str, base: str = "HEAD~1") -> Tuple[bool, str]:
    """检查 base..HEAD 的 diff 是否全在 session 租约 scope 内。"""
    doc = _lease.load()
    lease = doc.get("leases", {}).get(session) if doc else None
    if not lease:
        return False, f"会话 {session} 无租约（须先 acquire）"
    scope = lease["scope"]
    out = subprocess.run(
        ["git", "diff", "--name-only", "-z", f"{base}..HEAD"],
        cwd=ROOT, capture_output=True,
    )
    files = [p for p in out.stdout.decode("utf-8", errors="ignore").split("\0") if p.strip()]
    bad = out_of_scope_files(files, scope)
    if bad:
        return False, f"越界文件（不在 {session} 的 scope）: {bad[:5]}"
    return True, f"{len(files)} 个文件全在 scope 内"


def check_honesty() -> Tuple[bool, str]:
    """复用诚实口径扫描。"""
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "_honesty_scan.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    return r.returncode == 0, (r.stdout or "").strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="Reviewer 验收门禁（T-10）")
    ap.add_argument("--session", required=True)
    ap.add_argument("--base", default="HEAD~1", help="diff 基线（默认 HEAD~1）")
    ap.add_argument("--skip-pytest", action="store_true", help="跳过 pytest（快查 scope+honesty）")
    a = ap.parse_args()

    results: List[Tuple[str, bool, str]] = []
    if not a.skip_pytest:
        ok, msg = check_pytest()
        results.append(("pytest 全绿", ok, msg))
    ok, msg = check_scope(a.session, a.base)
    results.append(("diff 在 scope 内", ok, msg))
    ok, msg = check_honesty()
    results.append(("诚实口径", ok, msg))

    passed = True
    for name, ok, msg in results:
        mark = "✅" if ok else "❌"
        print(f"  {mark} {name}: {msg}")
        if not ok:
            passed = False

    if passed:
        print("✅ 机器验收通过（语义正确性仍须人工单点 Reviewer 终审）")
        return 0
    print("❌ 机器验收未通过，禁止 merge。修完重跑。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
