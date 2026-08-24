#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""文档↔实现一致性校验器（2026-08-23）。

背景：三轮锐评的终极裁定是「写文档不查证，没有用实测校验输出」。这个病反复
犯——G1 落地后，三处文档还声称「单写者全局租约 / G1 未落地」，从「诚实说明」
漂移成「过时谎言」。本脚本把两类**低误报、可机器校验**的漂移变成门禁。

校验两类（刻意收窄，宁漏勿误——误报会让门禁被关掉，重演「靠自觉」）：
1. 文件引用失效：文档引用的关键文件不存在（如 TASK_BOARD.md = 「开工必登记」无登记处）
2. 状态断言漂移：文档**使用**（非「提及」）过时的状态断言，与当前实现矛盾

**刻意不校验**（误报不可控，根治法在别处）：
- 过时快照（git 哈希）：历史记录 vs 过时快照无法用正则区分
- 状态断言的根治是「单一事实源」——文档不手写状态、改从机器事实生成（见白皮书 §10）

用法：
    python scripts/_doc_consistency.py             # 校验全部协同文档
    python scripts/_doc_consistency.py --cached    # 只校验暂存区文档
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_ROOT = os.path.abspath(os.path.join(ROOT, "..", "deliverables"))

# 过时断言 → 当前现实（文档「使用」这些短语即与实现矛盾）
_STALE_ASSERTIONS = {
    "单写者全局租约": "已落地为目录级多写者租约（_lease.py scopes_conflict）",
    "单写者互斥锁": "已升级为目录级多写者租约",
    "G1 未落地": "G1 已于 2026-08-23 落地",
    "G1 尚未落地": "G1 已落地",
    "目录级并行尚未落地": "目录级并行已落地（G1）",
}

# 引号剥离（使用-提及区分）：「单写者全局租约」/ "..." 是「提及」，不是「使用」
_QUOTE_RE = re.compile(r"「[^」]*」|『[^』]*』|“[^”]*”|“[^”]*”|\"[^\"]*\"")
# 否定表述排除：「不再是单写者全局租约锁」是「否定」，不是「声称是」
_NEGATE_RE = re.compile(r"(不再|不再是|已不|并非|并非还是)[^。\n]*")
# 关键文件：文档引用但必须存在（缺 = 「开工必登记」连登记处都没有）
_REQUIRED_FILES = ("TASK_BOARD.md",)

# 批判/审查类文档：它们引用过时断言是在「批评」它，是「提及」而非「使用」
_SKIP_DOC_KEYWORDS = ("锐评", "评审", "评估", "复查")


def _strip_quoted(text: str) -> str:
    return _QUOTE_RE.sub("", text)


def collect_docs() -> List[str]:
    docs: List[str] = []
    for dp, dirnames, fns in os.walk(DOC_ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", ".venv", "__pycache__")]
        for fn in fns:
            if fn.endswith(".md"):
                docs.append(os.path.join(dp, fn))
    agents = os.path.join(ROOT, "AGENTS.md")
    if os.path.isfile(agents):
        docs.append(agents)
    return docs


def check_stale_assertions(path: str, text: str) -> List[str]:
    """状态断言漂移：文档「使用」过时断言（排除提及/否定/批判文档）。"""
    if any(k in path for k in _SKIP_DOC_KEYWORDS):
        return []
    hits: List[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = _strip_quoted(line)
        for phrase, reality in _STALE_ASSERTIONS.items():
            if phrase not in stripped:
                continue
            # 排除否定表述（"不再是单写者全局租约锁"）
            if _NEGATE_RE.search(stripped) and phrase in _NEGATE_RE.search(stripped).group(0):
                continue
            hits.append(f"{path}:{idx}: 过时断言「{phrase}」——现实现实是「{reality}」")
    return hits


def check_missing_files() -> List[str]:
    """文件引用失效：关键文件不存在。"""
    hits: List[str] = []
    for fn in _REQUIRED_FILES:
        found = False
        for base in (ROOT, DOC_ROOT):
            for dp, dirnames, fns in os.walk(base):
                dirnames[:] = [d for d in dirnames if d not in (".git", ".venv", "__pycache__")]
                if fn in fns:
                    found = True
                    break
            if found:
                break
        if not found:
            hits.append(f"引用失效：文档引用的关键文件「{fn}」不存在（全盘未找到）——「开工必登记」无登记处")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="文档↔实现一致性校验器")
    ap.add_argument("--cached", action="store_true", help="只校验暂存区文档")
    args = ap.parse_args()

    if args.cached:
        try:
            raw = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "-z"],
                cwd=ROOT, capture_output=True, check=True,
            ).stdout
            docs = [os.path.join(ROOT, p) for p in raw.decode("utf-8", errors="ignore").split("\0")
                    if p and p.endswith(".md")]
        except Exception:
            docs = []
    else:
        docs = collect_docs()

    all_hits: List[str] = []
    for path in docs:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        all_hits.extend(check_stale_assertions(path, text))

    if not args.cached:
        all_hits.extend(check_missing_files())

    if all_hits:
        print("❌ 文档↔实现一致性校验失败（漂移点）：")
        for h in all_hits:
            print(f"   - {h}")
        print("根因：写文档时未实测校验当前实现。请回写文档或更新断言。")
        return 1
    print("✅ 文档↔实现一致性校验通过（无状态断言漂移 / 文件引用失效）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
