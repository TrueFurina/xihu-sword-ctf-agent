#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""文档↔实现一致性校验器（2026-08-23）。

背景：三轮锐评的终极裁定是「写文档不查证，没有用实测校验输出」。这个病反复
犯——G1 落地后，三处文档还声称「单写者全局租约 / G1 未落地」，从「诚实说明」
漂移成「过时谎言」。本脚本把两类**低误报、可机器校验**的漂移变成门禁。

校验三类（刻意收窄，宁漏勿误——误报会让门禁被关掉，重演「靠自觉」）：
1. 文件引用失效：文档引用的关键文件不存在（如 TASK_BOARD.md = 「开工必登记」无登记处）
2. 状态断言漂移：文档**使用**（非「提及」）过时的状态断言，与当前实现矛盾
3. KPI 数字漂移：文档/基线文件手写的 `offline_verified` 数字 ≠ 机器计数
   （2026-09-12 新增）——背景：specialcurve2 带证据晋级 12→13 后，
   `README.md` 与台账第二节标题都改了 13，但同一份台账的「第五节 当前诚实水位」
   表仍写 12 且仍称 specialcurve2「移出严格 KPI 并列入 KNOWN_GAP」，而当时
   26 个一致性/反注水测试**全绿**——因为本脚本只查措辞、不查数字。
   「唯一真值口径」不能只靠人记得同步，故把数字本身变成断言。

**刻意不校验**（误报不可控，根治法在别处）：
- 过时快照（git 哈希）：历史记录 vs 过时快照无法用正则区分
- 状态断言的根治是「单一事实源」——文档不手写状态、改从机器事实生成（见白皮书 §10）
- KPI 数字只锚定**明确的声明位**（README 指标表 / 台账第五节汇总行 / KPI_BASELINE.json），
  不全文搜数字——历史叙述里的「12→13」「回退 12→9」等演进记录是合法内容，搜全文必误报。

用法：
    python scripts/_doc_consistency.py             # 校验全部协同文档
    python scripts/_doc_consistency.py --cached    # 只校验暂存区文档
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import List, Optional, Tuple

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

# ── KPI 数字漂移（2026-09-12 新增）────────────────────────────────────────
# 唯一真值 = scripts/_merge_gate.count_offline_verified()（机器计数台账第二节 ✅ 题块）。
# 只锚定**明确声明位**，不全文搜数字：历史叙述里的「12→13」「回退 12→9」
# 是合法演进记录，全文搜必误报（本模块首条原则：宁漏勿误）。
_KPI_DECL_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (os.path.join(os.pardir, "README.md"),
     r"\|\s*\*\*offline_verified\*\*\s*\(strict real-problem KPI\)\s*\|\s*\*\*(\d+)\*\*"),
    ("REAL_SOLVES_LEDGER.md",
     r"\|\s*\*\*严格真题\s*offline_verified[^|]*\*\*\s*\|\s*\*\*(\d+)\*\*"),
)
_KPI_BASELINE_REL = os.path.join("data", "results", "KPI_BASELINE.json")


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


def _load_gov_module(name: str):
    """从 scripts/ 目录加载治理模块；失败返回 None（宁漏勿误，绝不因取数失败阻断门禁）。"""
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    try:
        return __import__(name)
    except Exception:
        return None


def machine_kpi_truth() -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """机器真值三元组 (count, watermark, baseline)；任一取不到则该位为 None。"""
    count: Optional[int] = None
    watermark: Optional[int] = None
    baseline: Optional[int] = None

    mg = _load_gov_module("_merge_gate")
    if mg is not None:
        try:
            count = int(mg.count_offline_verified())
        except Exception:
            count = None

    af = _load_gov_module("_antifraud")
    if af is not None:
        try:
            watermark = int(af.KPI_WATERMARK)
        except Exception:
            watermark = None

    try:
        with open(os.path.join(ROOT, _KPI_BASELINE_REL), encoding="utf-8") as fh:
            raw = json.load(fh).get("offline_verified")
        baseline = int(raw) if raw is not None else None
    except Exception:
        baseline = None

    return count, watermark, baseline


def check_kpi_number_consistency() -> List[str]:
    """KPI 数字漂移：声明位手写数字 ≠ 机器计数（2026-09-12 新增）。

    背景：specialcurve2 带证据晋级 12→13 后，README 与台账第二节标题都改成 13，
    但台账第五节「当前诚实水位」汇总行仍写 12、且仍称 specialcurve2「移出严格 KPI」
    ——而当时 26 个一致性/反注水测试全绿，因为旧校验只查措辞不查数字。
    """
    count, watermark, baseline = machine_kpi_truth()
    if count is None:
        return []  # 拿不到机器真值 → 不误报

    hits: List[str] = []

    # ① 文档声明位
    for rel, pattern in _KPI_DECL_PATTERNS:
        path = os.path.normpath(os.path.join(ROOT, rel))
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        m = re.search(pattern, text)
        if not m:
            continue  # 锚点不在（文档改版/删表）→ 不误报
        declared = int(m.group(1))
        if declared != count:
            hits.append(
                f"{os.path.normpath(rel)}: KPI 数字漂移——声明 offline_verified={declared}，"
                f"而机器计数 count_offline_verified()={count}（同一口径两个数字，必须同步）"
            )

    # ② 基线棘轮锚
    if baseline is not None and baseline != count:
        hits.append(
            f"{os.path.normpath(_KPI_BASELINE_REL)}: 基线 offline_verified={baseline} "
            f"≠ 机器计数 {count}（棘轮锚漂移）"
        )

    # ③ 派生不变式：KPI_WATERMARK = 地板基线 + 晋升数，必须等于机器计数
    if watermark is not None and watermark != count:
        hits.append(
            f"KPI_WATERMARK={watermark} ≠ 机器计数 {count}"
            f"（「水位 = 地板 + 晋升数」派生不变式被破坏）"
        )

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

    # KPI 数字漂移：全局不变式（不属于「某个文档」），与 --cached 无关，两种模式都跑。
    # 开销毫秒级（count_offline_verified 纯文本解析，无子进程）。
    all_hits.extend(check_kpi_number_consistency())

    if all_hits:
        print("❌ 文档↔实现一致性校验失败（漂移点）：")
        for h in all_hits:
            print(f"   - {h}")
        print("根因：写文档时未实测校验当前实现。请回写文档或更新断言。")
        return 1
    print("✅ 文档↔实现一致性校验通过（无状态断言漂移 / 文件引用失效 / KPI 数字漂移）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
