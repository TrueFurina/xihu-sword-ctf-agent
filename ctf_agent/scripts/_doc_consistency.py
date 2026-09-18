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
    (os.path.join(os.pardir, "README.zh.md"),
     r"\|\s*\*\*offline_verified\*\*[^|]*\|\s*\*\*(\d+)\*\*"),
    ("REAL_SOLVES_LEDGER.md",
     r"\|\s*\*\*严格真题\s*offline_verified[^|]*\*\*\s*\|\s*\*\*(\d+)\*\*"),
)
# 公开声明文件：**必须**在诚实 KPI 表格中保留 offline_verified 声明行。
# 2026-09-19 新增——本次事故中 README.zh.md 全文 0 次出现 offline_verified，
# 中文版根本没提唯一机器强制的 KPI，而旧闸门「锚点缺失不误报」的取舍让它静默放行。
# 对这两个文件，锚点缺失 = 漂移（防「把声明行整行删掉」这种绕过方式）。
# 其余文件（如 REAL_SOLVES_LEDGER.md）保持原「锚点缺失不报」行为不变。
_KPI_DECL_MANDATORY: Tuple[str, ...] = ("README.md", "README.zh.md")

# ── KPI 正文习语交叉校验（2026-09-19 新增，D2）────────────────────────────
# 旧闸门只锚定**明确声明位**（表格行），正文散文里的手写数字永远匹配不到——
# 本次 README.md L80 正文写 `offline_verified=13`（表格是 14）就这么溜过去的。
# 零误报依据（已复跑确认）：合法的历史演进叙述一律用**箭头式**习语
# （`12→13`、`回退 12→9`、`nominal 12 to 9`），从不使用 `offline_verified=<n>`。
# 全仓 `offline_verified[=＝]<n>` 扫描只在两个公开 README 里命中声明数字；
# `.workbuddy/memory/**` 等历史记录里有大量合法旧值（5/9/12），故本规则
# **只扫这两个明确路径**，绝不扩展到全仓 `.md`（全仓扫必误报）。
_KPI_INLINE_IDIOM_RE = re.compile(r"offline_verified\s*[=＝]\s*(\d+)")
_KPI_INLINE_SCAN_FILES: Tuple[str, ...] = ("README.md", "README.zh.md")

# LLM 自主推理贡献：合法分母只有两个——KPI 集（=机器计数 count）与 held-out 池。
# `0 / <分母>` 里分母 ∉ 白名单即报漂移（本次捕获 L80/L84 的 0/13 与 ZH 的 0/1）。
_KPI_CONTRIB_MARKERS: Tuple[str, ...] = ("contribution", "自主推理贡献")
_KPI_CONTRIB_RATIO_RE = re.compile(r"0\s*/\s*(\d+)")

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


def _repo_root() -> str:
    """仓库根（= ctf_agent 的上一级），即两个公开 README 所在目录。

    README 声明锚点、正文习语扫描、mandatory 文件均以仓库根为基准；
    与 _KPI_DECL_PATTERNS 里 `os.path.join(os.pardir, ...)` 的路径解析一致。
    """
    return os.path.normpath(os.path.join(ROOT, os.pardir))


def _read_text(path: str) -> Optional[str]:
    """读文本；文件不存在或不可读返回 None（宁漏勿误）。"""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _kpi_allowed_denominators(count: int) -> set:
    """LLM 自主推理贡献的合法分母集合：KPI 集（=count）与 held-out 池。

    held-out 分母**必须**取自 `_kpi_canonical`（KPI 单一权威入口），禁止硬编码——
    这是项目铁律。取不到时只保留 {count}，绝不因取数失败而误报。
    """
    dens = {count}
    kc = _load_gov_module("_kpi_canonical")
    if kc is not None:
        try:
            heldout = int(kc.count_heldout_candidates())
            if heldout > 0:
                dens.add(heldout)
        except Exception:
            pass
    return dens


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

    # ① 文档声明位：声明数字 ≠ 机器计数 → 报漂移
    # matched_decl：normpath → 该文件是否至少匹配上一个声明锚点（供 ①b 判定缺失）
    matched_decl: dict = {}
    for rel, pattern in _KPI_DECL_PATTERNS:
        path = os.path.normpath(os.path.join(ROOT, rel))
        text = _read_text(path)
        if text is None:
            continue
        m = re.search(pattern, text)
        if not m:
            matched_decl.setdefault(path, False)  # 锚点不在 → 记录缺失（不报，见 ①b）
            continue
        matched_decl[path] = True
        declared = int(m.group(1))
        if declared != count:
            hits.append(
                f"{os.path.normpath(rel)}: KPI 数字漂移——声明 offline_verified={declared}，"
                f"而机器计数 count_offline_verified()={count}（同一口径两个数字，必须同步）"
            )

    # ①b 公开声明文件必须保留声明行（2026-09-19 新增）——防「把声明行整行删掉」这种绕过。
    # 本次事故：README.zh.md 全文 0 次出现 offline_verified，旧闸门静默放行。
    repo_root = _repo_root()
    for name in _KPI_DECL_MANDATORY:
        path = os.path.normpath(os.path.join(repo_root, name))
        if not os.path.isfile(path):
            continue  # 文件本身不存在 → 不是「删声明行」，交给别的门禁
        if matched_decl.get(path, False):
            continue
        hits.append(
            f"{name}: KPI 声明缺失——公开声明文件必须在诚实 KPI 表格中保留 "
            f"`offline_verified` 声明行（期望 `| **offline_verified** ... | **{count}** |`）；"
            f"整行删除/改版视为漂移（机器计数 count_offline_verified()={count}）"
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


def check_kpi_inline_idiom_drift() -> List[str]:
    """KPI 正文习语 + LLM 贡献分母交叉校验（2026-09-19 新增）。

    只扫 `README.md` / `README.zh.md` 两个**公开**文件，做两件事：

    D2（习语漂移）：用 `offline_verified\\s*[=＝]\\s*(\\d+)` 扫**全文**（不止表格），
    任何数字 ≠ 机器计数 → 报 hit。旧闸门只锚定表格行，本次 README.md 正文
    `offline_verified=13`（表格为 14）永远匹配不到，就这么溜过去了。

    零误报依据（已复跑确认）：合法历史叙述一律用**箭头式**（`12→13`、`回退 12→9`、
    `nominal 12 to 9`），从不使用 `offline_verified=<n>`；全仓扫描仅在这两个 README
    里命中声明数字（其余 `.md` 命中 `.workbuddy/memory` 等历史记录里的合法旧值 5/9/12），
    故**只扫这两个明确路径**，绝不扩展全仓。

    D3（分母白名单）：含 `contribution` / `自主推理贡献` 的行，`0 / <分母>` 的分母
    必须 ∈ {机器计数 count, held-out 池大小}；held-out 池取自 `_kpi_canonical`
    （单一权威入口，禁止硬编码）。本次捕获 L80/L84 的 `0/13` 与 ZH 的 `0/1`。
    """
    count, _watermark, _baseline = machine_kpi_truth()
    if count is None:
        return []  # 拿不到机器真值 → 不误报

    allowed_dens = _kpi_allowed_denominators(count)
    repo_root = _repo_root()
    hits: List[str] = []

    for name in _KPI_INLINE_SCAN_FILES:
        path = os.path.normpath(os.path.join(repo_root, name))
        text = _read_text(path)
        if text is None:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            # D2：正文习语 `offline_verified=<n>` 必须等于机器计数
            for m in _KPI_INLINE_IDIOM_RE.finditer(line):
                declared = int(m.group(1))
                if declared != count:
                    hits.append(
                        f"{name}:{idx}: 正文习语漂移——`offline_verified={declared}` "
                        f"≠ 机器计数 {count}（习语必须等于 count_offline_verified()）"
                    )
            # D3：LLM 自主推理贡献行的分母白名单
            if any(marker in line for marker in _KPI_CONTRIB_MARKERS):
                for m in _KPI_CONTRIB_RATIO_RE.finditer(line):
                    denom = int(m.group(1))
                    if denom not in allowed_dens:
                        hits.append(
                            f"{name}:{idx}: LLM 自主推理贡献分母非法——`0/{denom}`，"
                            f"合法分母只有 {sorted(allowed_dens)}"
                            f"（KPI 集 = 机器计数 {count}；held-out 池 = _kpi_canonical）"
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
    # KPI 正文习语 / LLM 贡献分母交叉校验（2026-09-19 新增）：只扫两个公开 README。
    all_hits.extend(check_kpi_inline_idiom_drift())

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
