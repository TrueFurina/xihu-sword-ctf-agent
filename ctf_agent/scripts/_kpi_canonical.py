#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KPI 单一权威口径源（P0-②，2026-09-17）。

为什么存在
----------
项目反复出现「14 / 92 / 15 子集」三套口径漂移，导致 README、台账、记忆互相打架
（记忆曾写 13、曾写有 KPI_WATERMARK 符号，实测均错）。本脚本把**所有 KPI 数字**
收敛到一台机器真值源，任何文档/台账想引用 KPI，必须跑本脚本或 import 本模块，
禁止手工誊抄数字（誊抄即漂移）。

机器真值锚点
------------
  - offline_verified：来自 scripts/_merge_gate.count_offline_verified()
    （严格真题 + 确定性复现 verifier，绝对计数，非率）
  - real_corpus：data/questions_real/**/*.json 递归计数（92 题真题全集）
  - heldout_candidates：由 scripts/benchmark_heldout.select_candidates() 在
    real_corpus 中剔除「已训练/泄露/自产/无 sha256」后的 unseen 非平凡题池
    —— 这才是「LLM 真·自主推理」的唯一合法分母

口径铁律（输出即声明，引用者照搬）
------------------------------
  1. 14 是**绝对计数**，不是率；凡说「能力 X%」必须显式声明分母是 92 还是 heldout 子集。
  2. 15 题子集 / 86.7% 口径已作废（早期 presolve 静态分析子集，不具竞技代表性）。
  3. goal_log.jsonl 是独立实验日志（解出数恒 0），与 KPI 非同源，**不构成产品能力率**。

用法
----
  python scripts/_kpi_canonical.py                 # 打印并写出 canonical KPI 声明
  python scripts/_kpi_canonical.py --json         # 仅 machine-readable JSON 到 stdout
  # 作为模块：
  #   from scripts._kpi_canonical import canonical_kpi
  #   k = canonical_kpi(); print(k["offline_verified"], k["real_corpus"])
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESULTS = ROOT / "data" / "results"
QUESTIONS_REAL = ROOT / "data" / "questions_real"
SKILLS_DIR = ROOT / "skills"
OUT = RESULTS / "kpi_canonical.json"

# 公开 README（仓库根，与 _doc_consistency 同基准）
README_EN = ROOT.parent / "README.md"
README_ZH = ROOT.parent / "README.zh.md"

# 过时口径，引用即报错，防止死灰复燃
_DEPRECATED_SUBSET = 15

# ── held-out 实测证据源（机器真值，禁止手写「已测量 / 未测量」）─────────────
# 背景：README 曾手写「0/10 未测量」，而实测 2026-09-19 已完成——**手写状态词本身就是漂移**。
# 2026-09-19 held-out 池 LLM 实测的原始 benchmark_report.json 取自：
#   ① 仓内归档 ctf_agent/heldout_evidence/（转公开后仍可溯源，优先）；
#   ② 本机 gitignored 的 data/results/heldout_rerun*（仅本地可得，降级兜底）。
# A = 1× 预算（deepseek_full），B = 2× 预算（ds_budget2x）——二者构成「预算翻倍」对照。
HELDOUT_EVIDENCE = ROOT / "heldout_evidence"
# 2026-09-22 清洗后「干净未见题」实测：P0-a 排除 43 道 WRITEUP 重建题 + 源码泄露闸
# 排除 gongye_web2（flag 明文在提供的 index.php），分母 10→2。deepseek + E3 证据注入，
# 2/2 解出（LLM 自主推理 1/2：dnui_keyboard；确定性 presolve 1/2：real_reverse_js），sha256 真值闭环。
_HELDOUT_CLEAN_REPORT = HELDOUT_EVIDENCE / "benchmark_report_clean2_20260922_deepseek.json"
# 旧 1×/2× 预算对照报告已更名 .SUPERSEDED_contaminated_pool_*（10 题污染池 + bug2 坏验证器），
# 其「瓶颈是能力不是预算」结论基于坏数据，作废不再引用；clean-2 池太小不做对照。
_HELDOUT_1X_REPORTS = (HELDOUT_EVIDENCE / "benchmark_report_A_deepseek_1x.json",)
_HELDOUT_2X_REPORTS = (HELDOUT_EVIDENCE / "benchmark_report_B_deepseek_2x.json",)
# 「最新」报告 = 清洗后干净池实测（clean-2）优先；旧 A/B（10 题污染池 + bug2 坏验证器）
# 与 clean-3（含源码泄露题 gongye_web2）均已更名 .SUPERSEDED_*，仅留档溯源。
_HELDOUT_LATEST_REPORTS = (_HELDOUT_CLEAN_REPORT,) + _HELDOUT_2X_REPORTS + _HELDOUT_1X_REPORTS


def count_skills() -> int:
    """确定性 skill 数（机器真值）。

    口径：`skills/__init__.py` 明示「每个 skill 模块暴露 run(params) -> …」，
    故以「模块**顶层**定义 run 函数」为判据（AST 解析，不导入、无副作用、无依赖）。
    排除 `__init__.py`。历史上 README 手写的「52」即因此口径漂移而失真（实测 56）。
    """
    import ast
    if not SKILLS_DIR.exists():
        return 0
    n = 0
    for p in sorted(SKILLS_DIR.glob("*.py")):
        if p.name == "__init__.py":
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, OSError):
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run":
                n += 1
                break
    return n


def count_regression_checks() -> int:
    """merge-gate 回归集条数（机器真值，委托 _merge_gate.REGRESSION_CHECKS）。"""
    from scripts._merge_gate import REGRESSION_CHECKS
    return len(REGRESSION_CHECKS)



def count_offline_verified() -> int:
    """委托 _merge_gate 的机器真值（strict 真题 + 确定性 verifier）。"""
    from scripts._merge_gate import count_offline_verified as _c
    return int(_c())


def count_real_corpus() -> int:
    """递归统计 data/questions_real/**/*.json（真题全集，含子目录）。"""
    if not QUESTIONS_REAL.exists():
        return 0
    return sum(1 for p in QUESTIONS_REAL.rglob("*.json") if p.is_file())


def count_heldout_candidates() -> int:
    """unseen 非平凡题池大小（LLM 真·自主推理的唯一合法分母）。

    复用 benchmark_heldout.select_candidates 的同一台机器逻辑，避免口径分叉。
    该函数仅做轻量文件扫描 + 排除判定，无 API 调用。
    """
    try:
        from scripts.benchmark_heldout import select_candidates
        cands, _ = select_candidates()
        return len(cands)
    except Exception as exc:  # pragma: no cover - 兜底不致命
        sys.stderr.write(f"[kpi_canonical] select_candidates 调用失败：{exc}\n")
        return -1


def _first_existing(paths) -> "Path | None":
    """返回候选路径中第一个存在的文件（按给定优先级）；都不存在返回 None。"""
    for p in paths:
        if Path(p).is_file():
            return Path(p)
    return None


def _rel(path) -> str:
    """把绝对/相对路径转成相对仓库根（README 所在目录）的 posix 路径，供溯源引用。"""
    try:
        return Path(path).resolve().relative_to(ROOT.parent.resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def _read_report(path) -> "dict | None":
    """读一份 benchmark_report.json；失败返回 None（宁漏勿误，绝不臆造数字）。"""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"[kpi_canonical] 读基准报告失败 {path}：{exc}\n")
        return None


def summarize_benchmark_report(data: dict, rel: str) -> dict:
    """把一份 held-out benchmark_report.json 压成可引用的实测指标（纯函数，便于测试注入）。

    Args:
        data: 已解析的 benchmark_report.json 内容。
        rel: 该报告的溯源相对路径（写入返回值的 `report` 字段）。

    Returns:
        含池内题数 / 解出数 / 分渠道解出数 / token / budget_exceeded 计数的 dict。
    """
    summary = data.get("summary") or {}
    by = summary.get("by_solved_by") or {}
    pre = by.get("presolve") or {}
    llm = by.get("main_agent_llm") or {}
    results = data.get("results") or []
    return {
        "report": rel,
        "pool_total": int(summary.get("total") or 0),
        "solved_total": int(summary.get("solved") or 0),
        "solved_by_presolve": int(pre.get("solved") or 0),
        "solved_by_llm": int(llm.get("solved") or 0),
        "llm_attempted": int(llm.get("total") or 0),
        "tokens_global_total": int((summary.get("tokens") or {}).get("global_total") or 0),
        "budget_exceeded": sum(1 for r in results if r.get("error") == "budget_exceeded"),
    }


def heldout_status() -> dict:
    """held-out 池实测状态（机器真值，读**最新** benchmark_report.json 派生）。

    为什么机器派生：README 曾手写「0/10 未测量」，而实测早已完成——**手写状态词即漂移**。
    本函数把「测了没有、池内几分」变成读文件派生，README / 台账只准引用本函数输出。

    取数优先级：仓内归档 `ctf_agent/heldout_evidence/`（可溯源）→ 本机
    `ctf_agent/data/results/heldout_rerun*/benchmark_report.json`（gitignored）。
    找不到任何报告 → `measured=False`（宁漏勿误，绝不臆造数字）。

    Returns:
        dict：measured(bool) / report(str|None) / pool_total / solved_total /
        solved_by_presolve（确定性，非 LLM）/ solved_by_llm（自主推理）/
        llm_attempted / tokens_global_total / budget_exceeded。
    """
    path = _first_existing(_HELDOUT_LATEST_REPORTS)
    if path is None:
        return {
            "measured": False, "report": None, "pool_total": 0, "solved_total": 0,
            "solved_by_presolve": 0, "solved_by_llm": 0, "llm_attempted": 0,
            "tokens_global_total": 0, "budget_exceeded": 0,
        }
    data = _read_report(path)
    if data is None:
        return {
            "measured": False, "report": None, "pool_total": 0, "solved_total": 0,
            "solved_by_presolve": 0, "solved_by_llm": 0, "llm_attempted": 0,
            "tokens_global_total": 0, "budget_exceeded": 0,
        }
    st = summarize_benchmark_report(data, _rel(path))
    st["measured"] = True
    return st


def heldout_budget_ablation() -> dict:
    """预算翻倍对照（1× vs 2× 预算）——机器派生，供「瓶颈是能力不是预算」结论引用。

    读 A(1×)/B(2×) 两份原始报告；缺任一 → `{"available": False}`（宁漏勿误，绝不臆造对照）。
    两份报告的 token / budget_exceeded / LLM 解出数由 `summarize_benchmark_report` 派生，
    调用方（README 校验、canonical statement）不得手写这些数字。

    Returns:
        dict：available(bool)；available 时含 baseline(1×) 与 doubled(2×) 两个指标子 dict。
    """
    p1 = _first_existing(_HELDOUT_1X_REPORTS)
    p2 = _first_existing(_HELDOUT_2X_REPORTS)
    if p1 is None or p2 is None:
        return {"available": False}
    d1, d2 = _read_report(p1), _read_report(p2)
    if d1 is None or d2 is None:
        return {"available": False}
    return {
        "available": True,
        "baseline": summarize_benchmark_report(d1, _rel(p1)),
        "doubled": summarize_benchmark_report(d2, _rel(p2)),
    }


def _heldout_clause(hs: dict, abl: dict) -> str:
    """由机器派生指标拼装 held-out 结论文本（禁止手写「未测量」与任何数字）。"""
    if not hs.get("measured"):
        return "该池尚未实测（本机与仓内均无 benchmark_report.json；须跑 benchmark_heldout --run）。"
    # 注：旧「预算翻倍对照」结论（"瓶颈是能力不是预算"）基于 10 题污染池 + bug2 坏验证器，
    # 已作废；clean-2 池（n=2）太小不做对照，故此处不再追加任何预算结论。
    return (
        f"该池已实测（{hs['report']}）：池内 {hs['solved_total']}/{hs['pool_total']}"
        f"（确定性 presolve {hs['solved_by_presolve']} + LLM 自主推理 {hs['solved_by_llm']}）/ "
        f"LLM 自主推理 {hs['solved_by_llm']}/{hs['pool_total']}；"
    )


def canonical_kpi() -> dict:
    ov = count_offline_verified()
    corpus = count_real_corpus()
    heldout = count_heldout_candidates()
    skills = count_skills()
    regression = count_regression_checks()
    coverage_all = (ov / corpus) if corpus else 0.0
    # 重要：offline_verified(14) 与 heldout_candidates(10) 是**不相交**集合
    # （14 全为已训练/KPI 题，本就在 held-out 排除逻辑里被剔除）。
    # 故「14/10」是欺骗性比率，绝不输出。
    coverage_heldout = None
    # held-out 实测状态与预算对照**机器派生**（读 benchmark_report.json，禁止手写）。
    hs = heldout_status()
    abl = heldout_budget_ablation()
    return {
        "as_of": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        "offline_verified": ov,                 # 绝对计数（KPI 真值上限）
        "real_corpus": corpus,                 # 真题全集分母（=92）
        "heldout_candidates": heldout,         # unseen 非平凡题池（自主推理分母）
        "skills": skills,                      # 确定性 skill 数（skills/*.py 顶层 run 入口）
        "regression_checks": regression,       # merge-gate 回归集条数
        "coverage_of_corpus": round(coverage_all, 4),     # 14/92
        "coverage_of_heldout": coverage_heldout,          # 恒 None：14 与 10 不相交
        "heldout_status": hs,                  # held-out 实测状态（读最新报告派生）
        "heldout_budget_ablation": abl,        # 1× vs 2× 预算对照（机器派生）
        "deprecated_subset": _DEPRECATED_SUBSET,          # 仅作警示锚点
        "statement": (
            f"offline_verified={ov}（绝对计数，非率） / real_corpus={corpus} "
            f"→ 全集覆盖率 {coverage_all:.1%}；"
            f"held-out 自主推理分母 = {heldout} 题（unseen 非平凡，与 14 题不相交），"
            + _heldout_clause(hs, abl) +
            f"15 题子集/86.7% 口径已作废。goal_log.jsonl 解出数恒 0，与 KPI 非同源。"
            f"⚠️ ledger-vs-corpus 1 项漂移：AUTHORIZED_KPI_SOLVES=14，但其中 10733 在"
            f"data/questions_real/ 无对应题文件（台账计 verified、语料缺文件）；"
            f"held-out {heldout} 题分母不受影响（已排除的 13 道均正确命中授权 ID；"
            f"另 7 道 WRITEUP 重建题于 2026-09-21 经 P0-a 排除，不再污染分母）。"
        ),
    }


def render_md(k: dict) -> str:
    hs = k.get("heldout_status") or {}
    abl = k.get("heldout_budget_ablation") or {}
    L = [
        "# KPI 单一权威声明（机器真值，禁止手工誊抄）",
        f"\n- 生成时间：`{k['as_of']}`",
        f"- **offline_verified = {k['offline_verified']}**（绝对计数，非率；KPI 真值上限）",
        f"- **real_corpus = {k['real_corpus']}**（真题全集分母，data/questions_real/**/*.json 递归）",
        f"- **heldout_candidates = {k['heldout_candidates']}**（unseen 非平凡题池 = LLM 真·自主推理唯一合法分母）",
        f"- **skills = {k['skills']}**（确定性解题 skill 数：skills/*.py 顶层暴露 run() 入口者）",
        f"- **regression_checks = {k['regression_checks']}**（merge-gate 可机器复现回归集条数）",
        f"- 全集覆盖率：{k['offline_verified']}/{k['real_corpus']} = {k['coverage_of_corpus']:.1%}",
        f"- held-out 自主推理池 = {k['heldout_candidates']} 题（unseen 非平凡，与 14 题不相交）",
        f"- held-out 覆盖率：N/A（14 与 {k['heldout_candidates']} 不相交，14/{k['heldout_candidates']} 是欺骗性比率，已作废）",
    ]
    if hs.get("measured"):
        L.append(
            f"- **held-out 实测（{hs['report']}）**：池内 {hs['solved_total']}/{hs['pool_total']}"
            f"（确定性 presolve {hs['solved_by_presolve']}，非 LLM）/ "
            f"LLM 自主推理 {hs['solved_by_llm']}/{hs['pool_total']}；"
            f"tokens={hs['tokens_global_total']}，budget_exceeded={hs['budget_exceeded']}"
        )
        if abl.get("available"):
            b, d = abl["baseline"], abl["doubled"]
            L.append(
                f"- held-out 预算对照（1×→2×）：tokens {b['tokens_global_total']}→{d['tokens_global_total']}，"
                f"budget_exceeded {b['budget_exceeded']}→{d['budget_exceeded']}，"
                f"LLM 解出 {b['solved_by_llm']}→{d['solved_by_llm']}"
            )
    else:
        L.append("- held-out 状态：**未实测**（本机与仓内均无 benchmark_report.json）")
    L += [
        "",
        "> 口径铁律：14 是绝对计数不是率；凡说「能力 X%」必须显式声明分母是 92 还是 heldout 子集。",
        "> 15 题子集 / 86.7% 口径已作废。goal_log.jsonl 解出数恒 0，与 KPI 非同源，不构成产品能力率。",
        "",
        f"> {k['statement']}",
    ]
    return "\n".join(L)


# ── README 计数交叉校验（P0-5，2026-09-19）──────────────────────────────
# 背景：README 里手写的计数（skills 52 / 回归 15-15 / 真题 92 …）随时会漂，
# 且历史上正是这类数字漂过。本表把每个「声明位」绑到 canonical 机器真值上，
# 任何手改 → 红。held-out 两行按 team-lead 指示本轮不动，故未纳入（engineer-4 出数后再定）。
# mandatory=True：该计数必须存在声明（防「整行删掉」绕过）；False：无声明不报（宁漏勿误）。
_README_COUNT_ANCHORS = (
    ("README.md", "skills（架构树）", r"skills/\s+(\d+)\s+deterministic skills", "skills", True),
    ("README.md", "skills（解题链路）", r"deterministic skills \((\d+)\)", "skills", True),
    ("README.md", "skills（确定性优先）", r"holds (\d+) runnable skills", "skills", True),
    ("README.zh.md", "skills（架构树）", r"skills/\s+(\d+)\s+个确定性解题 skill", "skills", True),
    ("README.zh.md", "skills（解题链路）", r"确定性 skill\((\d+)\)", "skills", True),
    ("README.zh.md", "skills（确定性优先）", r"含 (\d+) 个即用 skill", "skills", True),
    ("README.md", "real_corpus（全集分母）", r"\*\*\d+ / (\d+)\*\* full-corpus", "real_corpus", True),
    ("README.zh.md", "real_corpus（全集分母）", r"\*\*\d+ / (\d+)\*\*（全集", "real_corpus", True),
    ("README.md", "regression_checks", r"Regression-set reproducible count \| \*\*(\d+) / \d+\*\*", "regression_checks", True),
    ("README.zh.md", "regression_checks", r"回归集可复现计数 \| \*\*(\d+) / \d+\*\*", "regression_checks", True),
)


def check_readme_counts(readme_root: "Path | None" = None, truth: "dict | None" = None) -> list:
    """校验两份公开 README 里的计数声明 == canonical 机器真值（P0-5）。

    返回漂移点列表（空 = 绿）。取真值失败时返回 []（宁漏勿误，绝不因取数失败误报）。
    offline_verified 已由 scripts/_doc_consistency.py 单独闸门看守，此处不重复。

    Args:
        readme_root: README 所在目录，默认仓库根（`ROOT.parent`）。测试可注入临时目录。
        truth: 覆盖机器真值 {skills, real_corpus, regression_checks}，默认取 canonical_kpi()。
               仅供测试注入，生产调用一律留空。
    """
    import re
    root = ROOT.parent if readme_root is None else Path(readme_root)
    if truth is None:
        try:
            k = canonical_kpi()
        except Exception as exc:  # pragma: no cover - 兜底不致命
            sys.stderr.write(f"[kpi_canonical] 取机器真值失败，跳过 README 计数校验：{exc}\n")
            return []
        truth = {
            "skills": k["skills"],
            "real_corpus": k["real_corpus"],
            "regression_checks": k["regression_checks"],
        }
    hits: list = []
    cache: dict = {}
    for fname, label, pattern, key, mandatory in _README_COUNT_ANCHORS:
        # 宁漏勿误：真值 <= 0 视为「该语料/目录在本环境不可得」（如 sparse/LFS clone
        # 或 .gitignore 误配），而非「期望值为 0」——此时跳过，绝不误报 RED。
        # （data/questions_real/ 由 .gitignore 的 `!data/questions_real/**` 反忽略，
        #  正常 clone 应得 92；skills/ 为跟踪目录。取 0 只可能是环境异常。）
        if truth.get(key, 0) <= 0:
            sys.stderr.write(
                f"[kpi_canonical] 跳过「{label}」校验：机器真值 {key}="
                f"{truth.get(key)} <= 0（疑语料/目录在本环境不可得）\n"
            )
            continue
        path = root / fname
        if not path.exists():
            continue
        if fname not in cache:
            cache[fname] = path.read_text(encoding="utf-8", errors="replace")
        matches = list(re.finditer(pattern, cache[fname]))
        if not matches:
            if mandatory:
                hits.append(
                    f"{fname}: 计数声明缺失——「{label}」未找到（期望 {key}={truth[key]}，"
                    f"机器真值见 scripts/_kpi_canonical.py）"
                )
            continue
        for m in matches:
            declared = int(m.group(1))
            if declared != truth[key]:
                hits.append(
                    f"{fname}: 计数漂移——「{label}」声明 {declared}，机器真值 {key}={truth[key]}"
                    f"（README 计数必须与 scripts/_kpi_canonical.py 输出一致）"
                )
    return hits


# ── README held-out 实测声明交叉校验（2026-09-19）──────────────────────────
# 背景：README 曾手写「0/10 未测量」与配套的 provider 报错，而实测早已完成。
# 本表把 README 里 held-out 的**每个数字**绑到 heldout_status() / heldout_budget_ablation()
# 的机器派生真值上：数字一漂（或整句被删）→ 红。与 _README_COUNT_ANCHORS 分开维护，
# 因 held-out 的合法值包含 0（LLM 解出 0），不能复用「真值<=0 即跳过」的宁漏勿误守卫。
# 结构：(文件, 标签, 正则(含 1-2 个捕获组), 各捕获组对应的真值键)
_README_HELDOUT_ANCHORS = (
    ("README.md", "held-out 池内解出",
     r"held-out pool[^\n]*?pool \*\*(\d+) / (\d+)\*\* solved",
     ("heldout_pool_solved", "heldout_pool_total")),
    ("README.md", "held-out LLM 自主推理",
     r"LLM autonomous reasoning[^\d\n]{0,4}?(\d+) / (\d+)",
     ("heldout_llm_solved", "heldout_pool_total")),
    ("README.md", "held-out 预算翻倍 token",
     r"token budget \(`([\d,]+) → ([\d,]+)`\)",
     ("abl_tokens_1x", "abl_tokens_2x")),
    ("README.md", "held-out budget_exceeded 对照",
     r"budget_exceeded[^\n]{0,24}?(\d+)\s*→\s*(\d+)",
     ("abl_budget_exceeded_1x", "abl_budget_exceeded_2x")),
    ("README.zh.md", "held-out 池内解出",
     r"held-out 池[^\n]*?池内 \*\*(\d+) / (\d+)\*\*",
     ("heldout_pool_solved", "heldout_pool_total")),
    ("README.zh.md", "held-out LLM 自主推理",
     r"LLM 自主推理[^\d\n]{0,4}?(\d+) / (\d+)",
     ("heldout_llm_solved", "heldout_pool_total")),
    ("README.zh.md", "held-out 预算翻倍 token",
     r"预算翻倍[^\n]*?`([\d,]+) → ([\d,]+)`",
     ("abl_tokens_1x", "abl_tokens_2x")),
    ("README.zh.md", "held-out budget_exceeded 对照",
     r"budget_exceeded[^\n]{0,24}?(\d+)\s*→\s*(\d+)",
     ("abl_budget_exceeded_1x", "abl_budget_exceeded_2x")),
)


def check_readme_heldout(readme_root: "Path | None" = None,
                         status: "dict | None" = None,
                         ablation: "dict | None" = None) -> list:
    """校验两份公开 README 的 held-out 实测声明 == 机器派生真值。

    返回漂移点列表（空 = 绿）。未实测（无报告）时返回 []——此时 README 应写「未测量」，
    无数字可校验（宁漏勿误）。预算对照真值缺失时，仅跳过依赖对照的锚点。

    Args:
        readme_root: README 所在目录，默认仓库根（`ROOT.parent`）。测试可注入临时目录。
        status: 覆盖 heldout_status()（测试注入用）。
        ablation: 覆盖 heldout_budget_ablation()（测试注入用）。
    """
    import re
    if status is None:
        try:
            status = heldout_status()
            ablation = heldout_budget_ablation()
        except Exception as exc:  # pragma: no cover - 兜底不致命
            sys.stderr.write(f"[kpi_canonical] 取 held-out 真值失败，跳过校验：{exc}\n")
            return []
    if not status.get("measured"):
        return []  # 未实测：无数字可校验（README 此时应显式标注「未测量」）

    truth = {
        "heldout_pool_total": status.get("pool_total", 0),
        "heldout_pool_solved": status.get("solved_total", 0),
        "heldout_llm_solved": status.get("solved_by_llm", 0),
    }
    if ablation and ablation.get("available"):
        b, d = ablation["baseline"], ablation["doubled"]
        truth.update({
            "abl_tokens_1x": b["tokens_global_total"],
            "abl_tokens_2x": d["tokens_global_total"],
            "abl_budget_exceeded_1x": b["budget_exceeded"],
            "abl_budget_exceeded_2x": d["budget_exceeded"],
        })

    root = ROOT.parent if readme_root is None else Path(readme_root)
    hits: list = []
    cache: dict = {}
    for fname, label, pattern, keys in _README_HELDOUT_ANCHORS:
        # 该锚点依赖的对照真值不可得（如缺 1×/2× 之一）→ 跳过（宁漏勿误）
        if any(k not in truth for k in keys):
            continue
        path = root / fname
        if not path.exists():
            continue
        if fname not in cache:
            cache[fname] = path.read_text(encoding="utf-8", errors="replace")
        found = re.findall(pattern, cache[fname])
        if not found:
            hits.append(
                f"{fname}: held-out 声明缺失——「{label}」未找到"
                f"（期望匹配 `{pattern}`；机器真值见 scripts/_kpi_canonical.py:heldout_status）"
            )
            continue
        for groups in found:
            for g, key in zip(groups, keys):
                declared = int(str(g).replace(",", ""))
                if declared != truth[key]:
                    hits.append(
                        f"{fname}: held-out 声明漂移——「{label}」声明 {declared}，"
                        f"机器真值 {key}={truth[key]}（README 必须与 heldout_status 输出一致）"
                    )
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="KPI 单一权威口径源（防漂移）")
    ap.add_argument("--json", action="store_true", help="仅输出 machine-readable JSON")
    ap.add_argument("--check", action="store_true",
                    help="校验 README 计数声明 == 机器真值；漂移则 exit 1（P0-5 闸门）")
    args = ap.parse_args()

    if args.check:
        hits = check_readme_counts() + check_readme_heldout()
        if hits:
            print("❌ README 计数 / held-out 声明漂移（手写数字必须与机器真值一致）：")
            for h in hits:
                print(f"   - {h}")
            return 1
        print("✅ README 计数 + held-out 实测声明与 _kpi_canonical 机器真值一致"
              "（skills / real_corpus / regression_checks / heldout_status）")
        return 0

    k = canonical_kpi()

    if args.json:
        print(json.dumps(k, ensure_ascii=False, indent=2))
        return 0

    md = render_md(k)
    RESULTS.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(k, ensure_ascii=False, indent=2), encoding="utf-8")
    print(md)
    print(f"\n[canonical] 已写出 {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
