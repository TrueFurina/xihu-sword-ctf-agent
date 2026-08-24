#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""盲区聚合 + presolve 优化建议（P1 Step 2，2026-08-24）。

数据前提：benchmark 报告的 results[].confidence 非零（P1-1 置信度输出管道已通）。
判定盲区：confidence >= threshold 且 solved == False —— 模型"自信但错"的题，
是 presolve/skill 触发词优化的第一优先级候选。

输出：
  data/results/blindspots_<date>.json  —— 机器可读（供 _board.py 看板消费）
  data/results/presolve_hints_<date>.md —— 人工确认用的优化建议草稿

用法：
  python scripts/_blindspot.py                       # 用最新 benchmark_*.json
  python scripts/_blindspot.py --report <路径>       # 指定报告
  python scripts/_blindspot.py --threshold 0.8       # 自定义置信度阈值（默认 0.8）
"""
import argparse
import glob
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(ROOT, "data", "results")
SKILLS_DIR = os.path.join(ROOT, "skills")
DEFAULT_THRESHOLD = 0.8

# 类别 → skill 匹配依据：skills/*.json 的 categories 字段
CATEGORY_ALIASES = {
    "crypto": ("crypto",),
    "misc": ("misc",),
    "web": ("web",),
    "reverse": ("reverse", "reverse_engineering", "rev"),
    "pwn": ("pwn", "binary"),
    "forensics": ("forensics", "misc"),
}


def _latest_report() -> str:
    """取最新 benchmark 报告（benchmark_*.json 或 benchmark_report*.json 取 mtime 最新）。"""
    pats = (os.path.join(RESULTS_DIR, "benchmark_*.json"),
            os.path.join(RESULTS_DIR, "benchmark_report*.json"))
    cands = []
    for p in pats:
        cands.extend(glob.glob(p))
    if not cands:
        return ""
    return max(cands, key=os.path.getmtime)


def _load_skills() -> dict:
    """加载 skills/*.json 的 {name: categories} 映射。"""
    out = {}
    for f in glob.glob(os.path.join(SKILLS_DIR, "*.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
            out[d.get("name", os.path.basename(f)[:-5])] = list(
                d.get("categories", []))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def _skill_coverage(category: str, skills: dict) -> list:
    """该类别下有多少 skill 覆盖（categories 字段匹配）。"""
    aliases = CATEGORY_ALIASES.get(category, (category,))
    hits = []
    for name, cats in skills.items():
        if any(c in aliases for c in cats):
            hits.append(name)
    return hits


def analyze(report_path: str, threshold: float) -> dict:
    """聚合盲区：读报告 → 高置信未解出 → 按类别分组 + skill 覆盖对比。"""
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    results = report.get("results", [])
    skills = _load_skills()

    blindspots = []
    for r in results:
        conf = r.get("confidence", 0.0) or 0.0
        if conf >= threshold and not r.get("solved"):
            blindspots.append({
                "question_id": r.get("question_id", ""),
                "category": r.get("category", ""),
                "confidence": conf,
                "solved_by": r.get("solved_by", ""),
                "error": r.get("error"),
            })

    # 按类别聚合 + skill 覆盖度对比
    by_cat = {}
    for b in blindspots:
        cat = b["category"]
        by_cat.setdefault(cat, []).append(b)
    coverage = {}
    for cat, items in by_cat.items():
        hits = _skill_coverage(cat, skills)
        coverage[cat] = {
            "blindspot_count": len(items),
            "skills_covering": hits,
            "skills_missing": "无" if hits else f"该类别无现成 skill——需补 fast_solve 模板或新 skill",
        }

    return {
        "as_of": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "report": os.path.basename(report_path),
        "threshold": threshold,
        "total": len(results),
        "blindspot_count": len(blindspots),
        "blindspots": blindspots,
        "coverage": coverage,
        "note": "盲区 = 高置信但未解出（模型自信与正确脱钩的位置）；presolve 优化第一优先级。",
    }


def render_md(analysis: dict) -> str:
    """渲染人工确认用的 presolve 优化建议草稿。"""
    L = [f"# 盲区聚合 + presolve 优化建议（{analysis['as_of']}）",
         f"\n报告：`{analysis['report']}` | 阈值：confidence >= {analysis['threshold']}",
         f"盲区 {analysis['blindspot_count']} 道 / 总 {analysis['total']} 道\n"]
    if not analysis["blindspots"]:
        L.append("**无盲区**——当前报告中没有高置信未解出的题。")
        return "\n".join(L)
    L.append("## 盲区明细\n")
    L.append("| 题号 | 类别 | confidence | solved_by | error |")
    L.append("|---|---|---|---|---|")
    for b in analysis["blindspots"]:
        err = (b.get("error") or {}).get("category", "") if isinstance(b.get("error"), dict) else str(b.get("error") or "")
        L.append(f"| {b['question_id']} | {b['category']} | {b['confidence']:.2f} | "
                 f"{b.get('solved_by','')} | {err} |")
    L.append("\n## 类别覆盖度 → 优化建议\n")
    for cat, cov in analysis["coverage"].items():
        L.append(f"### {cat}（盲区 {cov['blindspot_count']} 道）")
        if cov["skills_covering"]:
            L.append(f"- 现有 skill：{', '.join(cov['skills_covering'])}")
            L.append("- 建议：核查这些 skill 的触发词/输入规格是否覆盖盲区题的题型；"
                     "若已覆盖仍失败，优先查工具链（factordb 网络/靶机部署）而非加模板。")
        else:
            L.append(f"- {cov['skills_missing']}")
            L.append("- 建议：人工确认后补 fast_solve 模板或新建 skill（禁止未经确认直接入库）。")
        L.append("")
    L.append("> 本文件是草稿：进 skills/ 前必须人工确认（防幻觉进 skill）。")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="盲区聚合 + presolve 建议（P1 Step 2）")
    ap.add_argument("--report", default="", help="benchmark 报告路径（默认取最新）")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                    help=f"置信度阈值（默认 {DEFAULT_THRESHOLD}）")
    ap.add_argument("--out", default=RESULTS_DIR, help="输出目录")
    args = ap.parse_args()

    report = args.report or _latest_report()
    if not report or not os.path.isfile(report):
        print(f"❌ 未找到 benchmark 报告（{report}）。先跑：python -m eval.benchmark ...")
        return 1

    analysis = analyze(report, args.threshold)
    os.makedirs(args.out, exist_ok=True)
    ts = time.strftime("%Y%m%d", time.gmtime())
    jpath = os.path.join(args.out, f"blindspots_{ts}.json")
    mpath = os.path.join(args.out, f"presolve_hints_{ts}.md")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(analysis, fh, ensure_ascii=False, indent=2)
    with open(mpath, "w", encoding="utf-8") as fh:
        fh.write(render_md(analysis))

    print(f"✅ 盲区聚合完成：{analysis['blindspot_count']} 道（confidence >= {args.threshold}）")
    print(f"   JSON: {jpath}")
    print(f"   MD  : {mpath}")
    if analysis["coverage"]:
        for cat, cov in analysis["coverage"].items():
            print(f"   [{cat}] 盲区 {cov['blindspot_count']} 道，skill 覆盖: "
                  f"{len(cov['skills_covering'])} 个")
    return 0


if __name__ == "__main__":
    sys.exit(main())
