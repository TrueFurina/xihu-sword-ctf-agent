#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""7 步链路失败步统计（P1 Step 3，2026-08-24）。

数据源：data/results/goal_log.jsonl（每行一条解题尝试记录）。
目标：按「最远成功到达步」归类每次失败，输出失败率直方图——
定位失败率最高的步，按误差复利数学（删一步 > 加固一步）给出删除/降级/加固建议。

7 步链路（与 goal_log 字段映射）：
  1 平台轮询   task_id 为空 / question_type 为空
  2 分诊       skill_require 为空（无攻击方向）
  3 附件下载   error_struct.category=env_failure（附件/靶机不可达）
  4 presolve   solved_by=presolve 且失败（skill 未命中）
  5 LLM 主 Agent  error_struct.category ∈ {stuck_loop, wrong_direction,
                hallucination, wallclock_timeout, tool_failure}（LLM/工具链失败）
  6 校验       flag 非空但 validated=False（候选 flag 被拒 = 假 flag）
  7 提交       平台 accepted 失败（本地记录无此步，预留）

输出：
  data/results/chain_stats_<date>.json  —— 机器可读（供 _board.py 看板消费）
  data/results/chain_stats_<date>.md    —— 人类可读直方图 + 建议

用法：
  python scripts/_chain_stats.py                       # 默认读 goal_log.jsonl
  python scripts/_chain_stats.py --log <路径>          # 指定日志
"""
import argparse
import json
import os
import sys
import time
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOG = os.path.join(ROOT, "data", "results", "goal_log.jsonl")
RESULTS_DIR = os.path.join(ROOT, "data", "results")

STEPS = ["1_平台轮询", "2_分诊", "3_附件下载", "4_presolve", "5_LLM主Agent",
         "6_校验", "7_提交"]

# error_struct.category → 失败步（第 5 步细分）
LLM_CATS = {"stuck_loop", "wrong_direction", "hallucination",
            "wallclock_timeout", "tool_failure"}
EXTRACT_CAT = "extract_fail"
ENV_CATS = {"env_failure"}


def classify(record: dict) -> str:
    """把一条记录归到"最远成功到达步"（失败发生在该步）。

    返回 "成功" 表示记录是解出的（flag 存在且 validated），不进失败直方图。
    """
    flag = record.get("flag")
    validated = record.get("validated")
    es = record.get("error_struct") or {}
    cat = es.get("category", "") if isinstance(es, dict) else ""

    # 成功路径：flag 存在且通过校验 → 不是失败步（不进直方图）
    if flag and validated:
        return "成功"
    # 优先：flag 已产生但未通过校验 → 第 6 步（假 flag）
    if flag and not validated:
        return "6_校验"
    # presolve 失败标记（solved_by=presolve 且无 flag 且未 validated）
    if record.get("solved_by") == "presolve" and not flag and not validated:
        return "4_presolve"
    # 环境/附件类失败 → 第 3 步
    if cat in ENV_CATS:
        return "3_附件下载"
    # 工具/LLM 类失败 → 第 5 步
    if cat in LLM_CATS:
        return "5_LLM主Agent"
    # 提取校验失败 → 第 6 步
    if cat == EXTRACT_CAT:
        return "6_校验"
    # 无任何错误信息：task_id/question_type 为空 → 第 1-2 步（早期断裂）
    if not flag and not validated:
        if not record.get("task_id") or not record.get("question_type"):
            return "1_平台轮询"
        if not record.get("skill_require"):
            return "2_分诊"
        return "1_平台轮询"
    # 兜底：无法归类
    return "未知"


def analyze(log_path: str) -> dict:
    """解析 goal_log → 失败步直方图 + 每步失败明细。"""
    if not os.path.isfile(log_path):
        raise FileNotFoundError(log_path)
    total = 0
    step_counter = Counter()
    unknown_detail = []
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            step = classify(rec)
            step_counter[step] += 1
            if step == "未知":
                unknown_detail.append(rec.get("error") or rec.get("error_struct") or "")
    # 输出完整 7 步（含 0 计数），便于直方图稳定渲染
    steps = {}
    for s in STEPS:
        steps[s] = {
            "count": step_counter.get(s, 0),
            "pct": round(100.0 * step_counter.get(s, 0) / total, 1) if total else 0.0,
        }
    unknown = step_counter.get("未知", 0)
    worst = max((s for s in STEPS if steps[s]["count"]), key=lambda s: steps[s]["count"],
                default="")
    return {
        "as_of": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "log": os.path.basename(log_path),
        "total": total,
        "steps": steps,
        "unknown": {"count": unknown, "detail_sample": unknown_detail[:5]},
        "worst_step": worst,
        "recommendation": _recommend(worst, steps),
        "note": "删一步 > 加固一步（误差复利：单步 95% × 10 步 ≈ 59.9%）；"
                "最高失败步优先删除/降级，次高步才加固。",
    }


def _recommend(worst: str, steps: dict) -> str:
    if not worst:
        return "无失败记录（全部解出或日志为空）"
    cnt = steps[worst]["count"]
    pct = steps[worst]["pct"]
    if worst == "5_LLM主Agent":
        return (f"第 5 步（LLM主Agent）失败 {cnt} 次（{pct}%）——最高失败步。"
                f"处置：presolve 命中题直接跳过 LLM 步；LLM 步加止损/降级 provider，"
                f"而不是加固提示词（删一步 > 加固一步）。")
    if worst == "6_校验":
        return (f"第 6 步（校验）失败 {cnt} 次（{pct}%）——假 flag 占比高。"
                f"处置：提取校验前先核对 flag 模板/附件真值；校验失败立即回 presolve，"
                f"不重试 LLM 同路径（防误差复利）。")
    if worst == "1_平台轮询":
        return (f"第 1 步（平台轮询）失败 {cnt} 次（{pct}%）——早期断裂。"
                f"处置：优先修平台 API 字段映射（赛时 get_access/endpoints 错配教训）；"
                f"轮询失败直接降级本地题库，不等平台。")
    return (f"第 {worst} 失败 {cnt} 次（{pct}%）——核查该步依赖（附件/skill/工具链）"
            f"是否为可降级项（本地 presolve 兜底）。")


def render_md(stats: dict) -> str:
    L = [f"# 7 步链路失败步统计（{stats['as_of']}）",
         f"\n数据源：`{stats['log']}` | 总尝试 {stats['total']} 次\n",
         "## 失败步直方图\n",
         "| 步骤 | 失败次数 | 占比 | 条形 |",
         "|---|---|---|---|"]
    for s in STEPS:
        d = stats["steps"][s]
        bar = "#" * max(1, int(d["pct"] / 5))
        L.append(f"| {s} | {d['count']} | {d['pct']}% | {bar} |")
    if stats["unknown"]["count"]:
        L.append(f"| 未知 | {stats['unknown']['count']} | — | |")
    L.append(f"\n## 最高失败步：{stats['worst_step'] or '无'}\n")
    L.append(stats["recommendation"])
    if stats["unknown"]["detail_sample"]:
        L.append(f"\n### 未归类样本（{len(stats['unknown']['detail_sample'])} 条）")
        for s in stats["unknown"]["detail_sample"]:
            L.append(f"- `{str(s)[:120]}`")
    L.append("\n> 建议按误差复利数学处置：删一步 > 加固一步；加固只用于次高失败步。")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="7 步链路失败步统计（P1 Step 3）")
    ap.add_argument("--log", default=DEFAULT_LOG, help="goal_log 路径")
    ap.add_argument("--out", default=RESULTS_DIR, help="输出目录")
    args = ap.parse_args()

    try:
        stats = analyze(args.log)
    except FileNotFoundError:
        print(f"❌ 未找到日志：{args.log}")
        return 1

    os.makedirs(args.out, exist_ok=True)
    ts = time.strftime("%Y%m%d", time.gmtime())
    jpath = os.path.join(args.out, f"chain_stats_{ts}.json")
    mpath = os.path.join(args.out, f"chain_stats_{ts}.md")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(stats, fh, ensure_ascii=False, indent=2)
    with open(mpath, "w", encoding="utf-8") as fh:
        fh.write(render_md(stats))

    print(f"✅ 失败步统计完成：总 {stats['total']} 次，最高失败步 = "
          f"{stats['worst_step'] or '无'}")
    for s in STEPS:
        d = stats["steps"][s]
        if d["count"]:
            print(f"   {s}: {d['count']} 次（{d['pct']}%）")
    print(f"   JSON: {jpath}")
    print(f"   MD  : {mpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
