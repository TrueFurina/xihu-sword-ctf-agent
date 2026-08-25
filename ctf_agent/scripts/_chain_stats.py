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


# ── 3.2 失败子类学（A-F）：把 5_LLM主Agent 失败再分桶 ──
# 数据源同 goal_log；识别特征以 error_struct.category / class4 为准
# （goal_log 无"附件是否已读但 prompt 未含"等细粒度信号，C/C2 采用
#  tool_failure / 超时兜底映射，并在输出注明数据局限）。
SUBCLASSES = [
    ("A",  "输出格式崩",   "JSON 解析失败 / action 缺字段"),
    ("B",  "方向决策错",   "步骤空转 / 重复同动作"),
    ("C",  "证据不进脑",   "附件已读但 prompt 未含内容"),
    ("C2", "上下文遗忘",   "关键参数在后轮丢失"),
    ("D",  "修正无效",     "correction 注入后仍同错"),
    ("E",  "模型能力不足", "以上都不是（含响应超时 wallclock_timeout）"),
    ("F",  "flag 提取失败", "解出但输出无 flag / 提取被拒"),
]

# error_struct.category → 子类（基于 goal_log 现有信号）
_SUBCAT_BY_CAT = {
    "stuck_loop": "B",
    "wrong_direction": "B",
    "wallclock_timeout": "E",
    "extract_fail": "F",
    "tool_failure": "C",
    "hallucination": "A",
}
# error_struct.class4 → 子类（category 缺省时兜底）
_SUBCAT_BY_C4 = {
    "决策错": "B",
    "超时": "E",
    "提取错": "F",
    "工具调用错": "C",
}


def subclassify(record: dict):
    """把一条记录归到 3.2 子类（A-F），非 LLM/工具类失败返回 None。

    仅对带 LLM/工具/提取类错误信号的失败记录分桶；早期断裂
    （step 1/2：task_id/question_type 空）与成功记录返回 None。
    """
    if record.get("flag") and record.get("validated"):
        return None  # 成功
    es = record.get("error_struct") or {}
    cat = es.get("category", "") if isinstance(es, dict) else ""
    c4 = es.get("class4", "") if isinstance(es, dict) else ""
    if cat in _SUBCAT_BY_CAT:
        return _SUBCAT_BY_CAT[cat]
    if c4 in _SUBCAT_BY_C4:
        return _SUBCAT_BY_C4[c4]
    return None


def analyze_subclass(log_path: str) -> dict:
    """按 3.2 子类统计 5_LLM主Agent 失败分布。"""
    if not os.path.isfile(log_path):
        raise FileNotFoundError(log_path)
    total = 0
    sub = Counter()
    unmapped = 0
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            sc = subclassify(rec)
            if sc is None:
                continue
            total += 1
            sub[sc] += 1
    dist = {}
    for code, name, feat in SUBCLASSES:
        dist[code] = {
            "name": name,
            "feature": feat,
            "count": sub.get(code, 0),
            "pct": round(100.0 * sub.get(code, 0) / total, 1) if total else 0.0,
        }
    biggest = max(SUBCLASSES, key=lambda x: sub.get(x[0], 0))[0] if total else ""
    return {
        "as_of": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "log": os.path.basename(log_path),
        "total_subclassed": total,
        "distribution": dist,
        "biggest_bucket": biggest,
        "recommendation": _recommend_subclass(biggest, dist),
        "note": "映射基于 error_struct.category/class4；A/C2/D 当前 goal_log 无直接"
                "信号(计0)，属数据局限非真零。哪个桶最大先打哪个。",
    }


def _recommend_subclass(biggest: str, dist: dict) -> str:
    if not biggest:
        return "无 LLM 类失败记录"
    d = dist[biggest]
    return (f"最大子类 = {biggest} {d['name']}（{d['count']} 次，{d['pct']}%）"
            f"→ 优先实验："
            f"{'E2步骤预算/E6 few-shot' if biggest=='B' else ''}"
            f"{'E2步骤预算' if biggest=='E' else ''}"
            f"{'E8多候选提交' if biggest=='F' else ''}"
            f"{'E3附件证据注入' if biggest=='C' else ''}"
            f"；其余桶按分布依次推进。")


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


def render_subclass_md(stats: dict) -> str:
    L = [f"# 失败子类分布（A-F，{stats['as_of']}）",
         f"\n数据源：`{stats['log']}` | 子类化 {stats['total_subclassed']} 条 "
         f"LLM/工具类失败\n",
         "## 子类直方图\n",
         "| 子类 | 名称 | 识别特征 | 次数 | 占比 | 条形 |",
         "|---|---|---|---|---|---|"]
    for code, name, feat in SUBCLASSES:
        d = stats["distribution"][code]
        bar = "#" * max(1, int(d["pct"] / 5))
        L.append(f"| {code} | {name} | {feat} | {d['count']} | {d['pct']}% | {bar} |")
    L.append(f"\n## 最大子类：{stats['biggest_bucket'] or '无'}\n")
    L.append(stats["recommendation"])
    L.append(f"\n> {stats['note']}")
    return "\n".join(L)


def _run_subclass(args) -> int:
    try:
        stats = analyze_subclass(args.log)
    except FileNotFoundError:
        print(f"❌ 未找到日志：{args.log}")
        return 1
    os.makedirs(args.out, exist_ok=True)
    ts = time.strftime("%Y%m%d", time.gmtime())
    jpath = os.path.join(args.out, f"chain_subclass_{ts}.json")
    mpath = os.path.join(args.out, f"chain_subclass_{ts}.md")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(stats, fh, ensure_ascii=False, indent=2)
    with open(mpath, "w", encoding="utf-8") as fh:
        fh.write(render_subclass_md(stats))
    print(f"✅ 子类分布完成：子类化 {stats['total_subclassed']} 条，"
          f"最大桶 = {stats['biggest_bucket'] or '无'}")
    for code, name, _ in SUBCLASSES:
        d = stats["distribution"][code]
        if d["count"]:
            print(f"   {code} {name}: {d['count']} 次（{d['pct']}%）")
    print(f"   JSON: {jpath}")
    print(f"   MD  : {mpath}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="7 步链路失败步统计（P1 Step 3）")
    ap.add_argument("--log", default=DEFAULT_LOG, help="goal_log 路径")
    ap.add_argument("--out", default=RESULTS_DIR, help="输出目录")
    ap.add_argument("--by-subclass", action="store_true",
                    help="3.2 模式：按 A-F 子类统计 5_LLM主Agent 失败分布")
    args = ap.parse_args()

    if args.by_subclass:
        return _run_subclass(args)

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
