#!/usr/bin/env python
"""provider 能力档案 · 归档聚合器（v2：用已付费的历史跑批做多样本证据）。

**为什么要有 v2**（2026-10-10）：
`_provider_toolcap_probe.py` 是"同一道题现跑一遍"的单样本探针，首测结论强度不足——
同一道题上 glm 与 xfyun 都是 0 解析失败，说明"解析失败率"更像**题目相关**而非 provider
绝对属性。单样本选型等于凭感觉。

本脚本改为**聚合历史跑批产物**（`data/results/*/benchmark_report.json`），用已经付过费的
数据算出多样本指标，零新增 token 成本：

1. **有效测量率**   = 非 provider/环境类失败的题数 / 总题数（识别"基础设施失败伪装成能力"）
2. **LLM 独立解出率** = 只算 solved_by==main_agent_llm（排除确定性兜底虚高）
3. **token 效率**   = 解出题平均 token（越低越好；高=烧钱不产出）
4. **动作产生率**   = 可选：日志里"代码动作兜底/沙盒"痕迹 ÷ 步数（是否能驱动工具循环）

🔴 **口径纪律**：
- 每个指标都带样本数 n；n 过小（<3）时结论标 `low_confidence`，不参与推荐排序。
- 只读历史产物，不发起任何 LLM 调用；不修改任何 run 目录。
- 「引擎整体解出率」与「LLM 独立解出率」必须分开——引擎有放弃前确定性兜底，
  混报会把 LLM 能力虚高数倍（10-10 实测：53.3% vs 2/30）。
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# provider 失败（基础设施类）——不计入"能力"分母
INFRA_ERRORS = {
    "provider_circuit_open",
    "provider_unavailable",
    "wallclock_timeout_all",
    "no_provider",
    "llm_unavailable",
}

# run 目录名 → provider 名（历史跑批命名的约定）
RUN_NAME_HINTS = {
    "deepseek": "deepseek",
    "ds_": "deepseek",
    "xfyun": "xfyun",
    "spark": "xfyun",
    "glm": "glm",
    "ark": "ark",
    "doubao": "ark",
    "kimi": "kimi",
    "moonshot": "moonshot",
    "qwen": "qwen",
    "tokenhub": "tokenhub",
    "siliconflow": "siliconflow",
    "baidu": "baidu",
    "tencent": "tencent",
    "minimax": "minimax",
    "stepfun": "stepfun",
    "baichuan": "baichuan",
}

MIN_SAMPLE_FOR_CONFIDENCE = 3


# 🔴 显式 run→provider 映射（2026-10-10 实测补齐）。
# 为什么不能只靠目录名猜：实测最大的两个 run（unseen86_pure_llm 69 题 / heldout_exp 78 题）
# 目录名里**没有 provider 字样**，靠 HINTS 猜全部落进 unknown 桶（253 题=最大桶），
# 于是聚合器把"provider 未知"的最大桶当成推荐对象——这是最坏的一种错：
# 数字看着最漂亮（LLM 独立率 0.107 全场最高），实际是无归属数据。
# 映射来源：各 run 的实际启动命令（--provider deepseek / xfyun / glm）与日志内标记，
# 无法从产物反推的一律留在 unknown，不猜。
RUN_PROVIDER_OVERRIDE = {
    "unseen86_pure_llm_20261010": "deepseek",   # --provider deepseek（会话内实跑）
    "unseen69_xfyun_20261010": "xfyun",         # --provider xfyun
    "glm_probe3_20261010": "glm",               # --provider glm
    "L2_pure_llm_20261006": "deepseek",         # 10-06 L2 纯 LLM 轮，provider=deepseek-chat
    "L2_withpresolve_20261006": "deepseek",     # 同上（含确定性层）
    "heldout_rerun20260919_selftruth_full": "deepseek",
    "heldout_rerun20260919_selftruth_val": "deepseek",
    "heldout_rerun20260919_stepfault_full": "deepseek",
    "heldout_rerun20260919_sha256fix_val": "deepseek",
    "heldout_rerun20260919_budget2x": "deepseek",
    "heldout_exp": "deepseek",                  # 09-23 heldout 主线，provider=deepseek
    "heldout_v3_20260923": "deepseek",
    "heldout_p0verify_20260923": "deepseek",
    "heldout_p0verify2_20260923": "deepseek",
}

# 🔴 口径不可比的 run（引擎版本不同 / 协议不同），聚合时单列不进 provider 汇总。
# 实测依据：heldout_rerun20260919_deepseek_full 跑在 P0 验证器 bug 修复**之前**
# （当日口径 1/10 实为冤案，修复后同协议 4/10）——把它与修复后的轮次混算会
# 把一个已知失效的引擎版本的能力算进 provider 表现里。
LEGACY_ENGINE_RUNS = {
    "heldout_rerun20260919_deepseek_full",
    "heldout_rerun20260919_deepseek_val",
    "heldout_rerun20260919_ds_budget2x",
    "heldout_rerun20260919_sha256fix_val",
    "heldout.BAK_20261001_023838",
}


def infer_provider(run_name: str) -> str:
    """从 run 目录名推断 provider；推断不出返回 'unknown'（不猜）。"""
    if run_name in RUN_PROVIDER_OVERRIDE:
        return RUN_PROVIDER_OVERRIDE[run_name]
    low = run_name.lower()
    hits = [prov for hint, prov in RUN_NAME_HINTS.items() if hint in low]
    if not hits:
        return "unknown"
    # 取最长匹配（避免 glm45 之类被 glm 抢先，同时避免 ark 命中 "spark" 之类）
    return max(hits, key=len)


def load_run(run_dir: Path) -> dict | None:
    rep = run_dir / "benchmark_report.json"
    if not rep.is_file():
        return None
    try:
        d = json.loads(rep.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    results = d.get("results") or []
    if not results:
        return None
    return d


def collect(results_dir: Path) -> list[dict]:
    """扫描所有 run 目录，逐个算指标。"""
    out = []
    for run_dir in sorted(p for p in results_dir.iterdir() if p.is_dir()):
        d = load_run(run_dir)
        if d is None:
            continue
        res = d["results"]
        summary = d.get("summary", {})
        pq = (summary.get("tokens") or {}).get("per_question") or {}

        infra = [r for r in res if r.get("error") in INFRA_ERRORS]
        valid = [r for r in res if r.get("error") not in INFRA_ERRORS]
        solved = [r for r in res if r.get("solved")]
        llm_solved = [r for r in res
                      if r.get("solved") and r.get("solved_by") == "main_agent_llm"]
        det_solved = [r for r in res
                      if r.get("solved") and r.get("solved_by") == "presolve"]

        solved_tokens = [pq.get(r["question_id"], 0) for r in solved
                         if pq.get(r["question_id"])]
        valid_tokens = [pq.get(r["question_id"], 0) for r in valid
                        if pq.get(r["question_id"])]

        out.append({
            "run": run_dir.name,
            "provider": infer_provider(run_dir.name),
            "total": len(res),
            "valid_measured": len(valid),
            "infra_failed": len(infra),
            "solved": len(solved),
            "llm_independent_solved": len(llm_solved),
            "deterministic_fallback_solved": len(det_solved),
            "tokens_total": (summary.get("tokens") or {}).get("global_total"),
            "tokens_per_solved_mean": round(statistics.mean(solved_tokens), 1)
            if solved_tokens else None,
            "tokens_per_valid_mean": round(statistics.mean(valid_tokens), 1)
            if valid_tokens else None,
        })
    return out


def aggregate(runs: list[dict]) -> list[dict]:
    """按 provider 聚合多样本指标。

    🔴 `unknown` 桶**单列但不参与推荐**：provider 归属不明的数字不能用来选模型
    （2026-10-10 实测踩坑：最大桶 253 题全是 unknown，聚合器一度把它当推荐对象）。
    🔴 legacy 轮（引擎有已知 bug 的历史版本）单列，不进 provider 汇总。
    """
    by_prov: dict[str, list[dict]] = defaultdict(list)
    legacy: list[dict] = []
    for r in runs:
        if r["run"] in LEGACY_ENGINE_RUNS:
            legacy.append(r)
            continue
        by_prov[r["provider"]].append(r)

    out = []
    for prov, rs in by_prov.items():
        # 题目总数（跨 run 累加；同题多跑会重复计入，故另给 run 数与去重提示）
        total = sum(r["total"] for r in rs)
        valid = sum(r["valid_measured"] for r in rs)
        infra = sum(r["infra_failed"] for r in rs)
        solved = sum(r["solved"] for r in rs)
        llm = sum(r["llm_independent_solved"] for r in rs)
        det = sum(r["deterministic_fallback_solved"] for r in rs)
        # 有效测量的 token 效率：解出题 token 更能说明"是否烧钱无产出"
        eff = [r["tokens_per_solved_mean"] for r in rs
               if r["tokens_per_solved_mean"] is not None]
        all_eff = [r["tokens_per_valid_mean"] for r in rs
                   if r["tokens_per_valid_mean"] is not None]

        entry = {
            "provider": prov,
            "runs": len(rs),
            "questions_measured": total,
            "valid_measured": valid,
            "infra_failed": infra,
            "infra_failure_rate": round(infra / total, 3) if total else None,
            "solved": solved,
            "engine_solve_rate": round(solved / valid, 3) if valid else None,
            "llm_independent_solved": llm,
            "llm_independent_rate": round(llm / valid, 3) if valid else None,
            "deterministic_fallback_solved": det,
            "tokens_per_solved_mean": round(statistics.mean(eff), 1) if eff else None,
            "tokens_per_valid_mean": round(statistics.mean(all_eff), 1) if all_eff else None,
        }
        # 置信度：题目数与 run 数都够才给 high
        entry["excluded_from_recommendation"] = prov == "unknown"
        if prov == "unknown":
            entry["confidence"] = "unattributed"
        else:
            entry["confidence"] = (
                "high" if len(rs) >= 2 and valid >= MIN_SAMPLE_FOR_CONFIDENCE
                else "low" if valid else "insufficient"
            )
        entry["caveat"] = (
            "题目跨 run 可能重复计入（同题多跑）；此处统计的是'该 provider 在历史跑批中的"
            "总体表现'，不是严格去重的独立样本。"
        )
        out.append(entry)
    agg = sorted(out, key=lambda e: (e["confidence"] != "high",
                                     -(e["llm_independent_rate"] or 0)))
    return agg, legacy


def recommend(agg: list[dict]) -> dict:
    """基于多样本聚合的推荐：只看 high confidence 且基础设施失败率低的 provider。"""
    # 🔴 `(x or 1)` 的 falsy 陷阱：infra_failure_rate == 0.0 时 `0.0 or 1` → 1，
    # 于是"零基础设施失败"被当成 100% 失败，全场被拒 → 推荐恒为 None（假保守）。
    # 正确写法：None 才当未知，其它值按原值比较。
    ok = [e for e in agg if e["confidence"] == "high"
          and not e.get("excluded_from_recommendation")
          and (1.0 if e["infra_failure_rate"] is None
               else e["infra_failure_rate"]) <= 0.2]
    if not ok:
        return {"recommended": None,
                "why": "无任何 provider 达到「多样本 + 基础设施失败率≤20%」门槛。"
                       "建议充值 deepseek（唯一被证明能驱动本 agent 循环的模型）"
                       "或换用其他 provider 后重跑。"}
    ok.sort(key=lambda e: (-(e["llm_independent_rate"] or 0),
                           e["tokens_per_valid_mean"] or 0))
    best = ok[0]
    return {"recommended": best["provider"],
            "why": f"多样本(n={best['questions_measured']}题/{best['runs']}跑批) "
                   f"LLM独立解出率 {best['llm_independent_rate']}, "
                   f"基础设施失败率 {best['infra_failure_rate']}, "
                   f"有效题均 token {best['tokens_per_valid_mean']}。"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", default=str(ROOT / "data" / "results"))
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "provider_capability.json"))
    args = ap.parse_args()

    runs = collect(Path(args.results_dir))
    if not runs:
        print("[toolcap-agg] 无可聚合的历史跑批产物")
        return 1
    agg, legacy = aggregate(runs)
    rec = recommend(agg)
    doc = {
        "schema": "provider_capability_archive/v2",
        "note": "由历史跑批产物离线聚合，零 LLM 调用。置信度按样本量分级；"
                "low/insufficient 不参与推荐排序。",
        "infra_error_classes": sorted(INFRA_ERRORS),
        "runs_scanned": len(runs),
        "legacy_runs_excluded": sorted(LEGACY_ENGINE_RUNS),
        "legacy_runs": legacy,
        "per_run": runs,
        "per_provider": agg,
        "recommendation": rec,
    }
    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"[toolcap-agg] 扫描 {len(runs)} 个 run，聚合 {len(agg)} 个 provider")
    for e in agg:
        mark = "（不参与推荐）" if e.get("excluded_from_recommendation") else ""
        print(f"  {e['provider']:10s} conf={e['confidence']:12s}{mark} "
              f"题={e['questions_measured']:>4} 有效={e['valid_measured']:>4} "
              f"基础设施失败率={e['infra_failure_rate']} "
              f"LLM独立={e['llm_independent_rate']} "
              f"题均token={e['tokens_per_valid_mean']}")
    print(f"[toolcap-agg] 推荐: {rec['recommended']} — {rec['why']}")
    print(f"[toolcap-agg] 已写出 {outp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())