#!/usr/bin/env python3
"""跑批结果有效性门禁（2026-10-10 · 防"把基础设施失败当能力"）。

事故背景
--------
2026-10-10 跑 69 题外部未见题盲测，provider=deepseek 中途掉线：
**39/69 题死于 `provider_circuit_open`**（熔断），只有 30 题获得有效测量。
若直接把"解出率"当能力数发布，基础设施失败就被算成了模型能力。
换 provider 重跑又出现另一类污染：xfyun 235 步 **0 次工具调用**，0 解出——
这属于"模型与 agent 循环不兼容"，同样不是"密码能力弱"。

因此本守卫做三件事（全部可在跑批前后自动执行）：
  1. **事前**：provider 是否活着（读探测快照，默认 fail-closed）。
  2. **事后**：基础设施类失败占比是否超阈值 → 判定"结果不可用作能力数"。
  3. **口径拆分**：引擎整体解出 vs LLM 独立解出（确定性兜底不得计入 LLM 能力）。

用法
----
  # 跑批后自检（退出码 2 = 结果被判定不可用，勿引用其解出率）
  python scripts/_run_validity_guard.py --results-dir data/results/xxx
  # 事前 provider 检查
  python scripts/_run_validity_guard.py --provider-check xfyun
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 判定为"基础设施/环境"类失败——这些不计入模型能力
INFRA_ERRORS = {
    "provider_circuit_open",   # provider 熔断（掉线/限流）
    "provider_unavailable",
    "budget_exceeded",         # 注意：预算耗尽往往是"没进展"的症状，单列不判 infra
}


def provider_live(provider: str, max_age_hours: int = 24) -> tuple[bool, str]:
    """读探测快照判断 provider 是否可用（fail-closed：快照缺失/过期=不可用）。"""
    snap_dir = ROOT / "logs" / "llm_probe"
    if not snap_dir.is_dir():
        return False, "无探测快照目录"
    snaps = sorted(snap_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if not snaps:
        return False, "无探测快照"
    newest = snaps[-1]
    age = datetime.now(timezone.utc) - datetime.fromtimestamp(
        newest.stat().st_mtime, tz=timezone.utc)
    if age > timedelta(hours=max_age_hours):
        return False, f"快照过旧（{age.total_seconds()/3600:.1f}h > {max_age_hours}h）"
    try:
        data = json.loads(newest.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return False, f"快照损坏: {exc}"
    # 快照 schema: llm_pool_probe/v1 → {"providers": {"<name>": {"ok": bool, "status": ...}}}
    # 初版错读 alive/available 顶层键 → 一律返回"不可用"的假红（假红比没门禁更糟）。
    provs = data.get("providers") or {}
    alive = {k for k, v in provs.items() if isinstance(v, dict) and v.get("ok")}
    detail_status = {k: (v.get("status") if isinstance(v, dict) else "?")
                     for k, v in provs.items() if k == provider}
    return (provider in alive,
            f"快照 {newest.name}（{data.get('ts')}）｜alive={sorted(alive) or '无'}"
            f"｜{provider} 状态={detail_status}")


def assess(results_dir: Path, infra_threshold: float = 0.2) -> dict:
    rep_path = results_dir / "benchmark_report.json"
    if not rep_path.is_file():
        return {"valid": False, "reasons": [f"找不到报告: {rep_path}"], "stats": {}}
    rep = json.loads(rep_path.read_text(encoding="utf-8"))
    res = rep.get("results", [])
    total = len(res)
    if total == 0:
        return {"valid": False, "reasons": ["报告里 0 题"], "stats": {}}
    errs = Counter(str(r.get("error")) for r in res if not r.get("solved"))
    infra = sum(v for k, v in errs.items() if k in INFRA_ERRORS)
    solved = [r for r in res if r.get("solved")]
    by = Counter(str(r.get("solved_by")) for r in solved)
    llm_solved = sum(v for k, v in by.items() if k == "main_agent_llm")
    det_solved = sum(v for k, v in by.items() if k == "presolve")

    reasons = []
    infra_ratio = infra / total
    if infra_ratio > infra_threshold:
        reasons.append(
            f"基础设施类失败占比 {infra_ratio:.1%} > 阈值 {infra_threshold:.0%}"
            f"（{dict((k, v) for k, v in errs.items() if k in INFRA_ERRORS)}）→ 解出率不可代表模型能力")
    if len(solved) and llm_solved == 0 and det_solved == len(solved):
        reasons.append("解出全部来自确定性兜底，LLM 独立贡献为 0——报引擎解出率会虚高 LLM 能力")
    stats = {
        "total": total, "solved": len(solved), "engine_solve_rate": round(len(solved) / total, 4),
        "llm_independent_solved": llm_solved, "deterministic_fallback_solved": det_solved,
        "infra_failed": infra, "infra_ratio": round(infra_ratio, 4),
        "errors": dict(errs), "solved_by": dict(by),
    }
    return {"valid": not reasons, "reasons": reasons, "stats": stats}


def main() -> int:
    ap = argparse.ArgumentParser(description="跑批结果有效性门禁")
    ap.add_argument("--results-dir", default="")
    ap.add_argument("--provider-check", default="", metavar="PROVIDER")
    ap.add_argument("--infra-threshold", type=float, default=0.2)
    args = ap.parse_args()

    if args.provider_check:
        ok, detail = provider_live(args.provider_check)
        print(f"[guard] provider={args.provider_check} 可用={ok}｜{detail}")
        return 0 if ok else 3

    if not args.results_dir:
        ap.error("需要 --results-dir 或 --provider-check")
    rep = assess(Path(args.results_dir), args.infra_threshold)
    print(json.dumps(rep, ensure_ascii=False, indent=1))
    print(f"[guard] 结论: {'可用于能力口径' if rep['valid'] else '**不可用于能力口径**'}")
    return 0 if rep["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
