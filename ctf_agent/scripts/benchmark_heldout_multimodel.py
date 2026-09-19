#!/usr/bin/env python3
"""多模型分摊版 held-out 基准（2026-09-17）。

为什么存在
----------
千问AI平台（dashscope）每个模型仅 **1M tokens 免费额度、用尽即停**，而 full-78 实测约 4.8M。
故把题池按模型额度切成 N 批，**每批换一个免费模型**跑，最后合并报告——在零超额成本下拿到全量样本。

配套：
  scripts/benchmark_heldout.py        （选题/脱敏/冷黑板）
  config.DASHSCOPE_FREE_MODELS        （免费模型登记表）
关键：config 的 `_PROVIDER_MODEL_ALLOWLIST['qwen']` 允许 CTF_AGENT_LIGHT/HEAVY_MODEL 覆盖为
     登记在册的 dashscope 模型（否则被端点-模型一致性净化回退默认）。

运行：
  python scripts/benchmark_heldout_multimodel.py                # 默认 10 模型 × 8 题/批
  python scripts/benchmark_heldout_multimodel.py --dry-run      # 只打印分批与 token 估算
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import scripts.benchmark_heldout as bh  # noqa: E402

RESULTS = bh.RESULTS

# 首选强推理/通用免费模型（均 0 消耗档）
DEFAULT_MODELS = [
    "deepseek-v3.1", "deepseek-v3.2-exp", "kimi-k2.6", "kimi-k2-thinking", "kimi-k2.5",
    "qwen3.7-max-preview", "qwen3.7-plus", "glm-5.2", "glm-5.1", "qwen3.6-plus",
    "qwen3.7-max-2026-06-08", "deepseek-r1", "qwen3.6-max-preview", "glm-5",
]


def _chunks(seq, n):
    return [seq[i:i + n] for i in range(0, len(seq), n)]


def main() -> int:
    ap = argparse.ArgumentParser(description="多模型分摊 held-out 基准")
    ap.add_argument("--models", default=",".join(DEFAULT_MODELS))
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--wallclock", type=float, default=300.0)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--per-batch-budget", type=int, default=900000,
                    help="每批全局 token 上限（须 < 单模型 1M 免费额度）")
    ap.add_argument("--provider", default="qwen")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    cands, _ = bh.select_candidates(require_sha256=True, include_neutralized=True)
    batches = _chunks(cands, args.batch_size)
    est_tokens = len(cands) * 62000  # 实测 ~62K/题（400s 档）
    print(f"[mm] 题池 {len(cands)} 道 -> {len(batches)} 批（批大小 {args.batch_size}）")
    print(f"[mm] 模型池 {len(models)} 个：{models[:len(batches)]}")
    print(f"[mm] 预估 token ≈ {est_tokens:,}（{est_tokens/1e6:.1f}M）；"
          f"免费额度 {len(models)}M（{len(models)} 模型 × 1M）-> 足够")
    for i, b in enumerate(batches):
        print(f"    batch {i+1:2d}: model={models[i % len(models)]:32s} n={len(b)}")
    if args.dry_run:
        return 0

    mm_dir = RESULTS / f"mm_{datetime.now():%Y%m%d_%H%M%S}"
    mm_dir.mkdir(parents=True, exist_ok=True)
    print(f"[mm] 输出目录 {mm_dir}")

    backup = bh._backup_and_clear_blackboard()
    merged: list[dict] = []
    try:
        for i, batch in enumerate(batches):
            model = models[i % len(models)]
            run_dir = mm_dir / f"run_{i:02d}"
            out_dir = mm_dir / f"out_{i:02d}"
            run_dir.mkdir(parents=True, exist_ok=True)
            out_dir.mkdir(parents=True, exist_ok=True)
            for c in batch:
                try:
                    q = json.loads((ROOT / c["path"]).read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                q = bh._neutralize(q)
                (run_dir / f"{c['id']}.json").write_text(
                    json.dumps(q, ensure_ascii=False, indent=1), encoding="utf-8")

            env = dict(os.environ)
            env.update({
                "CTF_AGENT_USE_REAL_LLM": "1",
                "CTF_AGENT_LIGHT_MODEL": model,
                "CTF_AGENT_MID_MODEL": model,
                "CTF_AGENT_HEAVY_MODEL": model,
                "CTF_AGENT_GLOBAL_BUDGET": str(args.per_batch_budget),
            })
            cmd = [sys.executable, "-m", "eval.benchmark",
                   "--questions-dir", str(run_dir),
                   "--presolve-skip",
                   "--provider", args.provider,
                   "--wallclock", str(args.wallclock),
                   "--results-dir", str(out_dir),
                   "--concurrency", str(args.concurrency)]
            print(f"[mm] === batch {i+1}/{len(batches)} model={model} n={len(batch)} ===", flush=True)
            subprocess.call(cmd, cwd=str(ROOT), env=env)
            rep = out_dir / "benchmark_report.json"
            if rep.exists():
                d = json.loads(rep.read_text(encoding="utf-8"))
                for r in d.get("results", []):
                    r["_model"] = model
                    r["_batch"] = i
                    merged.append(r)
                tk = (d.get("summary", {}).get("tokens", {}) or {}).get("global_total")
                print(f"[mm] batch {i+1} done tokens={tk}", flush=True)
    finally:
        bh._restore_blackboard(backup)

    total = len(merged)
    solved = sum(1 for r in merged if r.get("solved"))
    by_cat: dict = {}
    by_src: dict = {}
    for r in merged:
        c = r.get("category") or "?"
        cs = by_cat.setdefault(c, {"total": 0, "solved": 0})
        cs["total"] += 1; cs["solved"] += 1 if r.get("solved") else 0
        s = r.get("solved_by") or "unknown"
        ss = by_src.setdefault(s, {"total": 0, "solved": 0})
        ss["total"] += 1; ss["solved"] += 1 if r.get("solved") else 0

    combined = {
        "mode": "real_main_agent_multimodel",
        "generated_by": "scripts/benchmark_heldout_multimodel.py",
        "models": models[:len(batches)],
        "total": total, "solved": solved,
        "solve_rate": (solved / total if total else 0.0),
        "by_category": by_cat, "by_solved_by": by_src,
        "results": merged,
    }
    out = mm_dir / "combined_report.json"
    out.write_text(json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[mm] DONE total={total} solved={solved} rate={combined['solve_rate']:.1%} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
