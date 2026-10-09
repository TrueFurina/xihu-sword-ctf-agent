#!/usr/bin/env python3
"""题库健康度基线门禁（2026-10-10）。

设计原则：**只在变坏时报警**。
`questions_real` 现存 77 道坏题是**已知历史问题**（64 道附件就是答案键、8 道载荷随归档
删除、5 道无真值），若门禁按"坏题>0 即红"，它会天天红——而**天天假红的护栏最终会被
整段注释掉**（本项目历史教训）。故本门禁比对基线：

  - 某池坏题数 **比基线多** → 红（回归）
  - 某池坏题数 **比基线少** → 绿，并提示可刷新基线
  - 正式基准 `benchmarks/external_unseen` 校验失败 → 红（独立于基线）

用法
----
  python scripts/check_corpus_health.py            # 比对基线
  python scripts/check_corpus_health.py --update   # 有意修复后刷新基线
  python scripts/check_corpus_health.py --json
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "benchmarks" / "corpus_health_baseline.json"
# 只对这些池做基线比对（临时/派生目录不进基线）
TRACKED_POOLS = ("questions_real", "questions_external", "questions_ext",
                 "questions_ext_cybench", "questions_ext_A_20261001",
                 "questions_ext_A_20261001", "questions_ext_trial5_20261001",
                 "questions_real_kpi9")


def _auditor():
    spec = importlib.util.spec_from_file_location(
        "_audit_corpus_integrity", ROOT / "scripts" / "_audit_corpus_integrity.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def snapshot() -> dict:
    aci = _auditor()
    out = {}
    for pool in TRACKED_POOLS:
        d = ROOT / "data" / pool
        if not d.is_dir():
            continue
        try:
            rep = aci.audit(d, ROOT)
        except Exception:  # noqa: BLE001
            continue
        lv = rep["by_level"]
        out[pool] = {"total": rep["total"], "ok": lv.get("ok", 0),
                     "leaky": lv.get("leaky", 0), "broken": lv.get("broken", 0)}
    return out


def benchmark_ok() -> tuple[bool, str]:
    script = ROOT / "scripts" / "_build_external_benchmark.py"
    spec = importlib.util.spec_from_file_location("_bench", script)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    ok, problems = m.check()
    return ok, ("；".join(problems[:3]) if problems else "OK")


def compare(cur: dict, base: dict) -> dict:
    regressions, improvements = [], []
    for pool, c in cur.items():
        b = base.get(pool)
        if b is None:
            regressions.append(f"{pool}: 基线缺失（新增池，需 --update 纳入）")
            continue
        if c["broken"] > b.get("broken", 0):
            regressions.append(f"{pool}: 坏题 {b.get('broken')} → {c['broken']}（+{c['broken']-b.get('broken')}）")
        elif c["broken"] < b.get("broken", 0):
            improvements.append(f"{pool}: 坏题 {b.get('broken')} → {c['broken']}（-{b.get('broken')-c['broken']}，建议 --update）")
    for pool in base:
        if pool not in cur:
            regressions.append(f"{pool}: 池消失（曾有 {base[pool]['total']} 题）")
    return {"regressions": regressions, "improvements": improvements}


def main() -> int:
    ap = argparse.ArgumentParser(description="题库健康度基线门禁")
    ap.add_argument("--update", action="store_true", help="刷新基线")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    cur = snapshot()
    bench_ok, bench_msg = benchmark_ok()

    if args.update:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(
            {"updated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"), "pools": cur},
            ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"[health] 基线已刷新：{BASELINE}")
        for p, v in cur.items():
            print(f"  {p:32s} 总 {v['total']:>3} 可用 {v['ok']:>3} 坏题 {v['broken']:>3}")
        return 0

    base = json.loads(BASELINE.read_text(encoding="utf-8"))["pools"] if BASELINE.is_file() else {}
    diff = compare(cur, base)
    ok = not diff["regressions"] and bench_ok
    rep = {"ok": ok, "current": cur, "baseline": base, **diff,
           "benchmark_check": {"ok": bench_ok, "detail": bench_msg}}
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        print(f"[health] 正式基准校验: {'通过' if bench_ok else '失败'}（{bench_msg}）")
        for r in diff["regressions"]:
            print("  ❌ 回归:", r)
        for i in diff["improvements"]:
            print("  ⬆️  改善:", i)
        print(f"[health] 结论: {'无回归' if ok else '**存在回归，需处理**'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
