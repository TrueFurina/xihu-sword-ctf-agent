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
import sys
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


def detect_corpus_loss(cur: dict, base: dict) -> tuple[list[str], set[str]]:
    """检测**题目池缩水**（真数据丢失）——返回 (回归消息, 涉及的池集合)。

    背景（2026-10-12 实测）：原门禁只比对 `broken` 计数，而题目定义 JSON 被整体删除时，
    该题不再进入 `_audit_corpus_integrity.audit()`（只 `rglob("*.json")`）⇒ `total` 下降、
    `broken` 不升反降 ⇒ 门禁把**数据丢失误读为「改善」**。实测：
      - `questions_ext`   37 → 17 题（剩 17 全是好题）⇒ 被报「改善 -3，建议 --update」；
      - `questions_ext_cybench` 13 → 0、`questions_ext_trial5` 5 → 0、
        `questions_real_kpi9` 8 → 0 ⇒ broken 恒 0 ⇒ 门禁**完全无感**。
    与基线 `incident_notes` 记录的 02-25 删除事件吻合（≈93 题仅剩 `_attachments/`）。

    判据：某池 `total` 或 `ok` 低于基线 ⇒ 数据丢失。**独立于 `compare()`、不改其契约**
    ——`compare()` 的 `broken` 语义与既有测试保持不变。本函数结果由 `main()` 默认以
    「⚠️ 警告」呈现（**不改变既有阻断语义**，避免引入新的红而自锁提交）；加 `--strict-loss`
    才计入阻塞回归。
    """
    msgs: list[str] = []
    pools: set[str] = set()
    for pool, b in base.items():
        c = cur.get(pool)
        if c is None:
            continue  # 整池消失由 compare() 既有判据覆盖，此处不重复
        b_total, c_total = b.get("total", 0), c.get("total", 0)
        b_ok, c_ok = b.get("ok", 0), c.get("ok", 0)
        if c_total < b_total:
            msgs.append(f"{pool}: 题目池缩水 {b_total} → {c_total} 题"
                        f"（丢失 {b_total - c_total}；可用 {b_ok} → {c_ok}）")
            pools.add(pool)
        elif c_ok < b_ok:
            msgs.append(f"{pool}: 可用题减少 {b_ok} → {c_ok}（-{b_ok - c_ok}）")
            pools.add(pool)
    return msgs, pools


def main() -> int:
    ap = argparse.ArgumentParser(description="题库健康度基线门禁")
    ap.add_argument("--update", action="store_true", help="刷新基线")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict-loss", action="store_true",
                    help="把「题目池缩水」判为回归（默认仅警告，不阻断）")
    args = ap.parse_args()
    cur = snapshot()
    bench_ok, bench_msg = benchmark_ok()

    if args.update:
        # 统一机器真值写入口（2026-10-10）：此前本文件是 benchmarks/ 下**唯一没有
        # schema 字段**的真值文件——任何脚本都能覆盖它，且事后无法判断这份基线
        # 是哪一版统计规则产生的。现与其它真值统一受守卫保护。
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from _truth_guard import write_truth, TruthWriteRefused, RC_REFUSED
        try:
            write_truth(BASELINE, {"pools": cur, "tracked_pools": list(TRACKED_POOLS)},
                        schema="corpus_health_baseline/v1",
                        by="scripts/check_corpus_health.py")
        except TruthWriteRefused as exc:
            # 友好报错 + 专属退出码；不要裸抛堆栈（调用方多为脚本/CI）
            print(f"[health] ❌ 拒绝写基线: {exc}")
            print("[health] 若确认该文件来源无误，一次性迁移："
                  "python scripts/_truth_guard.py --migrate-legacy")
            return RC_REFUSED
        print(f"[health] 基线已刷新：{BASELINE}")
        for p, v in cur.items():
            print(f"  {p:32s} 总 {v['total']:>3} 可用 {v['ok']:>3} 坏题 {v['broken']:>3}")
        return 0

    base = json.loads(BASELINE.read_text(encoding="utf-8"))["pools"] if BASELINE.is_file() else {}
    diff = compare(cur, base)
    loss_msgs, loss_pools = detect_corpus_loss(cur, base)
    if loss_pools:
        # 池缩水时的「坏题下降」不是改善，而是被丢失掩盖 ⇒ 抑制误报的 improvement 提示
        diff["improvements"] = [
            i for i in diff["improvements"]
            if not any(i.startswith(p + ":") for p in loss_pools)
        ]
    # 默认只警告、不阻断（保持既有阻断语义不变，避免引入新的红而自锁提交）；
    # 需要把「数据丢失」作为阻断项时显式加 --strict-loss。
    if args.strict_loss:
        diff["regressions"] = diff["regressions"] + loss_msgs
    ok = not diff["regressions"] and bench_ok
    rep = {"ok": ok, "current": cur, "baseline": base, **diff,
           "corpus_loss": loss_msgs, "strict_loss": args.strict_loss,
           "benchmark_check": {"ok": bench_ok, "detail": bench_msg}}
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        print(f"[health] 正式基准校验: {'通过' if bench_ok else '失败'}（{bench_msg}）")
        for r in diff["regressions"]:
            print("  ❌ 回归:", r)
        if loss_msgs and not args.strict_loss:
            for w in loss_msgs:
                print("  ⚠️  数据丢失（默认不阻断；--strict-loss 可阻断）:", w)
        for i in diff["improvements"]:
            print("  ⬆️  改善:", i)
        print(f"[health] 结论: {'无回归' if ok else '**存在回归，需处理**'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
