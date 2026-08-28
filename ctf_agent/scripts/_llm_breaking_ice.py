"""LLM 破冰 harness（战役A）：强制走 LLM 主链路，验证 deepseek 付费链路可端到端解出真题。

背景：2026-08 长期"LLM 真推理贡献=0"是临时 outage + 死 baidu 默认 + 免费档熔断的假象，
并非能力缺口。本脚本在 deepseek 已充值前提下，对真题集跑 skip_presolve=True 的真实 Agent，
用 flag_sha256 做独立校验，证明 LLM 驱动链路可解出真题（KPI 锚点：LLM 贡献 0 → ≥1）。

用法：
    .venv/Scripts/python.exe scripts/_llm_breaking_ice.py \
        --qids real_crypto_ezrsa,real_misc_xuanhun_signin,real_crypto_dnui_keyboard \
        --provider deepseek --attempts 2 --timeout 180

输出：
    deliverables/llm_breaking_ice_<ts>.json  每题结果（flag/sha256 校验/机制/usage）
    （stdout 同时打印增量进度）
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import run as run_mod  # noqa: E402
from eval.cases import load_questions  # noqa: E402


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _validate(flag: str | None, q) -> tuple[bool, str | None]:
    if not flag:
        return False, None
    fs = getattr(q, "flag_sha256", None)
    if not fs:
        return False, None
    for cand in (flag, flag.strip(), flag.strip().strip("flag{}")):
        if _sha256_hex(cand) == fs:
            return True, cand
    return False, None


async def _solve_one(qid: str, provider: str, attempts: int, per_timeout: int, no_internal_presolve: bool):
    questions = load_questions("data/questions_real")
    q = next((x for x in questions if x.id == qid), None)
    if q is None:
        return {"qid": qid, "status": "NOT_FOUND"}

    # 强制 LLM 主链路：skip_presolve=True；validate_locally=False 避免误用训练集答案比对，
    # 正确性由本脚本 flag_sha256 独立校验。
    # --no-internal-presolve：运行时 monkeypatch 掉 main_agent 内部的静态预扫快捷通道，
    # 让 LLM 必须自己推理+调度工具层（crypto_auto/flag_scan 等适配器）求解——
    # 用于区分"presolve 直出"与"LLM 真推理贡献"，不改动项目源码。
    if no_internal_presolve:
        import core.presolve as _ps

        _ps.presolve = lambda *a, **k: None  # noqa: E731
        import core.main_agent as _ma

        if hasattr(_ma, "presolve"):
            _ma.presolve = lambda *a, **k: None  # noqa: E731

    solver = run_mod.build_solver(
        use_mock=False, provider=provider, validate_locally=False, skip_presolve=True
    )

    async def _run():
        out = await solver(q, 0, None)
        return out

    t0 = time.time()
    try:
        out = await asyncio.wait_for(_run(), timeout=per_timeout)
    except asyncio.TimeoutError:
        return {"qid": qid, "status": "TIMEOUT", "seconds": round(time.time() - t0, 1)}
    except Exception as e:  # noqa: BLE001
        return {"qid": qid, "status": "ERROR", "error": repr(e), "seconds": round(time.time() - t0, 1)}

    flag = out.get("flag")
    ok, canon = _validate(flag, q)
    rec = {
        "qid": qid,
        "category": getattr(q, "category", "?"),
        "difficulty": getattr(q, "difficulty", "?"),
        "status": "SOLVED" if ok else "UNSOLVED",
        "flag_found": flag,
        "sha256_ok": ok,
        "solved_by": out.get("solved_by"),
        "provider": out.get("provider"),
        "validated": out.get("validated"),
        "attempts_used": out.get("attempts"),
        "error": out.get("error"),
        "seconds": round(time.time() - t0, 1),
        "raw_keys": sorted(out.keys()),
    }
    return rec


async def _main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qids", required=True, help="逗号分隔的真题 id")
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--attempts", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=180, help="每题 asyncio 超时(秒)")
    ap.add_argument("--no-internal-presolve", action="store_true",
                    help="monkeypatch 掉 agent 内部静态预扫，强制 LLM 真推理（不改项目代码）")
    args = ap.parse_args()

    qids = [x.strip() for x in args.qids.split(",") if x.strip()]
    results = []
    for qid in qids:
        tag = "LLM-ONLY" if args.no_internal_presolve else "presolve-first"
        print(f"[*] solving {qid} via {args.provider} ({tag}) ...", flush=True)
        rec = await _solve_one(qid, args.provider, args.attempts, args.timeout, args.no_internal_presolve)
        results.append(rec)
        print(f"    -> {rec['status']:8s} sha256_ok={rec.get('sha256_ok')} "
              f"solved_by={rec.get('solved_by')} sec={rec.get('seconds')}", flush=True)

    ts = time.strftime("%Y%m%d-%H%M%S")
    out_path = os.path.join(_ROOT, "deliverables", f"llm_breaking_ice_{ts}.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    summary = {
        "provider": args.provider,
        "skip_presolve": True,
        "total": len(results),
        "solved": sum(1 for r in results if r.get("status") == "SOLVED"),
        "results": results,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n=== SUMMARY: {summary['solved']}/{summary['total']} solved ===")
    print(f"report -> {out_path}")


if __name__ == "__main__":
    asyncio.run(_main())
