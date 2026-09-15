#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KPI 合法晋升候选扫描（严格诚实）。

对 data/questions_real 全部真题：
  - 只保留 provenance=real_past_ctf（历年真实赛题，严格 KPI 唯一分母）
  - 排除 answer_disclosed=True（附件曾自带明文 flag，注水题，不计）
  - 要求有外部真值 flag_sha256（否则无法独立闭环，不进严格 KPI）
  - 用与真实链路一致的 presolve 确定性管线真跑（force=True）
  - 输出：确定性解出且 sha256 匹配、但不在 AUTHORIZED_KPI_SOLVES(当前13) 的候选
诚实约束：绝不把"读泄露附件"当解出——answer_disclosed 已排除；flag 仅 sha256 比对。
"""
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.presolve import presolve  # noqa: E402
from eval.cases import load_questions  # noqa: E402
from scripts._antifraud import AUTHORIZED_KPI_SOLVES  # noqa: E402

from sandbox.subprocess_executor import SubprocessExecutor  # noqa: E402
from tools.registry import ToolRegistry  # noqa: E402
from tools.adapters.file_analysis_adapter import FileAnalysisAdapter  # noqa: E402
from tools.adapters.stego_adapter import StegoAdapter  # noqa: E402
from tools.adapters.python_adapter import PythonAdapter  # noqa: E402
from tools.adapters.hash_crack_adapter import HashCrackAdapter  # noqa: E402
from tools.adapters.wordlist_crack_adapter import WordlistCrackAdapter  # noqa: E402
from tools.adapters.web_request_adapter import WebRequestAdapter  # noqa: E402
from tools.adapters.openssl_adapter import OpensslAdapter  # noqa: E402
from tools.adapters.bkcrack_adapter import BkcrackAdapter  # noqa: E402
from tools.adapters.xxe_adapter import XxeFileReadAdapter  # noqa: E402
from tools.adapters.zip_chain_adapter import ZipChainDecodeAdapter  # noqa: E402
from tools.adapters.deterministic_decode_adapter import DeterministicDecodeAdapter  # noqa: E402
from tools.adapters.crypto_auto_adapter import CryptoAutoAdapter  # noqa: E402
from tools.adapters.flag_scan_adapter import FlagScanAdapter  # noqa: E402


def build_registry():
    sandbox = SubprocessExecutor()
    registry = ToolRegistry()
    for a in (
        FileAnalysisAdapter(), StegoAdapter(), PythonAdapter(sandbox=sandbox),
        HashCrackAdapter(), WordlistCrackAdapter(), WebRequestAdapter(),
        OpensslAdapter(sandbox=sandbox), BkcrackAdapter(sandbox=sandbox),
        XxeFileReadAdapter(), ZipChainDecodeAdapter(), DeterministicDecodeAdapter(),
        CryptoAutoAdapter(sandbox=sandbox), FlagScanAdapter(),
    ):
        registry.register(a)
    return registry


async def main():
    qs = load_questions("data/questions_real")
    registry = build_registry()
    rows = []
    for q in qs:
        if q.provenance != "real_past_ctf":
            continue
        if q.answer_disclosed:
            continue
        if not q.flag_sha256:
            rows.append((q.id, q.category, "NO_EXT_TRUTH", None, None, None))
            continue
        in_auth = q.id in AUTHORIZED_KPI_SOLVES
        t0 = time.time()
        try:
            flag = await presolve(q, registry=registry, force=True)
        except Exception as exc:  # noqa: BLE001
            flag = f"<err:{exc}>"
        dt = (time.time() - t0) * 1000
        extracted = bool(flag) and not str(flag).startswith("<")
        match = bool(extracted and q.flag_matches(str(flag)))
        verdict = ("MATCH" if match else ("EXTRACTED_NO_TRUTH" if extracted else "FAIL"))
        rows.append((q.id, q.category, verdict, in_auth, round(dt),
                     str(flag)[:40] if extracted else None))

    # 分类输出
    candidates = [r for r in rows if r[2] == "MATCH" and r[3] is False]
    already = [r for r in rows if r[2] == "MATCH" and r[3] is True]
    no_truth = [r for r in rows if r[2] == "NO_EXT_TRUTH"]
    failed = [r for r in rows if r[2] in ("FAIL", "EXTRACTED_NO_TRUTH")]

    print(f"=== 扫描 data/questions_real（real_past_ctf + 非注水 + 有外部真值）===")
    print(f"  候选（确定性解出+真值匹配+未入白名单）: {len(candidates)}")
    for r in candidates:
        print(f"    ★ {r[0]:38s} {r[1]:7s} {r[4]}ms")
    print(f"  已授权(13内，对照): {len(already)}")
    for r in already:
        print(f"      {r[0]:38s} {r[1]:7s}")
    print(f"  无外部真值(不进严格KPI): {len(no_truth)}")
    print(f"  确定性未解出(需攻击链/LLM): {len(failed)}")
    for r in failed:
        print(f"      - {r[0]:38s} {r[1]:7s} {r[2]} {r[5]}")

    # 落盘 JSON 供后续晋升流程读取
    out = {
        "candidates": [
            {"id": r[0], "category": r[1], "ms": r[4]} for r in candidates
        ],
        "already_authorized": [r[0] for r in already],
        "no_external_truth": [r[0] for r in no_truth],
        "failed": [{"id": r[0], "category": r[1], "verdict": r[2]} for r in failed],
    }
    Path("deliverables/kpi_candidates_scan.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n落盘: deliverables/kpi_candidates_scan.json")


if __name__ == "__main__":
    asyncio.run(main())
