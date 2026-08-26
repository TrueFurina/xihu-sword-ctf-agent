"""纯静态 presolve 真值比对（零 LLM 调用，离线）。

目的：对 data/questions_real/ 15 道真题，用与真实模式一致的完整工具层跑
core.presolve.presolve，把提取到的 flag 与题库自带 ground-truth（question.flag）
逐题比对，得到「确定性管线真实解出数」——可验证、可复现，不含任何 LLM 幻觉。

用法：.venv/Scripts/python.exe scripts/_verify_presolve_truth.py
"""
import asyncio
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.presolve import presolve  # noqa: E402
from eval.cases import load_questions  # noqa: E402

# ── 复刻 build_solver 的工具层（保证与真实链路一致）──
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
    registry.register(FileAnalysisAdapter())
    registry.register(StegoAdapter())
    registry.register(PythonAdapter(sandbox=sandbox))
    registry.register(HashCrackAdapter())
    registry.register(WordlistCrackAdapter())
    registry.register(WebRequestAdapter())
    registry.register(OpensslAdapter(sandbox=sandbox))
    registry.register(BkcrackAdapter(sandbox=sandbox))
    registry.register(XxeFileReadAdapter())
    registry.register(ZipChainDecodeAdapter())
    registry.register(DeterministicDecodeAdapter())
    registry.register(CryptoAutoAdapter(sandbox=sandbox))
    registry.register(FlagScanAdapter())
    return registry


async def main():
    qs = load_questions("data/questions_real")
    print(f"加载真题 {len(qs)} 道\n")
    registry = build_registry()

    rows = []
    for q in qs:
        gt = q.flag_sha256 or q.flag or "(题库无真值字段)"
        t0 = time.time()
        try:
            flag = await presolve(q, registry=registry, force=True)
        except Exception as exc:  # noqa: BLE001
            flag = f"<presolve异常:{exc}>"
        dt = (time.time() - t0) * 1000
        extracted = bool(flag) and not str(flag).startswith("<")
        # 真值比对：明文比对或 sha256 占位比对（2026-08-24 红线整改）
        match = bool(extracted and q.flag_matches(str(flag)))
        no_ground = (extracted and not q.flag)
        rows.append((q.id, q.category, q.provenance, extracted, match, no_ground, flag, gt, dt))
        shown = (str(flag)[:46] + "...") if flag and len(str(flag)) > 46 else flag
        verdict = "✅真值匹配" if match else ("⚠️无真值(已提取)" if no_ground else ("❌未命中" if not extracted else "⛔提取≠真值"))
        print(f"  [{verdict}] {q.id:34s} {q.category:7s} prov={q.provenance:18s} {dt:7.0f}ms -> {shown}")

    total = len(rows)
    matched = sum(1 for r in rows if r[4])
    extracted_n = sum(1 for r in rows if r[3])
    no_ground_ok = sum(1 for r in rows if r[5])
    print(f"\n=== 纯静态 presolve 真值比对（data/questions_real, {total} 题）===")
    print(f"  提取到 flag（含无真值题） : {extracted_n}/{total}")
    print(f"  提取 flag 与题库真值一致 : {matched}/{total}  ← 确定性管线真实可验证解出")
    print(f"  已提取但题库无真值(待独立核验): {no_ground_ok} 道")
    for r in rows:
        if r[5]:
            print(f"    · {r[0]} ({r[1]}) 提取={str(r[6])[:40]}")

    print("\n--- 未命中清单（presolve 确定性管线解不出，需 LLM 推理/独立攻击链）---")
    for r in rows:
        if not r[4] and not r[5]:
            print(f"  - {r[0]} ({r[1]}, prov={r[2]}) 提取={str(r[6])[:40]}")


if __name__ == "__main__":
    asyncio.run(main())
