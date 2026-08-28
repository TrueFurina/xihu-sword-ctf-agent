"""单题确定性真值回归（per-problem 可复现 verify，供 merge_gate 回归集调用）。

与 `scripts/_verify_presolve_truth.py` 共用同一套工具层/适配器，但只跑一道题，
输出机器可判定结果：成功打印 `REGRESS_PASS <id>` 并 exit 0；失败 exit 1。
flag 仅以 sha256/规范化比对，绝不回显明文（遵守 8/24 红线）。

用法：
  python scripts/_regress_one.py <question_id> [--dir data/questions_real]
  python scripts/_regress_one.py real_crypto_ezrsa
"""
import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.presolve import presolve  # noqa: E402
from eval.cases import load_questions  # noqa: E402

# ── 复刻 build_solver 的工具层（与真实链路一致）──
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


async def run_one(qid: str, dirs):
    qs = []
    for d in dirs:
        try:
            qs += [q for q in load_questions(d) if q.id == qid]
        except Exception:  # noqa: BLE001 - 某目录缺失不影响其它目录
            continue
    if not qs:
        print(f"REGRESS_SKIP {qid} (not found in {dirs})")
        return 2
    q = qs[0]
    registry = build_registry()
    t0 = time.time()
    try:
        flag = await presolve(q, registry=registry, force=True)
    except Exception as exc:  # noqa: BLE001
        flag = f"<presolve异常:{exc}>"
    dt = (time.time() - t0) * 1000
    extracted = bool(flag) and not str(flag).startswith("<")
    match = bool(extracted and q.flag_matches(str(flag)))
    if match:
        print(f"REGRESS_PASS {q.id} ({q.category}, {dt:.0f}ms) — 确定性管线真值匹配")
        return 0
    print(f"REGRESS_FAIL {q.id} ({q.category}, {dt:.0f}ms) 提取={str(flag)[:48]}")
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("qid")
    ap.add_argument("--dir", action="append", default=None,
                    help="题集目录，可多次；默认 data/questions_real + data/race_details")
    args = ap.parse_args()
    dirs = args.dir or ["data/questions_real", "data/race_details"]
    rc = asyncio.run(run_one(args.qid, dirs))
    sys.exit(rc)


if __name__ == "__main__":
    main()
