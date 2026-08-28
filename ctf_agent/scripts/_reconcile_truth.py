"""诚实真值收口（2026-08-27）：对真题集可复现题落盘全量 flag + sha256。

- 仅记录「确定性 presolve 真值匹配」的题（零 LLM，离线可复现）。
- 分类标注 A/B/C/D，严格 KPI 只数 A/B 类（C=源码grep、D=题面给答案 不计）。
- specialcurve2 / 10732 / 10735 不可复现，不写入严格KPI（单独标注 unreproducible）。
用法：.venv/Scripts/python.exe scripts/_reconcile_truth.py
"""
import asyncio
import hashlib
import json
import os
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.presolve import presolve  # noqa: E402
from eval.cases import load_questions  # noqa: E402
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


# 分类（A/B 计入严格KPI；C=源码grep；D=题面给答案；均依据 _verify_presolve_truth 实测）
CLASS = {
    "real_crypto_anwang_crypto1": "B",   # 八进制+Vigenère
    "real_crypto_dnui_keyboard": "D",    # 题面直接给 CLCKOUTHK
    "real_crypto_exciting_inverse": "B",  # 矩阵求逆
    "real_crypto_ezmult": "B",           # base64+ROT13
    "real_crypto_ezrsa": "B",            # Hastad CRT
    "real_crypto_filterrandom": "B",      # LFSR 噪声恢复（重建实例，匹配题面sha256）
    "real_crypto_qiangwang_classic": "B",  # 摩斯+单表替换
    "real_crypto_simplelegendre": "B",    # 勒让德逐位
    "real_crypto_specialcurve2": "UNREPRODUCIBLE",  # 附件仅模板，实例值丢失
    "real_misc_vnctf_flag": "A",          # 图像重采样+OCR
    "real_misc_xuanhun_signin": "A",      # JPEG嵌PNG+OCR
    "real_reverse_js": "C",               # 源码 flag_scan grep
    "real_reverse_sheng": "A",            # 逆向静态分析
    "real_reverse_upx": "A",              # UPX 脱壳
    "real_web_gongye_web2": "C",          # 源码审计 flag_scan grep
}


def build_registry():
    sandbox = SubprocessExecutor()
    registry = ToolRegistry()
    for a in (FileAnalysisAdapter(), StegoAdapter(), PythonAdapter(sandbox=sandbox),
              HashCrackAdapter(), WordlistCrackAdapter(), WebRequestAdapter(),
              OpensslAdapter(sandbox=sandbox), BkcrackAdapter(sandbox=sandbox),
              XxeFileReadAdapter(), ZipChainDecodeAdapter(),
              DeterministicDecodeAdapter(), CryptoAutoAdapter(sandbox=sandbox),
              FlagScanAdapter()):
        registry.register(a)
    return registry


async def main():
    store_path = "data/results/verified_flags.json"
    store = json.load(open(store_path, encoding="utf-8"))
    registry = build_registry()
    qs = load_questions("data/questions_real")

    count_a = count_b = 0
    for q in qs:
        cid = q.id
        cls = CLASS.get(cid, "?")
        if cls in ("UNREPRODUCIBLE", "C", "D"):
            # 仍记录 flag（若可得），但标注不计 KPI
            continue
        try:
            flag = await presolve(q, registry=registry, force=True)
        except Exception as exc:  # noqa: BLE001
            print(f"  [ERR] {cid}: {exc}")
            continue
        if not flag or str(flag).startswith("<"):
            print(f"  [MISS] {cid} (class {cls})")
            continue
        flag = str(flag)
        if not q.flag_matches(flag):
            print(f"  [MISMATCH] {cid}: {flag[:40]}")
            continue
        sha = hashlib.sha256(flag.encode("utf-8")).hexdigest()
        store[cid] = {
            "flag": flag,
            "sha256": sha,
            "verified": "offline_verified",
            "class": cls,
            "source": "确定性 presolve 真值匹配（零 LLM，离线可复现）+ 题面 flag_sha256 校验",
            "date": date.today().isoformat(),
        }
        print(f"  [OK {cls}] {cid}: {flag[:50]}")
        if cls == "A":
            count_a += 1
        elif cls == "B":
            count_b += 1

    # 10733（race_details 平台题，已独立复现）—— 明文 flag 仅存于本地 gitignored
    # data/results/verified_flags.json，由脚本起始 json.load 载入并原样保留，不在此硬编码。
    if "real_crypto_10733" in store and store["real_crypto_10733"].get("verified") == "offline_verified":
        count_a += 1

    # 不可复现标注（不计入）
    for cid in ("real_crypto_specialcurve2", "real_crypto_10732", "real_crypto_10735"):
        store[cid] = {
            "verified": "unreproducible_2026-08-27",
            "class": "A(claimed)",
            "note": "附件/求解器缺失或实例值丢失，无法离线复现；已从严格KPI移除",
            "date": date.today().isoformat(),
        }

    json.dump(store, open(store_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"\n=== 诚实收口：严格 KPI 可复现 A/B 类 = {count_a} (A) + {count_b} (B) = {count_a + count_b} ===")


if __name__ == "__main__":
    asyncio.run(main())
