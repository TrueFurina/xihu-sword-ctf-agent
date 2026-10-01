#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KPI 合法晋升候选扫描（严格诚实）。

对 data/questions_real 全部真题：
  - 只保留 provenance=real_past_ctf（历年真实赛题，严格 KPI 唯一分母）
  - **排除真值已自带在题目材料里的题（att_leak / desc_leak）** ← 反注水闸门，见下
  - 要求有外部真值 flag_sha256（否则无法独立闭环，不进严格 KPI）
  - 用与真实链路一致的 presolve 确定性管线真跑（force=True）
  - 输出：确定性解出且 sha256 匹配、但不在 AUTHORIZED_KPI_SOLVES(当前13) 的候选

🔴 反注水闸门为什么从 `answer_disclosed` 换成「来源判定」（2026-10-01）：
  旧写法只跳过 `answer_disclosed=True`，而 `data/questions_real` 全池 **92 题该字段恒为
  False**（0 题置真）——**门是死的**。实测（本脚本改动前的行为）：附件里明文躺着真值的
  题（如 `real_crypto_anxun2020_aes` / `real_crypto_changan2021_checkin`）被 presolve
  的附件扫描在 0.0-0.2 秒内"命中"，随即以 MATCH 候选身份提供晋升——**任何一次按它
  晋升，都是把"读附件"记成"解出"**。历史落盘 `deliverables/kpi_candidates_scan.json`
  的 57 条候选里就混着这类题。
  现在改用与 `_leak_provenance.py` **同一台判定机器**（`classify`）：
    att_leak  真值明文在附件里（含 zip 内层 / 裸 token）→ 排除
    desc_leak 真值明文或内层 token 在题面描述里          → 排除
    判定异常/档位未知                                    → 排除（fail-closed）
诚实约束：绝不把"读题目材料里的答案"当解出；flag 仍只做 sha256 比对。
调试用途：`--no-leak-guard` 复刻旧行为（仅用于对比，不得用于晋升）。
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
from scripts._leak_provenance import classify as leak_classify  # noqa: E402

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


# 反注水：真值物理上自带在题目材料里的档位（命中只能算「读到」，不能算「解出」）
LEAK_PROVENANCE = ("att_leak", "desc_leak")
# 与 _leak_provenance.py 的 --dir 约定保持一致（口径同源，不得各判各的）。
# 附件字段本身已是 ctf_agent 相对路径，该 base 仅作路径解析兜底。
LEAK_BASE = Path("data/questions_real")


def split_by_leak(qs, classifier):
    """纯函数：按「答案是否自带在题目材料里」切分题集（反注水闸门）。

    classifier(q) 须返回含 "provenance" 的 dict（与 `_leak_provenance.classify` 同构）。
    返回 (scannable, leaked, unknown)：
      scannable provenance == "none"（材料里没有答案）→ 可进入确定性扫描
      leaked    att_leak / desc_leak → 一律排除：命中是"读到答案"，不是"解出"
      unknown   判定器抛异常或档位未知 → 同样排除（fail-closed）。候选会被用于
                KPI 晋升，误报等于把注水记成能力，故宁可漏报不可误报。
    """
    scannable, leaked, unknown = [], [], []
    for q in qs:
        try:
            prov = str((classifier(q) or {}).get("provenance") or "").strip()
        except Exception as exc:  # noqa: BLE001 - 判定失败必须显式记账，不得静默放行
            unknown.append((q, f"<err:{type(exc).__name__}>"))
            continue
        if prov in LEAK_PROVENANCE:
            leaked.append((q, prov))
        elif prov == "none":
            scannable.append(q)
        else:
            unknown.append((q, prov))
    return scannable, leaked, unknown


def _classify_provenance(q, oracle: dict | None = None) -> dict:
    """复用审计同一台机器判真值来源，避免"扫描器一套、审计另一套"的口径分叉。

    oracle = {id: 明文答案}。题面把答案写成裸 token（如「解出 CLCKOUTHK」）时，
    只有拿到明文才能判出 desc_leak —— 故二段判定须传入本次扫描自己解出的答案。
    """
    return leak_classify(q, LEAK_BASE, oracle)


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


async def main(leak_guard: bool = True):
    qs = load_questions("data/questions_real")
    registry = build_registry()

    # 反注水闸门（默认开）：真值已自带在题目材料里的题一律不入扫。
    if leak_guard:
        scannable, leaked, unknown = split_by_leak(qs, _classify_provenance)
    else:
        scannable, leaked, unknown = list(qs), [], []

    rows = []
    hits: dict = {}  # id -> 本次扫描解出的完整答案（二段反注水判定的明文 oracle）
    for q in scannable:
        if q.provenance != "real_past_ctf":
            continue
        if q.answer_disclosed:
            # 兼容保留：该字段当前全池为 False（死门）；真正的闸门是上面的来源判定。
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
        if match:
            hits[q.id] = str(flag)
        rows.append((q.id, q.category, verdict, in_auth, round(dt),
                     str(flag)[:40] if extracted else None))

    # 二段反注水（oracle）：用本次扫描自己解出的答案，再判一次「题目材料是否自带答案」。
    # att_leak 靠附件里扫真值即可判；desc_leak 唯有拿到明文才能判出——例如
    # real_crypto_dnui_keyboard 题面直接写「解出 CLCKOUTHK」，presolve 返回
    # flag{CLCKOUTHK} 并 MATCH：那不是解出，是把题面给的答案抄出来。
    if leak_guard and hits:
        rescan, desc_leaked, unk2 = split_by_leak(
            scannable, lambda q: _classify_provenance(q, hits))
        if desc_leaked or unk2:
            leaked = leaked + desc_leaked
            unknown = unknown + unk2
            keep = {q.id for q in rescan}
            rows = [r for r in rows if r[0] in keep]
            scannable = rescan

    # 分类输出
    candidates = [r for r in rows if r[2] == "MATCH" and r[3] is False]
    already = [r for r in rows if r[2] == "MATCH" and r[3] is True]
    no_truth = [r for r in rows if r[2] == "NO_EXT_TRUTH"]
    failed = [r for r in rows if r[2] in ("FAIL", "EXTRACTED_NO_TRUTH")]

    print(f"=== 扫描 data/questions_real（real_past_ctf + 非注水 + 有外部真值）===")
    print(f"  入扫 {len(scannable)} 题 | 反注水排除 {len(leaked)} 题 | "
          f"判定失败排除 {len(unknown)} 题（闸门={'开' if leak_guard else '关'}）")
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

    # 反注水记账：被闸门挡下的题必须可见（否则"少了题"无从复核）
    if leaked:
        print(f"  ⛔ 反注水排除（真值自带在题目材料里，命中≠解出）: {len(leaked)}")
        for q, prov in leaked:
            print(f"      {q.id:38s} {prov}")
    if unknown:
        print(f"  ⚠️ 真值来源判定失败（fail-closed 排除，需人工复核）: {len(unknown)}")
        for q, why in unknown:
            print(f"      {q.id:38s} {why}")

    # 落盘 JSON 供后续晋升流程读取
    out = {
        "leak_guard": leak_guard,
        "scanned": len(scannable),
        "candidates": [
            {"id": r[0], "category": r[1], "ms": r[4]} for r in candidates
        ],
        "already_authorized": [r[0] for r in already],
        "no_external_truth": [r[0] for r in no_truth],
        "failed": [{"id": r[0], "category": r[1], "verdict": r[2]} for r in failed],
        "leak_excluded": [{"id": q.id, "provenance": p} for q, p in leaked],
        "leak_unknown": [{"id": q.id, "why": w} for q, w in unknown],
    }
    Path("deliverables/kpi_candidates_scan.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n落盘: deliverables/kpi_candidates_scan.json")


if __name__ == "__main__":
    import argparse

    _ap = argparse.ArgumentParser(description="KPI 候选扫描（含反注水闸门）")
    _ap.add_argument("--no-leak-guard", action="store_true",
                     help="复刻旧的 answer_disclosed-only 行为；仅供对比，不得用于晋升")
    asyncio.run(main(leak_guard=not _ap.parse_args().no_leak_guard))
