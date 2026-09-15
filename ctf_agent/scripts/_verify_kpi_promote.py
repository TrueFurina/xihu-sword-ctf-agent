#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KPI 晋升诚实甄别（严格）。

对扫描出的候选（确定性解出+真值匹配+未入白名单），逐题重跑 presolve 取明文 flag，
并鉴别解出来源，杜绝把"读泄露附件/题面给答案"当能力注水：
  - leak_attachment : 明文 flag 出现在某附件文件内容中 → 读泄露答案（注水，不晋升）
  - leak_description: 明文 flag 出现在题面 description 中 → D类 题面直接给答案（不晋升）
  - genuine         : 均不命中 → 真从挑战数据确定性计算得出（B类合法晋升）
flag 仅本地 sha256 比对，绝不明文回显到 stdout 之外。

已知局限（2026-09-15 实测，最终归类以人工复核 + 台账分类规则为准）：
  - 附件路径拼接对位于 ctf_agent/scripts/ 子目录的题会双拼 ctf_agent/，致该子类题
    未被自动附件扫描（vnctf_cm1 即属此类，已人工确认其 solver 为真 XXTEA 计算、非读泄露）。
  - dnui_keyboard 因 flag 格式 flag{CLCKOUTHK} 与 description 纯 CLCKOUTHK 不匹配，
    被漏判为 genuine；按其题面给答案属性归 D 类（不晋升，见台账收录边界规则）。
"""
import asyncio
import hashlib
import json
import os
import sys
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


def _local_attachment_paths(q, root):
    out = []
    for att in q.attachments:
        p = Path(root) / att
        if not p.exists():
            # 试 _attachments 子目录
            p2 = Path(root) / "data" / "questions_real" / "_attachments" / att
            if p2.exists():
                out.append(p2)
            continue
        out.append(p)
    return out


async def main():
    root = Path(__file__).resolve().parent.parent
    scan = json.loads(Path("deliverables/kpi_candidates_scan.json").read_text(encoding="utf-8"))
    cands = [c["id"] for c in scan["candidates"]]
    qs = {q.id: q for q in load_questions("data/questions_real")}
    registry = build_registry()

    genuine, leak_att, leak_desc, failed = [], [], [], []
    for qid in cands:
        q = qs.get(qid)
        if not q:
            failed.append((qid, "not_found"))
            continue
        try:
            flag = await presolve(q, registry=registry, force=True)
        except Exception as exc:  # noqa: BLE001
            flag = f"<err:{exc}>"
        extracted = bool(flag) and not str(flag).startswith("<")
        if not extracted or not q.flag_matches(str(flag)):
            failed.append((qid, "no_match"))
            continue
        f = str(flag)
        # 鉴别：flag 是否出现在附件 / 题面
        leak_in_att = False
        for ap in _local_attachment_paths(q, root):
            try:
                txt = ap.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                try:
                    data = ap.read_bytes()
                    txt = data.decode("utf-8", errors="ignore")
                except Exception:
                    continue
            if f in txt:
                leak_in_att = True
                break
        leak_in_desc = f in (q.description or "")
        if leak_in_att:
            leak_att.append(qid)
        elif leak_in_desc:
            leak_desc.append(qid)
        else:
            genuine.append(qid)

    print("=== 晋升诚实甄别结果 ===")
    print(f"  ✅ genuine（真确定性计算，合法晋升）: {len(genuine)}")
    for i in genuine:
        print(f"      + {i}")
    print(f"  ⛔ leak_attachment（读泄露附件，注水，不晋升）: {len(leak_att)}")
    for i in leak_att:
        print(f"      - {i}")
    print(f"  ⛔ leak_description（题面直接给答案/D类，不晋升）: {len(leak_desc)}")
    for i in leak_desc:
        print(f"      - {i}")
    print(f"  ⚠️ failed（重跑未匹配）: {len(failed)}")
    for i, r in failed:
        print(f"      - {i} ({r})")

    out = {
        "genuine": genuine,
        "leak_attachment": leak_att,
        "leak_description": leak_desc,
        "failed": [r[0] for r in failed],
    }
    Path("deliverables/kpi_promote_plan.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n落盘: deliverables/kpi_promote_plan.json")


if __name__ == "__main__":
    asyncio.run(main())
