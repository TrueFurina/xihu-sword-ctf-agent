# -*- coding: utf-8 -*-
"""诊断：真实循环里浅层工具空转检测器为何没触发（一次性脚本，可删）。

用包装器 instrumentation 真实循环：打印 _apply_shallow_escalation /
_force_deep_probe 每次被调用时看到的 steps/tool_used/escalated_tools，
以及 solve 收口后逐步的 tool_used 序列。
"""
import asyncio
import json
import sys

sys.path.insert(0, ".")

from types import SimpleNamespace

import core.main_agent as ma
from sandbox.subprocess_executor import SubprocessExecutor
from tools.registry import ToolRegistry
from tools.adapters.file_analysis_adapter import FileAnalysisAdapter
from tools.adapters.stego_adapter import StegoAdapter
from tools.adapters.python_adapter import PythonAdapter
from tools.adapters.hash_crack_adapter import HashCrackAdapter
from tools.adapters.wordlist_crack_adapter import WordlistCrackAdapter
from tools.adapters.web_request_adapter import WebRequestAdapter
from tools.adapters.openssl_adapter import OpensslAdapter
from tools.adapters.bkcrack_adapter import BkcrackAdapter
from tools.adapters.xxe_adapter import XxeFileReadAdapter
from tools.adapters.zip_chain_adapter import ZipChainDecodeAdapter
from tools.adapters.deterministic_decode_adapter import DeterministicDecodeAdapter
from tools.adapters.crypto_auto_adapter import CryptoAutoAdapter
from tools.adapters.flag_scan_adapter import FlagScanAdapter
from tools.adapters.rea_probe import ReaProbeAdapter
from tools.adapters.wasm_probe import WasmProbeAdapter
from tools.adapters.pcap_probe import PcapProbeAdapter

QID = "ext_cybench_hackthebox_cyber_apocalypse_2024_reversing_easy_crushing"
_ctx_box = {}


def build_registry():
    sandbox = SubprocessExecutor(default_timeout=60)
    r = ToolRegistry()
    for A in (FileAnalysisAdapter, StegoAdapter, CryptoAutoAdapter, FlagScanAdapter,
              ReaProbeAdapter, WasmProbeAdapter, PcapProbeAdapter):
        r.register(A())
    r.register(PythonAdapter(sandbox=sandbox))
    for A in (HashCrackAdapter, WordlistCrackAdapter, WebRequestAdapter,
              OpensslAdapter, BkcrackAdapter, XxeFileReadAdapter,
              ZipChainDecodeAdapter, DeterministicDecodeAdapter):
        r.register(A())
    return r


_llm_n = {"i": 0}


async def fake_llm(system, user, attempt):
    # glm 实证形态：计划恒为 reason（presolve 会先分析附件，act 兜底不触发）
    _llm_n["i"] += 1
    return json.dumps({"action": "reason", "detail": f"思考第{_llm_n['i']}轮",
                       "hypothesis": "diag"}, ensure_ascii=False)


async def _async_none(*a, **k):
    return None


def _wrap_apply(orig):
    def _w(agent, ctx):
        _ctx_box["ctx"] = ctx
        tools = [str(getattr(s, "tool_used", "") or "") for s in (ctx.steps or [])]
        print(f"  [apply] steps={len(ctx.steps)} tools={tools} "
              f"escalated={set(ctx.escalated_tools)} cand={ctx.candidate_flag}")
        r = orig(agent, ctx)
        print(f"  [apply] -> {r}")
        return r
    return _w


def _wrap_force(orig):
    async def _w(agent, question, ctx):
        _ctx_box["ctx"] = ctx
        tools = [str(getattr(s, "tool_used", "") or "") for s in (ctx.steps or [])]
        print(f"  [force] steps={len(ctx.steps)} tools={tools} "
              f"escalated={set(ctx.escalated_tools)} forced={set(ctx.forced_probes)}")
        try:
            r = await orig(agent, question, ctx)
        except Exception as e:
            print(f"  [force] EXC {type(e).__name__}: {e}")
            raise
        print(f"  [force] -> {r}")
        return r
    return _w


async def main():
    q = json.load(open(f"benchmarks/external_unseen/questions/{QID}.json", encoding="utf-8"))
    qobj = SimpleNamespace(id=QID, category="reverse", difficulty="EASY",
                           description=q.get("description", "d"),
                           attachments=list(q.get("attachments", [])),
                           flag_pattern=None, extra={})
    ma._apply_shallow_escalation = _wrap_apply(ma._apply_shallow_escalation)
    ma._force_deep_probe = _wrap_force(ma._force_deep_probe)
    agent = ma.MainAgent(llm_client=fake_llm, registry=build_registry(),
                         per_question_wallclock=300, llm_call_budget=9)
    # 不 patch presolve：忠实复现真实跑（presolve 先分析附件 → act 兜底不触发）
    try:
        res = await agent.solve(qobj)
    finally:
        pass
    ctx = _ctx_box.get("ctx")
    print("=== solve done ===")
    print("steps:", res.get("steps"), "| flag:", res.get("flag"),
          "| err:", str(res.get("error"))[:100])
    if ctx is not None:
        print("final tool_used seq:",
              [str(getattr(s, "tool_used", "") or "") for s in ctx.steps])
        print("escalated_tools:", set(ctx.escalated_tools),
              "| forced_probes:", set(ctx.forced_probes))
        print("manual detector on final ctx:",
              ma._shallow_tool_escalation(agent, ctx))
        print("attachments:", qobj.attachments)


if __name__ == "__main__":
    asyncio.run(main())
