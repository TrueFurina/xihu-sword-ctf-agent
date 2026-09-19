"""LLM 破冰 harness（战役A）：强制走 LLM 主链路，验证真实 LLM 可端到端解出真题。

背景：2026-08 长期"LLM 真推理贡献=0"是临时 outage + 死 baidu 默认 + 免费档熔断的假象，
并非能力缺口。本脚本在配置真实 LLM 凭证前提下，对真题集跑 skip_presolve=True 的真实 Agent，
用 flag_sha256 做独立校验，证明 LLM 驱动链路可解出真题。

严格诚实分类（用户硬性要求"指标严格诚实"）
------------------------------------------------
结果状态分为四类，**严禁混用**：
  - SOLVED / UNSOLVED : 这才是 LLM 推理能力信号（需 env 配真实 key 且跑通）。
  - INFRA_NO_CREDENTIAL : 本环境未配置真实 LLM 凭证(env CTF_AGENT_USE_REAL_LLM=1
                          且 provider key 缺失)。这是基础设施问题，**绝不计入能力统计**，
                          也**绝不**用来宣称"LLM 无能"——历史上 11/15 的"4 未解"正是把
                          这种 API 挂死与真实推理缺陷混为一谈。
  - TIMEOUT : 任务超时被取消，steps 不可得；标注 timeout_cause 疑似基础设施，需先排查
              凭证/网络/首包延迟，再判定是否推理失败。

用法：
    .venv/Scripts/python.exe scripts/_llm_breaking_ice.py \
        --qids real_crypto_ezrsa,real_misc_xuanhun_signin,real_crypto_dnui_keyboard \
        --provider baidu --attempts 2 --timeout 180

输出：
    deliverables/llm_breaking_ice_<ts>.json  每题结果（分类/flag/sha256 校验/steps 数/机制）
    （stdout 同时打印增量进度与诚实 SUMMARY）
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


# 各 provider 常见凭证环境变量（best-effort 预检，避免把"无 key 挂死"误标成"推理失败"）
_PROVIDER_KEY_ENV = {
    # 与 config.resolve_api_key 对齐：千帆单 key 走 QIANFAN_API_KEY（Bearer）。
    # 旧表只列 QIANFAN_AK/SK 等 OAuth 双密钥，漏掉了单 API Key 形式——
    # 会导致环境里明明有 QIANFAN_API_KEY 却被预检误判 INFRA_NO_CREDENTIAL。
    "baidu": ("QIANFAN_API_KEY", "QIANFAN_AK", "QIANFAN_SK", "BAIDU_API_KEY",
              "CTF_AGENT_BAIDU_KEY", "QIANFAN_ACCESS_KEY", "QIANFAN_SECRET_KEY"),
    "deepseek": ("DEEPSEEK_API_KEY", "CTF_AGENT_DEEPSEEK_KEY"),
    "qwen": ("DASHSCOPE_API_KEY", "QWEN_API_KEY", "CTF_AGENT_QWEN_KEY"),
    "moonshot": ("MOONSHOT_API_KEY", "CTF_AGENT_MOONSHOT_KEY"),
    "ark": ("ARK_API_KEY", "VOLCENGINE_ARK_API_KEY", "CTF_AGENT_ARK_KEY"),
    "xfyun": ("XFYUN_APP_ID", "XFYUN_API_KEY", "CTF_AGENT_XFYUN_KEY"),
    "tokenhub": ("TOKENHUB_API_KEY", "CTF_AGENT_TOKENHUB_KEY"),
}


def _credential_available(provider: str) -> bool:
    """best-effort 凭证预检：真实 LLM 开关 + 该 provider 的 key 至少存在一个。

    仅是诚实性护栏——不能 100% 保证 key 有效，但能拦住"本环境压根没配置 key
    却把失败算到 LLM 推理能力头上"这种典型造假。无 key 时 harness 会标
    INFRA_NO_CREDENTIAL，绝不混入 UNSOLVED/推理失败统计。

    2026-09-17 修复（实测 bug）：本项目多数 key 存于**注册表**、仅在 `config`
    导入时同步进 `os.environ`；本脚本只 `import eval.cases`（不触发 config 同步），
    故旧实现仅查 `os.environ` 会把"注册表里有 key"误判为 INFRA_NO_CREDENTIAL
    （实测 qwen/DASHSCOPE 全 15 题被误判）。改为**优先用 `config.resolve_api_key`**
    （含注册表回退），与文件注释「与 config.resolve_api_key 对齐」一致。
    """
    if os.environ.get("CTF_AGENT_USE_REAL_LLM", "").strip() not in ("1", "true", "True"):
        return False
    try:
        from config import resolve_api_key  # 触发配置/注册表同步，并含注册表回退
        if resolve_api_key(provider):
            return True
    except Exception:  # noqa: BLE001 - 预检失败不阻断，落回 env 检查
        pass
    for k in _PROVIDER_KEY_ENV.get(provider, ()):
        if os.environ.get(k):
            return True
    # 兜底：未知 provider 也允许（用户可能用 CTF_AGENT_*_MODEL/KEY 自定义）
    return bool(os.environ.get(f"CTF_AGENT_{provider.upper()}_KEY"))


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

    # 诚实性护栏：无凭证直接标 INFRA_NO_CREDENTIAL，绝不把"没 key 挂死"算作"LLM 推理失败"
    if not _credential_available(provider):
        return {
            "qid": qid,
            "category": getattr(q, "category", "?"),
            "difficulty": getattr(q, "difficulty", "?"),
            "status": "INFRA_NO_CREDENTIAL",
            "provider": provider,
            "use_real_llm": os.environ.get("CTF_AGENT_USE_REAL_LLM"),
            "note": "未配置真实 LLM 凭证(env CTF_AGENT_USE_REAL_LLM=1 且 provider key 缺失)；"
                    "该结果不计入 LLM 推理能力统计",
        }

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
        # 诚实归因：steps==0 且无 LLM 首包 => 大概率 API 挂死/无首响；
        # 否则为推理耗尽预算。无法 100% 区分，但明确标注"需人工复核"。
        return {
            "qid": qid,
            "status": "TIMEOUT",
            "timeout_cause": "api_hang_or_no_first_response_suspected",
            "seconds": round(time.time() - t0, 1),
            "note": "TIMEOUT 不等于推理失败；steps 不可得(任务被取消)，"
                    "优先排查凭证/网络/首包延迟后再判定 LLM 能力",
        }
    except Exception as e:  # noqa: BLE001
        return {"qid": qid, "status": "ERROR", "error": repr(e), "seconds": round(time.time() - t0, 1)}

    flag = out.get("flag")
    ok, canon = _validate(flag, q)
    # 持久化推理轨迹（若存在），使"是否真发生 LLM 推理"可审计——
    # 解决历史上"4 未解"无法区分基础设施挂死与真实推理缺陷的漏洞。
    steps = out.get("steps")
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
        "evidence_injected": out.get("evidence_injected"),
        "reasoning_steps": len(steps) if isinstance(steps, (list, tuple)) else None,
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
    n_solved = sum(1 for r in results if r.get("status") == "SOLVED")
    n_infra = sum(1 for r in results if r.get("status") == "INFRA_NO_CREDENTIAL")
    n_unsolved = sum(1 for r in results if r.get("status") == "UNSOLVED")
    n_to = sum(1 for r in results if r.get("status") == "TIMEOUT")
    summary = {
        "provider": args.provider,
        "skip_presolve": True,
        "total": len(results),
        "solved": n_solved,
        "unsolved_reasoning": n_unsolved,
        "timeout_suspected_infra": n_to,
        "infra_no_credential": n_infra,
        "honest_note": (
            "SOLVED/UNSOLVED 才是 LLM 推理能力信号；INFRA_NO_CREDENTIAL/TIMEOUT "
            "属基础设施问题，严禁计入能力统计或宣称'LLM 无能'。当前若 env 无 key，"
            "全部题将落入 INFRA_NO_CREDENTIAL。"
        ),
        "results": results,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n=== SUMMARY (honest) ===")
    print(f"  solved(推理能力):        {n_solved}/{len(results)}")
    print(f"  unsolved(推理失败):      {n_unsolved}")
    print(f"  timeout(疑似基础设施):   {n_to}")
    print(f"  infra_no_credential:     {n_infra}  <- 本环境若缺 key 全落此项")
    print(f"report -> {out_path}")


if __name__ == "__main__":
    asyncio.run(_main())
