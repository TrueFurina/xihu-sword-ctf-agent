"""主 Agent 真打 web-002 / web-003（强制 presolve-skip，走 LLM 全链路），验证泛化。

目的：web-001 已证明"LLM 在 web 上的能力缺口本质是工具缺陷（GET vs POST），不是 LLM 质量问题"。
本脚本验证该结论能否**泛化**到其它 web 漏洞类型（SSTI / 反序列化），把 LLM 贡献从 1 推到 3。

靶机需先起（各自一个终端 / 或后台）：
    .venv/Scripts/python.exe scripts/web_target_ssti.py
    .venv/Scripts/python.exe scripts/web_target_unserialize.py

用法：
    VERIFY_IDS=web-002,web-003 VERIFY_PROVIDER=qwen \
        .venv/Scripts/python.exe scripts/_verify_web_batch.py

不计分练兵场（比赛已结束、平台不可达），仅用于诊断主 Agent 真实 web 推理能力泛化。
"""
from __future__ import annotations

import asyncio
import os
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from run import build_solver  # noqa: E402
from eval.cases import load_questions  # noqa: E402


async def main() -> None:
    provider = os.getenv("VERIFY_PROVIDER", "qwen")
    ids = [x.strip() for x in os.getenv("VERIFY_IDS", "web-002,web-003").split(",") if x.strip()]
    questions = {q.id: q for q in load_questions("data/questions")}

    # 强制跳过 presolve，走主 Agent LLM 全链路（与 web-001 验证一致）
    solver = build_solver(use_mock=False, provider=provider,
                          validate_locally=True, skip_presolve=True)

    summary = []
    for qid in ids:
        q = questions.get(qid)
        if q is None:
            print(f"[{qid}] 不在 data/questions")
            summary.append((qid, False, "missing"))
            continue
        print(f"=== 主 Agent 真打 {qid}（presolve 跳过，LLM 全链路） provider={provider} ===")
        out = await solver(q, 1)
        flag = (out or {}).get("flag") or (out or {}).get("answer")
        err = (out or {}).get("error") or {}
        solved = bool(flag) and (q.flag in str(flag))
        err_cat = err.get("category") if isinstance(err, dict) else err
        print(f"  flag: {flag}")
        print(f"  llm_calls: {(out or {}).get('llm_calls')} steps: {(out or {}).get('steps')}")
        print(f"  error: {err_cat}")
        print(f"  SOLVED_BY_LLM: {solved}")
        summary.append((qid, solved, str(flag)))

    print("\n=== 汇总 ===")
    for qid, ok, fl in summary:
        print(f"  {qid}: {'OK' if ok else 'FAIL'} ({fl})")


if __name__ == "__main__":
    asyncio.run(main())
