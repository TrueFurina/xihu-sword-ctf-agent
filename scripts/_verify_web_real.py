"""主 Agent 真打 web-001（强制 presolve-skip，走 LLM 全链路）。

目的：用真执行靶机暴露主 Agent 在 web 上的真实 LLM 能力缺口（E 类问题）。
靶机需先起：.venv/Scripts/python.exe -c "from scripts.web_target_real import RealWebTarget; RealWebTarget().start(); import threading; threading.Event().wait()"

不计分练兵场（比赛已结束、平台不可达），仅用于诊断主 Agent 真实 web 推理能力，
对比 presolve 主导的 15/15 假象。

provider 用环境变量 VERIFY_PROVIDER 覆盖（默认 qwen，因 baidu 千帆账号 overdue 熔断）。

用法：.venv/Scripts/python.exe scripts/_verify_web_real.py
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
    questions = load_questions("data/questions")
    q = next((x for x in questions if x.id == "web-001"), None)
    if q is None:
        print("ERROR: web-001 不在 data/questions"); return
    print(f"题目: {q.id} / {q.category} / {q.title}")
    print(f"provider: {provider}")

    # 强制跳过 presolve，走主 Agent LLM 全链路
    solver = build_solver(use_mock=False, provider=provider,
                          validate_locally=True, skip_presolve=True)
    print("=== 主 Agent 真打 web-001（presolve 已跳过，LLM 全链路）===")
    out = await solver(q, 1)
    flag = (out or {}).get("flag") or (out or {}).get("answer")
    solved = bool(flag) and "sqli_waf_bypass" in str(flag)
    err = (out or {}).get("error") or {}
    print("solver output keys:", list((out or {}).keys()))
    print("flag:", flag)
    print("error:", err.get("category") if isinstance(err, dict) else err)
    print("llm_calls:", (out or {}).get("llm_calls"), "steps:", (out or {}).get("steps"))
    print("SOLVED_BY_LLM:", solved)
    print("诚实口径: 若解出则主 Agent LLM 贡献 +1（此前真题集 15/15 全为 presolve 直出，LLM 贡献=0）")


if __name__ == "__main__":
    asyncio.run(main())
