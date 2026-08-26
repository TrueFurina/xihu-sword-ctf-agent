"""真实 LLM 端到端冒烟（赛前必跑：验证非 mock 链路全通）。

背景（2026-08-21 锐评 P0-3）：tests/ 套件零真实 LLM 覆盖，全是 mock 查表自嗨，
"7/7 绿"不代表真实 deepseek 链路可用。本脚本补上这条缺口——真实 Key + 真实端点 +
完整 build_solver（工具层 + 数学引擎 + fast_solve + LLM 推理）跑一道真库题。

用法：
    .venv/Scripts/python.exe scripts/_smoke_real_llm.py [--question crypto-002]
    .venv/Scripts/python.exe scripts/_smoke_real_llm.py --quick   # 仅最小往返，不跑题

退出码：0=全通；1=链路断（赛前必须排查）。
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _probe_key() -> str:
    from config import resolve_api_key, _resolve_provider_defaults

    key = resolve_api_key("deepseek")
    base, model = _resolve_provider_defaults("deepseek")
    print(f"[1] 配置探测: base={base} model={model} key={'sk-'+key[3:9]+'...' if key else 'NONE'}")
    if not key:
        print("FAIL: 未解析到 DeepSeek Key（检查 DEEPSEEK_API_KEY / 注册表）")
        sys.exit(1)
    return base, model


def _min_roundtrip() -> None:
    from llm.client import ai_chat

    t0 = time.time()
    text = ai_chat([{"role": "user", "content": "只回复两个汉字：正常"}],
                   provider="deepseek", model="deepseek-chat", max_tokens=16)
    dt = time.time() - t0
    print(f"[2] 最小 LLM 往返: 耗时 {dt:.1f}s 响应={text!r}")
    if not text:
        print("FAIL: 最小往返失败（白名单/网络/额度/解析 任一环节断）")
        sys.exit(1)


def _run_one_question(qid: str) -> None:
    import run as run_mod
    from eval.cases import load_questions, preset_answers

    questions = load_questions("data/questions")
    answers = preset_answers(questions)
    q = next((x for x in questions if x.id == qid), None)
    if q is None:
        print(f"FAIL: 题库无题目 {qid}")
        sys.exit(1)
    expected = answers.get(qid)

    solver = run_mod.build_solver(use_mock=False)  # 真实模式（is_correct 默认比对题库答案）

    async def _solve():
        return await solver(q, 0, None)

    print(f"[3] 真实求解: {qid} {q.title} (difficulty={getattr(q,'difficulty','?')})")
    t0 = time.time()
    out = asyncio.run(_solve())
    dt = time.time() - t0
    flag = out.get("flag")
    print(f"    耗时 {dt:.1f}s | flag={flag!r} | expected={expected!r}")
    print(f"    provider={out.get('provider')} | validated={out.get('validated')} "
          f"| error={out.get('error')}")
    if not flag:
        print("FAIL: 未解出（真实链路解题失败，需排查）")
        sys.exit(1)
    if expected and flag != expected:
        print(f"FAIL: flag 不匹配（{flag} != {expected}）——幻觉/跨题误判")
        sys.exit(1)
    print("PASS: 真实端到端链路全通（LLM/工具/数学引擎/fast_solve 至少其一真实跑通）")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--question", default="crypto-002", help="用于端到端的题目 id（默认 crypto-002 凯撒 easy）")
    ap.add_argument("--quick", action="store_true", help="仅最小往返，不跑题")
    args = ap.parse_args()

    _probe_key()
    _min_roundtrip()
    if args.quick:
        print("PASS: 最小往返通过（--quick 模式不跑题）")
        return
    _run_one_question(args.question)


if __name__ == "__main__":
    main()
