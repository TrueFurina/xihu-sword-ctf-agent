"""一次性验证：纯静态 presolve 能否独立解出真题集各题（零 LLM 调用）。

目的：把「13/15 解出」严格拆成
  - 静态 presolver 秒解（确定性分析器，零 LLM）
  - 真正需要 LLM 推理的题
避免把静态分析器功劳算到 LLM 头上（第六轮锐评防自欺核心）。

用法：.venv/Scripts/python.exe scripts/_verify_presolve_only.py
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.presolve import presolve  # noqa: E402
from eval.cases import load_questions  # noqa: E402


async def main():
    qs = load_questions("data/questions_real")
    print(f"加载真题 {len(qs)} 道\n")
    rows = []
    for q in qs:
        try:
            flag = await presolve(q, registry=None, force=True)
        except Exception as exc:  # noqa: BLE001
            flag = f"<presolve异常:{exc}>"
        hit = bool(flag) and not str(flag).startswith("<")
        rows.append((q.id, q.category, hit, flag))
        status = "PRESOLVE命中" if hit else "presolve未命中"
        shown = (flag[:50] + "...") if flag and len(str(flag)) > 50 else flag
        print(f"  [{status}] {q.id:35s} {q.category:8s} -> {shown}")

    solved = sum(1 for _, _, h, _ in rows if h)
    print(f"\n=== 纯静态 presolve 独立解出: {solved}/{len(qs)} ===")
    print("（这些题零 LLM 调用即可解出；剩余需 LLM 推理或真未解出）")

    remain = [r for r in rows if not r[2]]
    if remain:
        print(f"\n需 LLM 推理 / 未解出（{len(remain)} 道）:")
        for qid, cat, _, _ in remain:
            print(f"  - {qid} ({cat})")


if __name__ == "__main__":
    asyncio.run(main())
