# -*- coding: utf-8 -*-
"""C 类 skill 端到端实证：按主链同一路径（SkillManager.load → registry.run）。

零 LLM 成本：不进 LLM 阶段，纯本地数论 solver。
验证链：
  1. infer_skill_require 路由命中目标 skill（真实 SkillManager）
  2. skill_dispatch.extract_numeric_params 提取出参数
  3. registry.run(skill, params) 真跑 solver
  4. extract_flag 抽出 flag，与题库 flag_sha256 逐字比对

用法：python scripts/_verify_numeric_dispatch.py [cycling|primes|mhk2|all]
"""
import hashlib
import os
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.cases import load_questions  # noqa: E402
from core.prompts import infer_skill_require  # noqa: E402
from tools.skill_manager import SkillManager  # noqa: E402
from tools.registry import ToolRegistry  # noqa: E402
from tools.skill_dispatch import (  # noqa: E402
    extract_flag, extract_numeric_params,
)

CASES = [
    # (question_id, dataset, expected skill)
    ("ext_gctf2022_cycling", "data/questions_external", "crypto_cycling"),
    ("ext_gctf2023_primes", "data/questions_external", "crypto_primes_subset"),
    ("ext_gctf2023_mhk2", "data/questions_external", "crypto_knapsack_mhk"),
]


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def run_one(qid, dataset, expect_skill, sm, registry, verbose=True):
    qs = load_questions(dataset)
    q = next((x for x in qs if getattr(x, "id", "") == qid), None)
    if q is None:
        print("[%s] 未找到题目" % qid)
        return False

    print("\n" + "=" * 70)
    print("### %s" % qid)

    # ① 路由
    req = infer_skill_require(SimpleNamespace(question=q),
                              {"ability_gap": ["<probe>"]}, skill_manager=sm)
    got = (req or {}).get("skill_name")
    ok1 = got == expect_skill
    print("  ① 路由: %s  %s" % (got, "OK" if ok1 else "期望 " + expect_skill))
    if not ok1:
        return False

    # ② 参数提取
    params = extract_numeric_params(expect_skill, q)
    print("  ② 参数提取: %s" % ("OK keys=%s" % sorted(params)
                             if params else "None → fail-closed"))
    if not params:
        return False

    # ③ registry.run（与主链同一路径）
    try:
        sm.load(expect_skill)
    except Exception as e:  # noqa: BLE001
        print("  load 失败: %s" % e)
        return False
    if not registry.get(expect_skill):
        print("  ③ 未注册进 registry")
        return False
    t0 = time.time()
    try:
        # ToolRegistry.run 是协程（主链里用 await self.registry.run(...)）；
        # 本脚本离线验证，用 asyncio.run 走同一条协程路径。
        import asyncio
        out = asyncio.run(registry.run(expect_skill, params))
    except Exception as e:  # noqa: BLE001
        print("  ③ run 异常: %s: %s" % (type(e).__name__, e))
        return False
    dt = time.time() - t0
    if verbose:
        print("  ③ run 完成 %.1fs" % dt)

    # ④ flag 校验
    flag = extract_flag(out)
    if not flag:
        print("  ④ 未解出 flag；返回: %s" % str(out)[:300])
        return False
    truth = getattr(q, "flag_sha256", None)
    hit = sha256(flag)
    print("  ④ flag=%s" % flag)
    if truth:
        ok = hit == truth
        print("     sha256 %s %s" % (hit[:16] + "...",
                                     "MATCH 真值" if ok else "≠ 真值 " + truth[:16]))
        return ok
    print("     (题库无 flag_sha256，仅证明 flag 非空)")
    return True


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    registry = ToolRegistry()
    sm = SkillManager(registry=registry)
    try:
        sm.discover()
    except Exception as e:  # noqa: BLE001
        print("discover: %s" % e)
    results = {}
    for qid, dataset, skill in CASES:
        if which not in ("all", skill.split("_")[-1], qid):
            continue
        results[qid] = run_one(qid, dataset, skill, sm, registry)
    print("\n" + "=" * 70)
    print("汇总: %s" % results)
    print("PASS %d / %d" % (sum(1 for v in results.values() if v), len(results)))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
