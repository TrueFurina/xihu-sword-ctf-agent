# -*- coding: utf-8 -*-
"""全库「主链 skill dispatch」能力兑现审计（零 LLM 成本，确定性）。

回答一个问题：**不用 LLM、不花 token，主链的 skill 路由 + 自动调用
能在全库兑现出多少道真解？**

链路完全对齐 core/main_agent.py 的通用 skill 调用分支：
    infer_skill_require(ctx, reflection, skill_manager)     —— 真实路由表
      → AUTO_CALLABLE 白名单判定
      → skill_manager.load(skill) → 注册进 registry
      → skill_dispatch.iter_candidate_params(skill, question)
      → await registry.run(skill, params)
      → extract_flag(result)
      → sha256 与题库 flag_sha256 逐字比对

诚实口径：
  * 这是**确定性兜底层**（roster 层）的上界，不等于 LLM 自主解出。
  * 但它代表了「接线能力→解题率」的**可兑现部分**：这些题在真实跑批里
    由主链自动触达，0 token、不依赖模型水平。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.cases import load_questions  # noqa: E402,F401（兼容旧引用）
from eval.corpus import (  # noqa: E402
    DEFAULT_ROOTS, load_corpus, measurable,
)
from core.prompts import infer_skill_require  # noqa: E402
from tools.skill_manager import SkillManager  # noqa: E402
from tools.registry import ToolRegistry  # noqa: E402
from tools.skill_dispatch import (  # noqa: E402
    AUTO_CALLABLE, extract_flag, iter_candidate_params,
)

DATASETS = DEFAULT_ROOTS  # 单一真相源：去重/择优顺序统一由 eval.corpus 定义
PER_CALL_TIMEOUT = 180  # 单题单 skill 调用上限（秒）


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def load_all(measurable_only: bool = True):
    """跨题库取 unique 题（去重/择优统一走 eval.corpus.load_corpus）。

    2026-10-07 修订：删掉脚本内私有的 _att_score 实现，改用共享层，
    避免判定口径再次漂移（此前正是两份实现不一致导致假象）。

    Args:
        measurable_only: 只保留可计入分母的题（有输入且真值）。
            input-less 题（附件已失效）跑必然 0 分，属数据缺失而非能力
            缺失，计入分母只会稀释真实解题率。
    """
    entries = load_corpus()
    kept = [e for e in entries if (not measurable_only) or measurable(e.question)]
    print("题库 unique 题数: %d" % len(entries))
    if measurable_only:
        print("可计分母(有输入+真值): %d，剔除 input-less/无真值: %d"
              % (len(kept), len(entries) - len(kept)))
    return [(e.source, e.question) for e in kept]


async def try_one(registry, sm, q, skill_name, timeout=PER_CALL_TIMEOUT):
    """对齐主链：load → iter_candidate_params → registry.run → extract_flag。"""
    try:
        sm.load(skill_name)
    except Exception:  # noqa: BLE001
        return None, "load_failed"
    if not registry.get(skill_name):
        return None, "not_registered"
    last_out = None
    for params in iter_candidate_params(skill_name, q):
        t0 = time.time()
        try:
            out = await asyncio.wait_for(
                registry.run(skill_name, params), timeout=timeout)
        except asyncio.TimeoutError:
            return None, "timeout"
        except Exception as e:  # noqa: BLE001
            return None, "%s: %s" % (type(e).__name__, str(e)[:80])
        flag = extract_flag(out)
        if flag:
            return flag, round(time.time() - t0, 1)
        # 记录未命中的候选输出，便于区分「附件不对」「solver 报错」「格式未识别」
        _t = getattr(out, "text", None)
        last_out = (_t if isinstance(_t, str) else str(out))[:120]
    if last_out is not None:
        return None, "no_flag; last_out=%s" % last_out
    return None, "no_candidate_params"


async def main_async(dry=False):
    registry = ToolRegistry()
    sm = SkillManager(registry=registry)
    try:
        sm.discover()
    except Exception as e:  # noqa: BLE001
        print("discover: %s" % e)

    corpus = load_all()
    print("题库总数: %d" % len(corpus))

    routed, attempted, solved = [], [], []
    for dataset, q in corpus:
        req = infer_skill_require(SimpleNamespace(question=q),
                                  {"ability_gap": ["<audit>"]},
                                  skill_manager=sm)
        name = (req or {}).get("skill_name")
        if not name:
            continue
        routed.append((q.id, name, dataset))
        if name not in AUTO_CALLABLE:
            continue
        attempted.append((q.id, name))
        if dry:
            solved.append({
                "id": q.id, "title": getattr(q, "title", ""), "skill": name,
                "dataset": dataset, "flag_nonempty": False,
                "sha256_match": False, "detail": "dry",
            })
            continue
        flag, meta = await try_one(registry, sm, q, name)
        truth = getattr(q, "flag_sha256", None)
        ok = bool(flag and truth and _sha(flag) == truth)
        solved.append({
            "id": q.id, "title": getattr(q, "title", ""), "skill": name,
            "dataset": dataset, "flag_nonempty": bool(flag),
            "sha256_match": ok, "detail": meta,
        })
        if flag:
            print("  %-34s %-26s %s  %ss" % (
                q.id, name, ("MATCH" if ok else "flag≠真值"), meta))

    print("\n" + "=" * 74)
    print("汇总")
    print("  路由命中 skill 的题数      : %d" % len(routed))
    print("  其中 skill 在自动调用白名单: %d" % len(attempted))
    hit = [s for s in solved if s["sha256_match"]]
    print("  端到端解出且 sha256 匹配    : %d" % len(hit))
    print("  解出 flag 但与真值不符      : %d" %
          len([s for s in solved if s["flag_nonempty"] and not s["sha256_match"]]))
    if hit:
        print("\n真解题清单（0 LLM token，确定性）:")
        for s in hit:
            print("  - %-32s %-26s %s" % (s["id"], s["skill"], s["dataset"]))
    out = os.path.join("data", "results",
                       "autocallable_coverage%s.json" % ("_dry" if dry else ""))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"dry": dry, "routed": routed, "solved": solved}, fh,
                  ensure_ascii=False, indent=2)
    print("\n明细已写入 %s" % out)


if __name__ == "__main__":
    asyncio.run(main_async(dry="--dry" in sys.argv))
