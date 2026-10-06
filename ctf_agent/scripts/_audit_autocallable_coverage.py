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

from eval.cases import load_questions  # noqa: E402
from core.prompts import infer_skill_require  # noqa: E402
from tools.skill_manager import SkillManager  # noqa: E402
from tools.registry import ToolRegistry  # noqa: E402
from tools.skill_dispatch import (  # noqa: E402
    AUTO_CALLABLE, extract_flag, iter_candidate_params,
)

DATASETS = ("data/questions", "data/questions_real", "data/questions_external")
PER_CALL_TIMEOUT = 180  # 单题单 skill 调用上限（秒）


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _att_score(q):
    """副本质量分：附件是否真实可用。

    ⚠️ 实测发现（2026-10-07）：题库存在 **id 重复但质量不齐** 的副本——
    data/questions 里的 real_crypto_ezrsa 等指向已失效的绝对路径
    （E:/Program/Cybersecurity/比赛真题/...，全部 exists=0），
    而 data/questions_real 里同 id 的副本附件完整可用。
    按 id 先到先得去重会选中**坏副本**，制造「能力未兑现」的假象。
    故去重时必须挑附件真实存在的那个。
    """
    atts = getattr(q, "attachments", None) or []
    if not atts:
        return (-1, 0)
    if isinstance(atts, str):
        atts = [atts]
    ok = sum(1 for a in atts if os.path.isfile(str(a)))
    return (1 if ok == len(atts) else 0, ok)


def load_all():
    """跨数据集按 id 去重，**优先保留附件真实存在的副本**。"""
    best = {}
    for d in DATASETS:
        try:
            qs = load_questions(d)
        except Exception as e:  # noqa: BLE001
            print("[skip] %s: %s" % (d, e))
            continue
        for q in qs or []:
            k = getattr(q, "id", None) or getattr(q, "title", None)
            if k not in best or _att_score(q) > _att_score(best[k][1]):
                best[k] = (d, q)
    dupes = sum(1 for _k, _v in best.items())
    print("去重后题数: %d" % dupes)
    return list(best.values())


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
