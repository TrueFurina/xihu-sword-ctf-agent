# -*- coding: utf-8 -*-
"""A 类白名单扩面实验：路径/文本类 skill 能否真正兑现解题（零 LLM 成本）。

纪律（防止「会调用」冒充「有能力」）：
  * 只把**端到端解出 flag 且 sha256 与题库真值逐字匹配**的记为真解；
  * 解出 flag 但与真值不符 = **假阳性**（比不解更危险，必须单列统计）；
  * 同时记录耗时——慢到会撞墙钟的，即使能解也要慎入生产路径。

用法：python scripts/_probe_expand_autocallable.py
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.cases import load_questions  # noqa: E402
from tools.skill_manager import SkillManager  # noqa: E402
from tools.registry import ToolRegistry  # noqa: E402
from tools.skill_dispatch import extract_flag, iter_candidate_params  # noqa: E402

# 实验组：AST 扫描确认接受 path/text 的白名单外 skill（第一组：通用编码/压缩类，
# 实测结论见 reports——50% 假阳 + 其余零收益，故**未**扩面）
_DEFAULT_CANDIDATES = [
    "base64_multilayer", "caesar_bruteforce", "morse_decoder",
    "pyc_decompile", "vigenere_decode", "zip_chain_decode",
]
# 第二组：专题 solver（路由命中数较少但更可能有真解）
_SPECIALIST_CANDIDATES = [
    "rsa_fermat_factor", "crypto_high_exponent", "crypto_complex_mult_group",
    "crypto_ecb_block_attack", "crypto_coppersmith", "crypto_keyboard_path",
    "hash_crack", "misc_traffic_analysis", "misc_disk_forensics",
    "task_analyzer",
]
CANDIDATES = set(os.environ.get(
    "CTF_EXPAND_SKILLS",
    "").replace(",", " ").split()) or set(_DEFAULT_CANDIDATES)
DRY_JSON = os.path.join("data", "results", "autocallable_coverage_dry.json")
TIMEOUT = 60


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _load_all():
    out, seen = [], set()
    for d in ("data/questions", "data/questions_real",
              "data/questions_external"):
        try:
            qs = load_questions(d)
        except Exception:  # noqa: BLE001
            continue
        for q in qs or []:
            k = getattr(q, "id", None)
            if k in seen:
                continue
            seen.add(k)
            out.append(q)
    return {getattr(q, "id", ""): q for q in out}


def iter_manual_candidates(q):
    """不依赖白名单，按 A 类同构方式给每个附件构造 {"path","text"}。

    ⚠️ 首版实验脚本直接调 iter_candidate_params()，但候选 skill **尚未进**
    _PATH_SKILLS → 该函数立即 return 空 → 38 题全部"未解"是**假结论**
    （链路根本没通，测的是空气）。必须在这里独立构造候选才是公平实验。
    """
    atts = getattr(q, "attachments", None) or []
    if isinstance(atts, str):
        atts = [atts]
    for a in atts:
        p = str(a)
        if not os.path.isfile(p):
            continue
        params = {"path": p}
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                params["text"] = fh.read()
        except OSError:
            pass
        yield params


async def run(sm, registry, skill, q):
    try:
        sm.load(skill)
    except Exception:  # noqa: BLE001
        return None, "load_failed", 0.0
    if not registry.get(skill):
        return None, "not_registered", 0.0
    for params in iter_manual_candidates(q):
        t0 = time.time()
        try:
            out = await asyncio.wait_for(registry.run(skill, params),
                                         timeout=TIMEOUT)
        except asyncio.TimeoutError:
            return None, "timeout", time.time() - t0
        except Exception as e:  # noqa: BLE001
            continue
        f = extract_flag(out)
        if f:
            return f, "", time.time() - t0
    return None, "no_flag", 0.0


async def main():
    with open(DRY_JSON, encoding="utf-8") as fh:
        dry = json.load(fh)
    corpus = _load_all()
    pairs = [(qid, skill) for qid, skill, _ds in dry["routed"]
             if skill in CANDIDATES]
    print("待实验题数: %d（涉及 skill: %s）\n" %
          (len(pairs), sorted({s for _q, s in pairs})))

    registry = ToolRegistry()
    sm = SkillManager(registry=registry)
    try:
        sm.discover()
    except Exception:  # noqa: BLE001
        pass

    stats = defaultdict(Counter)
    detail = defaultdict(list)
    for qid, skill in pairs:
        q = corpus.get(qid)
        if q is None:
            continue
        flag, err, dt = await run(sm, registry, skill, q)
        truth = getattr(q, "flag_sha256", None)
        if flag and truth and _sha(flag) == truth:
            stats[skill]["match"] += 1
            detail[skill].append((qid, "MATCH", round(dt, 1)))
            print("  ✅ %-30s %-22s %ss" % (qid, skill, round(dt, 1)))
        elif flag:
            stats[skill]["false_positive"] += 1
            detail[skill].append((qid, "FALSE_POSITIVE:" + flag[:40],
                                  round(dt, 1)))
            print("  ⚠️  %-30s %-22s 解出但与真值不符: %s"
                  % (qid, skill, flag[:40]))
        else:
            stats[skill][err or "unsolved"] += 1
            detail[skill].append((qid, err or "unsolved", round(dt, 1)))

    print("\n" + "=" * 78)
    print("%-24s %6s %6s %6s %6s" % ("skill", "match", "假阳", "未解", "合计"))
    print("-" * 78)
    tm = tfp = 0
    for s in sorted(stats):
        c = stats[s]
        m = c["match"]
        fp = c["false_positive"]
        un = sum(v for k, v in c.items() if k not in ("match", "false_positive"))
        tm += m
        tfp += fp
        print("%-24s %6d %6d %6d %6d" % (s, m, fp, un, sum(c.values())))
    print("-" * 78)
    print("%-24s %6d %6d" % ("合计", tm, tfp))
    out = os.path.join("data", "results", "expand_autocallable_probe.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({k: v for k, v in detail.items()}, fh,
                  ensure_ascii=False, indent=2)
    print("\n明细: %s" % out)


if __name__ == "__main__":
    asyncio.run(main())
