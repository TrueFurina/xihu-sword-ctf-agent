"""诚实解题能力基准（战役B）：LLM 真推理 + 工具编排，禁用 presolve 读答案，且运行时剔除答案文件。

与 _llm_breaking_ice.py 的区别（更诚实）：
  - 运行时从 question.attachments 剔除 flag.txt/answer.txt/solution.txt，
    确保 LLM 拿不到答案密钥，测的是"真推理+工具"而非"读答案"。
  - 正确性仍由 flag_sha256 独立校验（不依赖答案文件）。
  - 自动按类别均衡抽样，输出每类真实解出率，直接回答"解题能力几何"。

用法：
    python scripts/_honest_bench.py --provider deepseek --per-category 3 --timeout 200
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import run as run_mod  # noqa: E402
from eval.cases import load_questions  # noqa: E402

ANSWER_NAMES = {"flag.txt", "answer.txt", "solution.txt", "flag", "flag"}

_CIPHER_HINT = re.compile(r"(0x[0-9a-f]{6,}|[A-Za-z0-9+/]{24,}={0,2}|base64|n\
=|\benc\b|\bcipher|\bct\b|\bpubkey|\bmodulus|\be\b=|\bc\b=)", re.I)

# 宽松 flag 形态（用于内容级答案检测）：prefix{...}
_FLAG_SHAPE = re.compile(r"([A-Za-z0-9_]{0,20}\{[^}\n]{4,}\})")


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _desc_leaks_flag(q) -> bool:
    """题面级答案检测：description 含真值 flag → D 类题面泄露，不可测。

    2026-09-01 补强（四层过滤）：real_crypto_anxun2020_aes 附件=flag.txt 被
    名字级剔除后，description 明文仍写有真值 flag，LLM 抄题面答案入账
    （9/22 中 1 个假解，修正为 8/21）。判据与 _is_answer_text 一致：
      1) flag 字段明文出现在 description；
      2) description 中 flag{...} 形态候选 sha256 命中 flag_sha256。
    """
    desc = getattr(q, "description", None)
    if not desc or not isinstance(desc, str):
        return False
    plain = getattr(q, "flag", None)
    fs = getattr(q, "flag_sha256", None)
    if plain and isinstance(plain, str) and not re.fullmatch(r"[0-9a-fA-F]{64}", plain):
        if plain.strip() in desc:
            return True
    if fs:
        for m in _FLAG_SHAPE.finditer(desc):
            cand = m.group(1)
            if _sha256(cand) == fs or _sha256(cand.strip("flag{}")) == fs:
                return True
    return False


def _is_answer_text(p: str, q) -> bool:
    """内容级答案检测：附件文本含真值 flag（writeup/重建笔记）→ 视为答案文件。

    判据（比名字黑名单更诚实，覆盖 BeCare4.md 类『输入即答案』）：
      1) flag 字段为明文且出现在内容中；
      2) 内容中提取 flag{...} 形态候选，sha256 命中 flag_sha256。
    密文材料（键盘坐标/培根/hex 串）不含 flag 明文真值 → 不误伤。
    """
    try:
        if os.path.getsize(p) > 128 * 1024:
            return False
        with open(p, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except Exception:
        return False
    plain = getattr(q, "flag", None)
    fs = getattr(q, "flag_sha256", None)
    if plain and isinstance(plain, str) and not re.fullmatch(r"[0-9a-fA-F]{64}", plain):
        if plain.strip() in content:
            return True
    if fs:
        for m in _FLAG_SHAPE.finditer(content):
            cand = m.group(1)
            if _sha256(cand) == fs or _sha256(cand.strip("flag{}")) == fs:
                return True
    return False


def _att_path(a):
    if isinstance(a, str):
        return a
    return a.get("path") or a.get("name") or a.get("filename") or ""


def _att_name(a):
    if isinstance(a, str):
        return a.split("/")[-1].split("\\")[-1]
    return (a.get("name") or a.get("filename") or "").split("/")[-1].split("\\")[-1]


def _strip_answer(atts):
    return [a for a in (atts or []) if _att_name(a).lower() not in ANSWER_NAMES]


def _real_attachments(q):
    """真输入附件：剔除答案文件（名字级）+ 答案文本（内容级）+ 悬空引用（路径级）。"""
    atts = getattr(q, "attachments", None) or []
    rem = []
    for a in atts:
        name = _att_name(a)
        if name.lower() in ANSWER_NAMES:
            continue
        p = _att_path(a)
        # 附件路径相对 ctf_agent/（_ROOT）解析，如 data/questions_real/_attachments/...
        ap = os.path.abspath(os.path.join(_ROOT, p)) if p else ""
        if not ap or not os.path.exists(ap):
            continue  # 悬空引用，不可测
        if _is_answer_text(ap, q):
            continue  # 输入即答案
        rem.append(a)
    return rem


def _has_real_input(q):
    """剔除答案后是否还有可推理的真实输入。

    三级排除（2026-09-01 补强，测的才是真能力）：
      - 名字级：flag.txt/answer.txt/solution.txt（答案密钥）
      - 内容级：附件文本含真值 flag（writeup/重建笔记，如 BeCare4.md）
      - 路径级：附件文件不存在（悬空引用，归档消失遗留）
      - 题面级：description 含真值 flag（D 类题面泄露，如 anxun2020_aes）
    剩余附件 → 真输入；无附件时退化到 description 密文特征判断。
    """
    if _desc_leaks_flag(q):
        return False  # 题面已泄露答案，抄题面=注水，不可测
    if _real_attachments(q):
        return True
    desc = getattr(q, "description", "") or ""
    return bool(_CIPHER_HINT.search(desc)) and len(desc) >= 40


def _validate(flag, q):
    if not flag:
        return False
    fs = getattr(q, "flag_sha256", None)
    plain = getattr(q, "flag", None)
    cands = {flag, flag.strip(), flag.strip().strip("flag{}")}
    if fs:
        for cand in cands:
            if _sha256(cand) == fs:
                return True
    else:
        # 无 flag_sha256 的题（如 real_anxun2020_BeCare4 等重建题）：明文 fallback
        for cand in cands:
            if plain and cand == plain:
                return True
    return False


async def _solve_one(q, provider, per_timeout, no_presolve):
    # D 类题面泄露（description 含真值 flag）：即使 _main 筛选已排除，
    # 单题直跑仍会把题面答案喂给 LLM → 抄答案=注水，直接跳过不可测
    if _desc_leaks_flag(q):
        return {"status": "LEAK_SKIP", "seconds": 0.0,
                "reason": "D 类题面泄露（description 含真值 flag），不可测"}
    orig = getattr(q, "attachments", None)
    # 运行时只保留真输入附件（名字级+内容级+路径级过滤，不改源码/数据集，仅诚实测量）
    try:
        q.attachments = _real_attachments(q)
        if no_presolve:
            import core.presolve as _ps
            # 必须替换为 async 协程（main_agent 里 await presolve(...)），
            # 同步 lambda 返回 None → await None 抛 TypeError（2026-09-01 修）
            async def _no_presolve(*a, **k):  # noqa: E731
                return None
            _ps.presolve = _no_presolve
            import core.main_agent as _ma
            if hasattr(_ma, "presolve"):
                _ma.presolve = _no_presolve
        solver = run_mod.build_solver(use_mock=False, provider=provider,
                                      validate_locally=False, skip_presolve=True)
        t0 = time.time()
        try:
            out = await asyncio.wait_for(solver(q, 0, None), timeout=per_timeout)
        except asyncio.TimeoutError:
            return {"status": "TIMEOUT", "seconds": round(time.time() - t0, 1)}
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "error": repr(e)[:200], "seconds": round(time.time() - t0, 1)}
        flag = out.get("flag")
        ok = _validate(flag, q)
        return {
            "status": "SOLVED" if ok else "UNSOLVED",
            "flag_found": flag,
            "sha256_ok": ok,
            "solved_by": out.get("solved_by"),
            "provider": out.get("provider"),
            "seconds": round(time.time() - t0, 1),
        }
    finally:
        q.attachments = orig


async def _main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--per-category", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=200)
    ap.add_argument("--seed", type=int, default=20260901)
    ap.add_argument("--no-internal-presolve", action="store_true", default=True)
    args = ap.parse_args()

    import random
    rnd = random.Random(args.seed)
    questions = load_questions("data/questions_real")
    by_cat = {}
    for q in questions:
        if not _has_real_input(q):
            continue
        by_cat.setdefault(getattr(q, "category", "?"), []).append(q)

    plan = []
    for cat, qs in by_cat.items():
        rnd.shuffle(qs)
        for q in qs[: args.per_category]:
            plan.append(q)

    print(f"[*] honest bench: {len(plan)} problems (real-input only), provider={args.provider}", flush=True)
    results = []
    for q in plan:
        rec = await _solve_one(q, args.provider, args.timeout, args.no_internal_presolve)
        rec["qid"] = q.id
        rec["category"] = getattr(q, "category", "?")
        rec["difficulty"] = getattr(q, "difficulty", "?")
        results.append(rec)
        print(f"    {q.id:32s} {rec['status']:8s} by={rec.get('solved_by')} "
              f"sec={rec.get('seconds')}", flush=True)

    from collections import Counter, defaultdict
    cats = defaultdict(lambda: [0, 0])
    for r in results:
        if r["status"] == "SOLVED":
            cats[r["category"]][0] += 1
        cats[r["category"]][1] += 1
    solved = sum(1 for r in results if r["status"] == "SOLVED")
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_path = os.path.join(_ROOT, "deliverables", f"honest_bench_{ts}.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    summary = {
        "provider": args.provider,
        "mode": "LLM-only+strip-answer",
        "total_real_input": len(results),
        "solved": solved,
        "by_category": {c: {"solved": v[0], "total": v[1]} for c, v in cats.items()},
        "results": results,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n=== HONEST BENCH: {solved}/{len(results)} SOLVED (real-input only) ===")
    for c, v in cats.items():
        print(f"    {c:10s} {v[0]}/{v[1]}")
    print(f"report -> {out_path}")


if __name__ == "__main__":
    asyncio.run(_main())
