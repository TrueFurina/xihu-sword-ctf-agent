"""全链路 dry-run：用 32 道正式赛真题跑 数据→presolve→LLM Agent→候选 flag。

用法:
    .venv/Scripts/python.exe scripts/_dryrun_race.py                    # 全部 32 题
    .venv/Scripts/python.exe scripts/_dryrun_race.py --ids 10732,10733  # 指定题号
    .venv/Scripts/python.exe scripts/_dryrun_race.py --presolve-only     # 仅确定性预扫
    .venv/Scripts/python.exe scripts/_dryrun_race.py --category crypto  # 按题型
    .venv/Scripts/python.exe scripts/_dryrun_race.py --timeout 120       # 每题超时秒

产出: data/results/dryrun_<timestamp>.json + 控制台报表
"""

from __future__ import annotations
import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
import traceback
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("dryrun")

# ── 题库分类映射（from category_regression.json）─────────────────────
# M1.1（2026-08-22 赛后重锐评）：索引由 scripts/_build_regression_index.py 重建，
# 合并 data/questions_real（真值）+ data/race_details（描述）。索引条目扩展字段：
#   qpath   → questions_real 的 JSON 绝对路径（Question 兼容，直接加载）
#   flag    → ground-truth flag（回归判分基准）
CAT_MAP = {}
INDEX = {}          # id -> 完整索引条目
FLAG_MAP = {}       # id -> ground-truth flag（questions_real 真值，回归判分）
_cat_path = _ROOT / "data" / "results" / "category_regression.json"
if _cat_path.exists():
    with open(_cat_path, encoding="utf-8") as _f:
        for _c in json.load(_f):
            _cid = str(_c["id"])
            CAT_MAP[_cid] = _c["category"]
            INDEX[_cid] = _c
            if _c.get("flag"):
                FLAG_MAP[_cid] = _c["flag"]


def load_race_challenge(cid: str) -> dict | None:
    """从 data/race_details/<id>.json 加载真题元数据。"""
    p = _ROOT / "data" / "race_details" / f"{cid}.json"
    if not p.exists():
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


_ARCHIVE_EXTS = (".zip", ".tar.gz", ".tgz", ".tar", ".7z", ".rar")
# 深层「单文件附件」扩展名（目录顶层无文件时递归查找，如 tempdir/MISC附件/logbool.pcapng）。
# 刻意不含 .txt/.py/.php/.js（源码目录里大量存在，命中会误把源码审计题当单文件题）
_ATT_FILE_EXTS = (".pcapng", ".pcap", ".cap", ".enc", ".bin", ".zip", ".tar.gz",
                  ".tgz", ".tar", ".7z", ".rar", ".pyc", ".elf", ".so", ".exe",
                  ".png", ".jpg", ".jpeg", ".pdf", ".img", ".dd", ".raw")


def _resolve_attachment_target(p: Path) -> str:
    """附件落盘可能是「目录」（下载 zip 被解压成以附件名命名的目录）。

    返回真实目标：目录内若含压缩包/单文件附件则返回它，否则返回目录本身
    （flag_scan / web_source_audit 支持递归扫目录）。
    修复（2026-08-22 M2 归因）：原实现直接返回目录路径，导致 file_analyze 用
    isfile() 判「文件不存在」、LLM 在 web 源码审计题上 180s 空转。
    """
    if not p.is_dir():
        return str(p)
    try:
        entries = sorted(p.iterdir(), key=lambda x: x.name)
    except OSError:
        return str(p)
    # 1) 顶层压缩包/归档（真附件本体）
    for f in entries:
        if f.is_file() and f.name.lower().endswith(_ARCHIVE_EXTS):
            return str(f)
    # 2) 顶层单文件附件（.enc/.bin/.pcapng 等，非源码）
    for f in entries:
        if f.is_file() and f.name.lower().endswith(_ATT_FILE_EXTS):
            return str(f)
    # 3) 顶层无附件文件（纯子目录）→ 递归找深层附件文件（tempdir/.../xxx.pcapng 等）
    try:
        for f in p.rglob("*"):
            if f.is_file() and f.name.lower().endswith(_ATT_FILE_EXTS):
                return str(f)
    except OSError:
        pass
    # 4) 纯源码目录（如 installer/）→ 返回目录本身，交给递归扫描
    return str(p)


def find_local_attachment(cid: str, att_name: str) -> str:
    """在 data/race_attachments/ 找到已下载的附件本地路径（目录则解析出真实文件）。"""
    att_dir = _ROOT / "data" / "race_attachments"
    if not att_dir.exists():
        return ""
    # 优先按 <id>_ 前缀匹配
    cands = [p for p in att_dir.iterdir() if p.name.startswith(f"{cid}_")]
    # 回退按名称匹配
    if not cands and att_name:
        cands = [p for p in att_dir.iterdir() if att_name in p.name]
    if not cands:
        return ""
    # 排除解压副本（_x / .fixed 后缀），优先原始条目
    primary = [p for p in cands if not p.name.endswith("_x") and ".fixed" not in p.name]
    target = (primary or cands)[0]
    return _resolve_attachment_target(target)


def race_to_question(cid: str) -> dict:
    """将真题元数据转为 Question 兼容 dict。

    questions_real 条目直接加载其 JSON（已是 Question 兼容格式，含真值 flag）；
    其余走 race_details 元数据组装。
    """
    entry = INDEX.get(cid) or {}
    qpath = entry.get("qpath")
    if qpath and Path(qpath).exists():
        try:
            with open(qpath, encoding="utf-8") as f:
                qd = json.load(f)
            qd["id"] = cid  # 确保 id 与索引一致
            return qd
        except Exception as e:  # noqa: BLE001
            logger.warning("questions_real 加载失败 %s: %s", qpath, e)
    raw = load_race_challenge(cid)
    if not raw or "data" not in raw:
        return {"id": cid, "error": "no race detail"}
    d = raw["data"]
    name = d.get("name", cid)
    desc = d.get("description", "")
    diff = d.get("difficulty", "MEDIUM")
    cat = CAT_MAP.get(cid, "misc")
    # 从 name 前缀提取题型（兜底）
    if name.startswith("CRYPTO"):
        cat = "crypto"
    elif name.startswith("MISC"):
        cat = "misc"
    elif name.startswith("PWN"):
        cat = "pwn"
    elif name.startswith("REVERSE"):
        cat = "reverse"
    elif name.startswith("WEB") or name.startswith("REAL") or name.startswith("Rank"):
        cat = "web"

    # 附件
    atts = []
    att_info = d.get("attachment")
    if att_info and isinstance(att_info, dict):
        att_name = att_info.get("name", "")
        local = find_local_attachment(cid, att_name)
        if local:
            atts.append(local)
    # endpoints（靶机，大概率已关，仅记录不直连）
    eps = d.get("endpoints") or []

    # flag pattern: DASCTF{} 是比赛标准格式
    flag_pat = r"DASCTF\{[^}]+\}" if "DASCTF" in desc else r"flag\{[^}]+\}"

    return {
        "id": cid,
        "title": name,
        "category": cat,
        "description": desc,
        "attachments": atts,
        "difficulty": diff.lower() if diff else "medium",
        "flag_pattern": flag_pat,
        "extra": {
            "score": d.get("score"),
            "difficulty": diff,
            "endpoints": eps,
            "has_solved": d.get("hasSolved"),
        },
    }


def verify_against_truth(cid: str, out: dict) -> dict:
    """回归判分：有真值的题必须与索引 flag 精确一致，否则视为未解出。

    防跨题误判（LLM 输出别的题的真值）——presolve/LLM 命中后统一过这道闸。
    """
    exp = FLAG_MAP.get(cid)
    if exp and out.get("flag"):
        if out["flag"] != exp:
            return {
                **out,
                "flag": None,
                "validated": False,
                "error": f"flag 与真值不符（预期 {exp[:24]}…）",
                "wrong_flag": out["flag"],
            }
        out["validated"] = True
    return out


async def run_presolve(qdict: dict, solver) -> dict:
    """确定性预扫（flag_scan/crypto_auto/math_engine/关键词 fast_solve）。"""
    from eval.cases import Question
    q = Question.from_dict(qdict)
    try:
        from core.presolve import presolve
        _reg = getattr(solver, "registry", None)
        _flag = await presolve(q, registry=_reg, sandbox=None, answers=None)
        if _flag:
            return {"flag": _flag, "method": "presolve", "validated": True}
        return {"flag": None, "method": "presolve_miss"}
    except Exception as e:
        return {"flag": None, "error": f"presolve: {e}"}


async def run_llm_agent(qdict: dict, solver, timeout: int) -> dict:
    """LLM Agent 全链路（presolve→LLM→tools→flag）。"""
    from eval.cases import Question
    q = Question.from_dict(qdict)
    try:
        out = await asyncio.wait_for(
            solver(q, attempt=0, correction=None),
            timeout=timeout,
        )
        flag = out.get("flag")
        validated = out.get("validated", False)
        method = "llm_agent"
        if not flag and out.get("error"):
            err = out["error"]
            method = f"llm_fail:{err.get('category', 'unknown')}"
        return {"flag": flag, "method": method, "validated": validated,
                "raw": {k: v for k, v in out.items() if k in ("flag", "validated", "error", "observation")}}
    except asyncio.TimeoutError:
        # M2（2026-08-22）：harness 级超时归入 wallclock_timeout，4 类失败分布可见
        return {"flag": None, "method": "llm_fail:wallclock_timeout",
                "error": f"timeout({timeout}s)"}
    except Exception as e:
        return {"flag": None, "error": f"agent: {e}"}


async def main():
    ap = argparse.ArgumentParser(description="真题 dry-run（47 题：questions_real 真值 + race_details）")
    ap.add_argument("--ids", default="", help="逗号分隔题号（空=全部）")
    ap.add_argument("--category", default="", help="只跑指定题型")
    ap.add_argument("--presolve-only", action="store_true", help="仅确定性预扫")
    ap.add_argument("--timeout", type=int, default=180, help="每题 LLM 超时秒")
    ap.add_argument("--max", type=int, default=0, help="最多跑 N 题（0=全部）")
    args = ap.parse_args()

    # 加载题号
    if args.ids:
        ids = [x.strip() for x in args.ids.split(",") if x.strip()]
    else:
        def _sort_key(x):
            try:
                return (0, int(x))
            except ValueError:
                return (1, x)
        ids = sorted(CAT_MAP.keys(), key=_sort_key)
    if args.category:
        ids = [i for i in ids if CAT_MAP.get(i) == args.category]
    if args.max > 0:
        ids = ids[:args.max]

    logger.info("待测题号: %s（共 %d）", ids, len(ids))

    # 构建 questions
    questions = []
    for cid in ids:
        q = race_to_question(cid)
        if "error" in q:
            logger.warning("跳过 %s: %s", cid, q["error"])
            continue
        questions.append((cid, q))
    logger.info("有效题目: %d", len(questions))

    # 构建 solver（真实 LLM）
    # M1.2（2026-08-22）：显式传 is_correct=索引真值表 —— 不用本地题库 answers
    # （教学题 flag 会误判真题）。validate_locally=False + is_correct 显式给定，
    # 正确性最终以 verify_against_truth 的逐题精确比对为准。
    from run import build_solver

    _truth = set(FLAG_MAP.values())
    solver = build_solver(
        use_mock=False,
        validate_locally=False,
        is_correct=(lambda f: f in _truth) if _truth else None,
    )
    logger.info("Solver 就绪: provider=%s, 真值表=%d 条",
                os.environ.get("CTF_AGENT_LLM_PROVIDER", "?"), len(_truth))

    # ── Phase 1: 全量 presolve ──
    logger.info("=== Phase 1: 确定性预扫（全 %d 题）===", len(questions))
    results = {}
    for cid, q in questions:
        t0 = time.time()
        out = await run_presolve(q, solver)
        out = verify_against_truth(cid, out)
        dt = time.time() - t0
        results[cid] = {**out, "category": q["category"], "name": q["title"],
                         "diff": q["difficulty"], "atts": q["attachments"],
                         "time_s": round(dt, 2)}
        flag = out.get("flag")
        status = f"✓ {flag[:40]}" if flag else f"✗ {out.get('method', out.get('error', ''))}"
        logger.info("[%s] %s %s (%.1fs) %s", cid, q["title"][:20], q["category"], dt, status)

    solved_presolve = sum(1 for r in results.values() if r.get("flag"))
    logger.info("Phase 1 完成: %d/%d 命中", solved_presolve, len(questions))

    # ── Phase 2: LLM Agent（仅 presolve 未命中 & 非 presolve-only）──
    if not args.presolve_only:
        unsolved = [(cid, q) for cid, q in questions if not results.get(cid, {}).get("flag")]
        logger.info("=== Phase 2: LLM Agent（%d 题未解）===", len(unsolved))
        for cid, q in unsolved:
            t0 = time.time()
            out = await run_llm_agent(q, solver, args.timeout)
            out = verify_against_truth(cid, out)
            dt = time.time() - t0
            results[cid].update({**out, "llm_time_s": round(dt, 2)})
            flag = out.get("flag")
            status = f"✓ {flag[:40]}" if flag else f"✗ {out.get('method', out.get('error', ''))}"
            logger.info("[%s] %s %s LLM (%.1fs) %s", cid, q["title"][:20], q["category"], dt, status)

    # ── 报表 ──
    total = len(questions)
    solved = sum(1 for r in results.values() if r.get("flag"))
    # M1.2：可验证题（有真值）的判分 + 4 类失败分布
    ver_total = sum(1 for cid in results if cid in FLAG_MAP)
    ver_solved = sum(1 for cid, r in results.items()
                     if cid in FLAG_MAP and r.get("flag") == FLAG_MAP[cid])
    CLASS4 = {
        "wrong_direction": "决策错", "stuck_loop": "决策错",
        "tool_failure": "工具调用错",
        "wallclock_timeout": "超时",
        "extract_fail": "提取错", "hallucination": "提取错",
        "budget_exceeded": "other",
    }
    fail_class: dict[str, int] = {}
    for cid, r in results.items():
        if r.get("flag"):
            continue
        # error 与 method 都参与匹配（error="timeout(320s)" 时 method=llm_fail:wallclock_timeout 仍可归类）
        err = str(r.get("error") or "") + " " + str(r.get("method") or "")
        m = re.search(r"(wallclock_timeout|tool_failure|wrong_direction|"
                      r"extract_fail|stuck_loop|hallucination|budget_exceeded)", err)
        cat = m.group(1) if m else None
        cls = CLASS4.get(cat or "", "other")
        fail_class[cls] = fail_class.get(cls, 0) + 1
    by_cat = {}
    for cid, r in results.items():
        cat = r.get("category", "?")
        by_cat.setdefault(cat, {"total": 0, "solved": 0})
        by_cat[cat]["total"] += 1
        if r.get("flag"):
            by_cat[cat]["solved"] += 1

    print("\n" + "=" * 70)
    print(f"真题 Dry-Run 报表（共 {total} 题，可验证 {ver_total} 题）")
    print(f"  raw 命中: {solved}/{total} = {solved / total:.1%}")
    if ver_total:
        print(f"  真值判分: {ver_solved}/{ver_total} = {ver_solved / ver_total:.1%}（回归主指标）")
    if fail_class:
        print(f"  失败分布: " + ", ".join(f"{k}={v}" for k, v in sorted(fail_class.items())))
    print(f"  按题型:")
    for cat, st in sorted(by_cat.items()):
        print(f"    {cat:8s} {st['solved']}/{st['total']}")
    print(f"\n  明细:")
    for cid, r in sorted(results.items()):
        flag = r.get("flag")
        cat = r.get("category", "?")
        name = r.get("name", cid)
        method = r.get("method", r.get("error", ""))
        atts = r.get("atts", [])
        att_info = f"[{len(atts)} atts]" if atts else "[no atts]"
        if flag:
            print(f"    ✓ {cid:6s} {cat:8s} {name:20s} {att_info:10s} {flag[:50]}")
        else:
            print(f"    ✗ {cid:6s} {cat:8s} {name:20s} {att_info:10s} {method}")
    print("=" * 70)

    # 保存结果
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = _ROOT / "data" / "results" / f"dryrun_{ts}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    logger.info("结果已保存: %s", out_path)

    return solved


if __name__ == "__main__":
    asyncio.run(main())
