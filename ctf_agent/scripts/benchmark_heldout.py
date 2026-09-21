#!/usr/bin/env python3
"""
Held-out 未见题自主解题基准（续评-20260917 P0）。

为什么存在
----------
严格 KPI=14 是「确定性复现 14 道已知 writeup」，LLM 真推理对 14 贡献 = 0。
竞技要的是**未见题上的自主推理**，而现有 benchmark 全在已见题上跑。
本脚本构造一个「未见 + 非平凡」题池，强制走主 Agent 全链路（--presolve-skip），
量出真正的自主解题水位，作为明年复赛的唯一竞技 KPI。

选题规则（接手以磁盘为准，机器真值）
------------------------------------
从 data/questions_real/ 递归抓题，逐题判定：
  - 在 _antifraud.AUTHORIZED_KPI_SOLVES（14 个已训练/已写 bespoke solver）→ 排除（已见）
  - 附件含 flag.txt（读泄露答案型，非能力）→ 排除（数据集已知"答案密钥泄露"）
  - answer_disclosed=True（教学题自带明文 flag）→ 排除（load_questions 护栏一致）
  - provenance/source 含 self_authored_training（自产训练题）→ 排除（非真题）
  - WRITEUP 重建题（附件路径含 recovered_external/wp_text，或描述含 reconstruct/官方wp/
    官方题解/writeup 等）→ 排除（题面由官方 wp 反推、flag 明文在 wp_text 附件，读附件=看答案，
    非自主推理能力，且污染 held-out 分母）
剩余 = 真·未见·非平凡候选池。

运行
----
  python scripts/benchmark_heldout.py --select            # 仅选题干，写 manifest
  python scripts/benchmark_heldout.py --run --mock        # 冒烟：mock 验证流水线
  python scripts/benchmark_heldout.py --run --provider baidu --wallclock 300   # 真自主推理

真跑需要 baidu 凭证可达；结果落 data/results/heldout/。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# 让 `python scripts/benchmark_heldout.py` 也能 import scripts 包下的模块
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
RESULTS = ROOT / "data" / "results"
QUESTIONS_REAL = ROOT / "data" / "questions_real"
MANIFEST = RESULTS / "heldout_candidates.json"
RUN_DIR = RESULTS / "heldout_run"
OUT_DIR = RESULTS / "heldout"
BLACKBOARD = RESULTS / "blackboard.json"

LEAK_MARKERS = ("flag.txt",)
SELF_AUTHORED_MARKERS = ("self_authored_training", "self-authored", "training")


def _is_leaked_attachment(q: dict) -> bool:
    for a in (q.get("attachments") or []):
        s = str(a).lower()
        if any(m in s for m in LEAK_MARKERS):
            return True
    return False


def _has_plaintext_flag_in_question(q: dict) -> bool:
    """题面 JSON 自身含真实明文 flag（非 sha256 占位）→ 答案已泄露，违反 2026-08-24 红线。

    注意：flag 字段常见为 64 位 hex 的 sha256 占位（合法校验锚），不得误判为泄漏。
    仅当 flag 字段是非占位的真实 flag 串，或 answer/solution 字段含明文 flag 时，才算泄漏。
    """
    flagre = re.compile(r"flag\{|dasctf\{|ctf\{|xctf\{|d0g3\{|d0gz\{", re.I)
    try:
        from eval.cases import Question
        qq = Question.from_dict(q)
        if (qq.flag is not None and not qq.flag_is_placeholder
                and isinstance(qq.flag, str) and flagre.search(qq.flag)):
            return True
    except Exception:
        # 兜底：flag 字段非 64 位 hex 占位且含 flag 串 → 视为明文泄漏
        f = q.get("flag")
        if isinstance(f, str) and f.strip() and not re.fullmatch(r"[0-9a-fA-F]{64}", f.strip()) \
                and flagre.search(f):
            return True
    for k in ("answer", "solution", "expected_flag"):
        v = q.get(k)
        if isinstance(v, str) and flagre.search(v):
            return True
    return False


_FLAG_RE = re.compile(r"flag\{|dasctf\{|ctf\{|xctf\{|d0g3\{|d0gz\{", re.I)


def _is_real_flag_string(s) -> bool:
    """非 sha256 占位、且含 flag 特征串 → 真实明文 flag（待脱敏）。"""
    return (isinstance(s, str) and s.strip()
            and not re.fullmatch(r"[0-9a-fA-F]{64}", s.strip())
            and bool(_FLAG_RE.search(s)))


def _neutralize(q: dict) -> dict:
    """脱敏：隐藏题面里可直接读到的答案，让 agent 无法「看答案」。

    - 去掉 attachments 里的 flag.txt（且 build_run_dir 不复制该文件）
    - 把 flag/answer/solution 里的真实明文 flag 置空；若缺 flag_sha256 则用明文算一个补上
      （保证校验仍可做，而 agent 读不到答案）
    """
    q = json.loads(json.dumps(q, ensure_ascii=False))
    atts = q.get("attachments") or []
    filtered = [a for a in atts if "flag.txt" not in str(a).lower()]
    # 关键：若剔除 flag.txt 后为空，presolve._attachments 会兜底回读原始题面 json
    # （questions_real/{cat}/{id}.json）并把 flag.txt 重新补回来 → 脱敏失效。
    # 故填一个不存在的哨兵路径，令 attachments 非空、兜底不触发、读取无害失败。
    if atts and not filtered:
        filtered = ["__neutralized_no_real_attachment__"]
    q["attachments"] = filtered
    for k in ("flag", "answer", "solution", "expected_flag"):
        v = q.get(k)
        if _is_real_flag_string(v):
            if not q.get("flag_sha256"):
                q["flag_sha256"] = hashlib.sha256(v.strip().encode("utf-8")).hexdigest().lower()
            q[k] = ""
    return q


def _is_self_authored(q: dict) -> bool:
    blob = " ".join(str(q.get(k, "")) for k in ("provenance", "source", "description"))
    return any(m in blob.lower() for m in SELF_AUTHORED_MARKERS)


# WRITEUP 重建题：题面由官方 writeup 反推、flag 明文藏在 wp_text 附件里。
# 读附件=看答案，不是自主推理能力；且 flag 在附件而非题面，现有 leaked-attachment 只拦
# flag.txt，漏掉 wp_text。这类题污染 held-out 分母（10→应为 3 道真·未见题）。
WP_ATTACHMENT_MARKERS = ("recovered_external/wp_text",)
WP_TEXT_MARKERS = ("reconstructed from", "reconstruct from", "官方wp", "官方题解",
                   "official writeup", "from official writeup", "flag from official",
                   "writeup")


def _is_writeup_reconstructed(q: dict) -> bool:
    """判定 WRITEUP 重建题（非真·未见题，答案在 wp_text 附件里）。

    判定信号（任一命中即排除）：
      - 附件路径含 recovered_external/wp_text（ definitive：7 道 WRITEUP 题统一特征）
      - description/source/notes/provenance 含重建关键词（reconstructed / 官方wp /
        官方题解 / official writeup / flag from official / writeup 等）
    3 道真·未见题（dnui_keyboard / real_reverse_js / gongye_web2）附件在
    data/questions_real/_attachments/，描述为真挑战文本，不会被误伤。
    """
    for a in (q.get("attachments") or []):
        s = str(a).lower()
        if any(m in s for m in WP_ATTACHMENT_MARKERS):
            return True
    blob = " ".join(str(q.get(k, "")) for k in
                    ("description", "source", "notes", "provenance"))
    blob_low = blob.lower()
    return any(m in blob_low for m in WP_TEXT_MARKERS)


def select_candidates(require_sha256: bool = True,
                      include_neutralized: bool = False) -> tuple[list[dict], list[dict]]:
    """返回 (候选池, 全部记录含排除原因)。

    include_neutralized=True 时：不再排除「答案泄露」题（flag.txt 附件 / 题面明文 flag），
    而是在建 run 目录时脱敏（隐藏答案），让 agent 无法「看答案」却被正常评测——
    对应指令「答案泄露可以不看答案」。trained/self_authored/answer_disclosed 仍排除。
    """
    # 机器真值：14 个已训练题（KPI 口径）
    try:
        import scripts._antifraud as af  # type: ignore
        trained = set(getattr(af, "AUTHORIZED_KPI_SOLVES", frozenset()))
    except Exception:
        trained = frozenset()

    all_recs: list[dict] = []
    seen_ids = set()
    for jf in sorted(QUESTIONS_REAL.rglob("*.json")):
        try:
            with open(jf, "r", encoding="utf-8") as fh:
                q = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
        qid = q.get("id") or jf.stem
        if qid in seen_ids:
            continue
        seen_ids.add(qid)
        has_plain = _has_plaintext_flag_in_question(q)
        # 脱敏模式下：明文 flag 可合成 sha256 校验锚 → 仍可校验
        validatable = bool(q.get("flag_sha256")) or (include_neutralized and has_plain)
        reason_excluded = None
        if qid in trained:
            reason_excluded = "trained(KPI)"
        elif q.get("answer_disclosed"):
            reason_excluded = "answer_disclosed"
        elif _is_self_authored(q):
            reason_excluded = "self_authored_training"
        elif _is_writeup_reconstructed(q):
            reason_excluded = "writeup-reconstructed(non-genuine)"
        elif not include_neutralized and _is_leaked_attachment(q):
            reason_excluded = "leaked-attachment(flag.txt)"
        elif not include_neutralized and has_plain:
            reason_excluded = "plaintext-flag-in-question"
        elif require_sha256 and not validatable:
            reason_excluded = "no-flag_sha256(unvalidatable)"
        rec = {
            "id": qid,
            "path": str(jf.relative_to(ROOT)),
            "category": q.get("category"),
            "has_flag_sha256": bool(q.get("flag_sha256")),
            "has_plaintext_flag": has_plain,
            "leaked_attachment": _is_leaked_attachment(q),
            "excluded": reason_excluded,
        }
        all_recs.append(rec)
    cands = [r for r in all_recs if r["excluded"] is None]
    return cands, all_recs


def write_manifest(cands: list[dict], all_recs: list[dict], require_sha256: bool,
                   include_neutralized: bool = False) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    from collections import Counter
    breakdown = Counter(r["excluded"] or "INCLUDED" for r in all_recs)
    if include_neutralized:
        criteria = ("unseen(NOT in AUTHORIZED_KPI_SOLVES) AND NOT answer_disclosed "
                    "AND NOT self_authored_training；泄露题纳入但**运行时脱敏**"
                    "（隐藏 flag.txt/明文答案，agent 读不到答案）"
                    + ("；has flag_sha256 或可合成(validatable)" if require_sha256 else ""))
    else:
        criteria = ("unseen(NOT in AUTHORIZED_KPI_SOLVES) AND NOT leaked-attachment(flag.txt) "
                    "AND NOT plaintext-flag-in-question AND NOT answer_disclosed "
                    "AND NOT self_authored_training AND NOT writeup-reconstructed(non-genuine)"
                    + (" AND has flag_sha256(validatable)" if require_sha256 else ""))
    payload = {
        "generated_by": "scripts/benchmark_heldout.py",
        "source_dir": str(QUESTIONS_REAL),
        "include_neutralized": include_neutralized,
        "criteria": criteria,
        "candidate_count": len(cands),
        "exclusion_breakdown": dict(breakdown),
        "candidates": cands,
    }
    MANIFEST.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def build_run_dir(cands: list[dict], neutralize_leaks: bool = False) -> Path:
    if RUN_DIR.exists():
        shutil.rmtree(RUN_DIR)
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    ok = 0
    neutralized = 0
    for c in cands:
        src = ROOT / c["path"]
        if not src.exists():
            continue
        try:
            q = json.loads(src.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if neutralize_leaks:
            before = json.dumps(q, ensure_ascii=False)
            q = _neutralize(q)
            if json.dumps(q, ensure_ascii=False) != before:
                neutralized += 1
        (RUN_DIR / f"{c['id']}.json").write_text(
            json.dumps(q, ensure_ascii=False, indent=1), encoding="utf-8")
        ok += 1
    tag = f"（其中 {neutralized} 道已脱敏：隐藏 flag.txt/明文答案）" if neutralize_leaks else ""
    print(f"[heldout] 复制 {ok} 道候选题到 {RUN_DIR}{tag}")
    return RUN_DIR


def _backup_and_clear_blackboard() -> Path | None:
    """冷启动事实黑板：备份跨会话 flag 缓存，清空后跑，避免 held-out 题被旧缓存命中。

    返回备份路径；若原本无黑板文件则返回 None（无需恢复）。
    """
    backup = RESULTS / f"blackboard.heldout_bak_{datetime.now():%Y%m%d_%H%M%S}.json"
    if BLACKBOARD.exists():
        shutil.copy(BLACKBOARD, backup)
        print(f"[heldout] 备份黑板 -> {backup.name}（{BLACKBOARD.stat().st_size} bytes）")
    # 清空：仅置空，不删文件（保留 known_failures 结构，运行后恢复备份）
    BLACKBOARD.write_text(
        json.dumps({"presolve_cache": {}, "known_failures": {}}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    print(f"[heldout] 黑板已冷启动（presolve_cache 清空，杜绝跨会话 flag 泄漏）")
    return backup


def _restore_blackboard(backup: Path | None) -> None:
    if backup is None:
        return
    if backup.exists():
        shutil.copy(backup, BLACKBOARD)
        print(f"[heldout] 恢复用户原黑板 -> {BLACKBOARD.name}")
    else:
        print("[heldout] 警告：备份不存在，跳过恢复")


def run(cands: list[dict], provider: str, wallclock: float, mock: bool,
        limit: int, concurrency: int, cold_blackboard: bool, e3: bool,
        neutralize_leaks: bool = False) -> int:
    run_dir = build_run_dir(cands, neutralize_leaks=neutralize_leaks)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", "eval.benchmark",
        "--questions-dir", str(run_dir),
        "--presolve-skip",                      # 强制主 Agent 全链路，禁 presolve 静态直出
        "--provider", provider,
        "--wallclock", str(wallclock),
        "--results-dir", str(OUT_DIR),
        "--limit", str(limit),
        "--concurrency", str(concurrency),
    ]
    if mock:
        cmd.append("--mock")
    print(f"[heldout] 运行自主链路: {' '.join(cmd)}")
    print(f"[heldout] E3 附件证据注入(CTF_AGENT_E3): {'ON' if e3 else 'OFF'}")

    # E3（2026-08-25 桶C攻坚）：held-out 自主推理正是证据注入的测量场，默认开启。
    # 不开 E3 则 30% 的「证据不进脑」LLM 失败无解药，且无法量 E3 效果。
    # 基线 KPI=14（presolve 口径）不走此路径，不受影响。
    env = dict(os.environ)
    if e3 and not mock:
        env["CTF_AGENT_E3"] = "1"
    elif e3 and mock:
        # mock 跑也透传，便于验证 E3 接线不改变流水线
        env["CTF_AGENT_E3"] = "1"

    backup = None
    if cold_blackboard and not mock:
        backup = _backup_and_clear_blackboard()
    try:
        rc = subprocess.call(cmd, cwd=str(ROOT), env=env)
    finally:
        if backup is not None:
            _restore_blackboard(backup)
    print(f"[heldout] 退出码 {rc}；报告见 {OUT_DIR}")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="Held-out 未见题自主解题基准")
    ap.add_argument("--select", action="store_true", help="仅选题并写 manifest")
    ap.add_argument("--run", action="store_true", help="在候选池上跑自主链路")
    ap.add_argument("--provider", default="baidu")
    ap.add_argument("--wallclock", type=float, default=300.0)
    ap.add_argument("--mock", action="store_true", help="冒烟用 mock（无 API）")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 题（0=全部）")
    ap.add_argument("--concurrency", type=int, default=1, help="题目并发数（1=串行）")
    ap.add_argument("--no-cold-blackboard", dest="cold_blackboard", action="store_false",
                    help="禁用冷启动（默认清空跨会话 flag 缓存，防 held-out 题被旧缓存命中）")
    ap.add_argument("--no-require-sha256", dest="require_sha256", action="store_false",
                    help="不强制要求 flag_sha256（默认仅纳入可校验题，避免假阴性）")
    ap.add_argument("--no-e3", dest="e3", action="store_false",
                    help="禁用 E3 附件证据注入（默认 ON：held-out 正是证据注入测量场，"
                         "关掉则约三成的『证据不进脑』失败无解药且无法量 E3 效果）")
    ap.add_argument("--include-neutralized", dest="include_neutralized", action="store_true",
                    help="纳入答案泄露题但脱敏（隐藏 flag.txt/明文答案，agent 看不到答案）——"
                         "对应『答案泄露可以不看答案』：扩样本量，量 agent 不看答案时的真实水位")
    args = ap.parse_args()

    cands, all_recs = select_candidates(require_sha256=args.require_sha256,
                                        include_neutralized=args.include_neutralized)
    write_manifest(cands, all_recs, args.require_sha256, args.include_neutralized)
    print(f"[heldout] 候选池 = {len(cands)} 道（manifest: {MANIFEST}）")
    for c in cands:
        print(f"  - {c['id']} [{c['category']}] sha256={'Y' if c['has_flag_sha256'] else 'N'}")
    print("[heldout] 排除明细:")
    from collections import Counter
    for reason, n in sorted(Counter(r["excluded"] or "INCLUDED" for r in all_recs).items()):
        print(f"    {reason}: {n}")

    if args.select and not args.run:
        return 0
    if not args.run:
        # 默认：选完即止（不自动真跑，避免无凭证时空耗）
        return 0
    return run(cands, args.provider, args.wallclock, args.mock,
               args.limit, args.concurrency, args.cold_blackboard, args.e3,
               neutralize_leaks=args.include_neutralized)


if __name__ == "__main__":
    raise SystemExit(main())
