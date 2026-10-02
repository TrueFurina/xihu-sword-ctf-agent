"""presolve 命中审计：统计确定性预扫在题库上的真命中 / 假命中 / 被误杀面。

背景（2026-09-30 扩池时意外发现）：
  在外部题（NYU CTF Bench）上跑 presolve 时，`_try_desc_answer` 返回了
  `flag{file}` / `flag{tened}` —— 与真值 sha256 不符的**假命中**。
  根因：该引擎正则含 `|is|=` 宽分支，匹配英文题面里的任意 "is"：
      "best lis|tened" -> flag{tened}      "th|is  file" -> flag{file}

  进一步发现校验闸 `_passes_answer_check` 形同虚设：
      run.py 传 answers=preset_answers()（值 = flag 字段 = **sha256 占位**），
      而该函数做**明文字符串比对**（"flag{xxx}" != "<64hex>"）→ 真命中也被拒。

本脚本把这两点量化：对同一题库跑两种 answers 形态，逐条用 sha256 判真伪。
零成本（纯本地确定性引擎，不调 LLM）。

2026-10-03 治理（B 组假命中收敛）：
  B 组（answers=None）在原实现下报出 11 条与真值 sha256 不符的假命中
  （internal92 6 / NYU34 3 / Cybench13 2），根因三条：
    ① `_try_pattern_scan` 取"第一个匹配"——共享赛事官方 wp 全文
       （anxun2020_official.txt / vnctf2022.txt）时同赛事各题都抓到该文件第一个
       flag（常是别题的）；宽 pattern 在二进制附件里伪匹配上百次（NYU hbv{}/6{Rp8$}/
       au{HHHH}）；
    ② `_engine_misc_decode`（math_engine）同类"解码后抓首个 flag"（722b6d 残余来源）；
    ③ `_try_desc_answer` 把"…提取得到 flag。"里的元词 "flag" 当答案 → flag{flag}
       （gaoxiao2024_file_extract）。
  修复：presolve 入口加「无真值时附件多候选统一守卫」 + `_try_desc_answer` 拒元词 +
  `_is_plausible_flag` 拒星号占位。实测 B 组假命中 **11 → 1**，A 组真命中 74/2/2
  完全不变（守卫仅在无真值时可触发）。残余 1 条（Cybench data_siege）为
  「无真值下不可判别」：pcap 内含看似合法的完整诱饵 flag（该题真 flag 由 3 段拼接），
  与 ELF 里硬编码真 flag（baby_s_third）在无真值时不可区分，如实保留、不假装清零。
  证据：heldout_evidence/presolve_audit_{internal92,nyu34,cybench13}_v3_20261003.json
  （对照 before 版 *_v2_20261001.json）。

用法：
    python scripts/_presolve_audit.py --dir data/questions_real_kpi9
    python scripts/_presolve_audit.py --dir data/questions_real --json ../logs/presolve_audit.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)  # 引擎日志噪音大，审计只要结果

from core.presolve import presolve  # noqa: E402
from eval.cases import load_questions, preset_answers  # noqa: E402


def _run(q, answers, timeout: float = 60.0) -> object:
    """跑一次 presolve，带单题超时保护。返回 flag / None / 'ERR:...'。"""
    async def _inner():
        return await presolve(q, registry=None, sandbox=None, answers=answers,
                              force=True)
    try:
        return asyncio.run(asyncio.wait_for(_inner(), timeout=timeout))
    except asyncio.TimeoutError:
        return "TIMEOUT"
    except Exception as exc:  # noqa: BLE001
        return f"ERR:{type(exc).__name__}"


def audit_dir(qdir: str, timeout: float = 60.0, limit: int = 0) -> dict:
    qs = load_questions(qdir)
    if limit:
        qs = qs[:limit]
    answers = preset_answers(qs)
    rows = []
    t0 = time.time()
    for i, q in enumerate(qs, 1):
        f_a = _run(q, answers, timeout)
        f_b = _run(q, None, timeout)

        def _verdict(f):
            if not isinstance(f, str) or f in ("TIMEOUT",) or f.startswith("ERR:"):
                return "-"
            return "TRUE" if q.flag_matches(f) else "FALSE"

        rows.append({
            "id": q.id, "category": q.category,
            "atts_ok": all(os.path.exists(a) for a in q.attachments) if q.attachments else False,
            "with_answers": f_a if isinstance(f_a, str) else None,
            "no_answers": f_b if isinstance(f_b, str) else None,
            "no_answers_verdict": _verdict(f_b),
            "with_answers_verdict": _verdict(f_a),
        })
        print(f"[{i:3d}/{len(qs)}] {q.id:40s} "
              f"A(分答案)={str(rows[-1]['with_answers_verdict']):6s} "
              f"B(无)={str(rows[-1]['no_answers_verdict']):6s} "
              f"| {time.time()-t0:.0f}s", flush=True)

    def _cnt(key, val):
        return sum(1 for r in rows if str(r[key]) == val)

    summary = {
        "dir": qdir, "n": len(rows), "seconds": round(time.time() - t0, 1),
        # B 组（answers=None）—— main_agent 路径的实际行为
        "no_answers_true": _cnt("no_answers_verdict", "TRUE"),
        "no_answers_false": _cnt("no_answers_verdict", "FALSE"),
        "no_answers_none": _cnt("no_answers_verdict", "-"),
        # A 组（answers=sha256 表）—— run.py 生产路径的实际行为
        "with_answers_true": _cnt("with_answers_verdict", "TRUE"),
        "with_answers_false": _cnt("with_answers_verdict", "FALSE"),
        "with_answers_none": _cnt("with_answers_verdict", "-"),
    }
    return {"summary": summary, "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="data/questions_real_kpi9")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    rep = audit_dir(args.dir, args.timeout, args.limit)
    s = rep["summary"]
    print("\n=== 汇总 ===")
    print(f"题库 {s['dir']} | {s['n']} 题 | {s['seconds']}s")
    print(f"  B 组 answers=None   （main_agent 路径）：真命中 {s['no_answers_true']} | "
          f"假命中(sha不符) {s['no_answers_false']} | 无命中 {s['no_answers_none']}")
    print(f"  A 组 answers=sha256表（run.py 路径）  ：真命中 {s['with_answers_true']} | "
          f"假命中 {s['with_answers_false']} | 无命中 {s['with_answers_none']}")
    if s["no_answers_true"] and not s["with_answers_true"]:
        print("  🔴 误杀确认：真命中在传 answers 时被 100% 拒绝（明文≠sha256 比对缺陷）")
    if s["no_answers_false"]:
        print(f"  🔴 假命中确认：{s['no_answers_false']} 条与真值 sha256 不符却通过了校验")

    if args.json:
        p = Path(args.json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"-> {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
