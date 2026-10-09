#!/usr/bin/env python
"""门禁聚合器：一条命令跑全部"数据真值/基准"类门禁（2026-10-10）。

**为什么需要**（真实缺口，不是整理癖）
-----------------------------------------
本项目已有 pre-commit 六道门禁（密钥/诚实口径/租约/身份/回归…），但 10-10 新增的
三道**数据类**门禁——

  ① `scripts/_truth_guard.py --audit`    机器真值 schema 完整性（防异构覆盖）
  ② `scripts/check_corpus_health.py`      题库健康基线（只在变坏时红）
  ③ `scripts/_build_external_benchmark.py --check`  正式基准清单 vs 磁盘

——**一道都没接进 pre-commit**，只能靠人记得手动跑。三道门禁各自都能发现问题，
但"记得跑"这件事本身就是最弱的一环：**纸面门禁等于没有门禁**。

于是本脚本把三道收成一个入口，供 pre-commit / 合并闸门 / 人工巡检共用。

**fail-closed 与假红权衡**
-------------------------
- 真值审计：硬失败（有发现即红，无商量）。
- 基准 `--check`：硬失败（清单与磁盘不一致说明基准已腐烂）。
- 题库健康：**只在回归时红**。`questions_real` 有 77 道已知历史坏题（64 道唯一附件
  是 `flag.txt` 答案键、8 道载荷随归档删除、5 道无真值），若按"坏题>0 即红"会天天假红，
  而**天天假红的护栏最终一定被人整段注释掉**——那才是真正的门禁失效。

退出码：0 全过 / 1 有门禁失败 / 2 脚本自身无法执行（fail-closed，不放行）。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

# 每道门禁：key, 标题, 命令, 失败是否硬拦
GATES = [
    ("truth", "机器真值 schema 审计（防异构覆盖）",
     [PY, "scripts/_truth_guard.py", "--audit"], True),
    ("bench", "正式基准清单 vs 磁盘一致性",
     [PY, "scripts/_build_external_benchmark.py", "--check"], True),
    ("health", "题库健康基线（只在回归时红）",
     [PY, "scripts/check_corpus_health.py"], True),
]


def run_gates(only: list[str] | None = None,
              verbose: bool = False) -> dict:
    """依次跑各门禁，返回结构化结果。"""
    results = []
    for key, title, cmd, hard in GATES:
        if only and key not in only:
            continue
        t0 = time.time()
        try:
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                               timeout=600)
            rc, out = p.returncode, (p.stdout or "") + (p.stderr or "")
            crashed = False
        except (OSError, subprocess.SubprocessError) as exc:
            # 🔴 门禁自身跑不起来 = 无法判定 = fail-closed（不放行）
            rc, out, crashed = 2, f"门禁无法执行: {exc}", True
        ok = (rc == 0) and not crashed
        results.append({
            "key": key, "title": title, "ok": ok, "rc": rc,
            "hard_block": hard, "crashed": crashed,
            "seconds": round(time.time() - t0, 2),
            "tail": out.strip().splitlines()[-4:] if (verbose or not ok) else [],
        })
    passed = all(r["ok"] for r in results)
    return {"passed": passed, "results": results,
            "n_passed": sum(1 for r in results if r["ok"]),
            "n_total": len(results)}


def main() -> int:
    ap = argparse.ArgumentParser(description="门禁聚合器（数据真值/基准类）")
    ap.add_argument("--only", default="", help="只跑指定门禁，逗号分隔（truth/bench/health）")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--verbose", action="store_true", help="打印每道门禁的输出尾部")
    args = ap.parse_args()

    only = [k.strip() for k in args.only.split(",") if k.strip()]
    if only:
        known = {k for k, *_ in GATES}
        bad = set(only) - known
        if bad:
            print(f"[gates] 未知门禁: {sorted(bad)}；可选: {sorted(known)}")
            return 2

    rep = run_gates(only or None, args.verbose)
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        for r in rep["results"]:
            mark = "✅" if r["ok"] else ("💥" if r["crashed"] else "❌")
            print(f"  {mark} [{r['key']:6s}] {r['title']:34s} "
                  f"rc={r['rc']} {r['seconds']}s")
            for line in r["tail"]:
                print(f"        {line}")
        total = rep["n_total"]
        print(f"[gates] {rep['n_passed']}/{total} 道通过"
              + ("（全部通过）" if rep["passed"] else "—— 有门禁失败，请先修复再提交"))
    if not rep["results"]:
        print("[gates] 未选中任何门禁")
        return 2
    return 0 if rep["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
