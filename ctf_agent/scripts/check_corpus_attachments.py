#!/usr/bin/env python3
"""Corpus attachment integrity checker.

扫描 data/questions 与 data/questions_real 下所有题目 JSON，解析其
``attachments`` 字段引用的本地二进制/附件路径，逐文件校验是否真实存在。

用途：
- 暴露 benchmark 语料“附件悬空引用”问题（二进制 fixtures 未在 checkout 中）。
- 可作为 CI 门禁：任一附件缺失即退出码非 0。

注意：本脚本只读扫描，绝不下载、绝不修改任何文件。live 平台题的附件来自
平台 API（见 core/attachment_harness.prepare_question），不在此检查范围。

用法：
    python scripts/check_corpus_attachments.py
    python scripts/check_corpus_attachments.py --json report.json
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {"_attachments", "answers", "_answers", "_keys", "_solutions"}


def _iter_question_jsons():
    for base_name in ("data/questions", "data/questions_real"):
        base = os.path.join(ROOT, base_name)
        if not os.path.isdir(base):
            continue
        for jf in glob.glob(os.path.join(base, "**", "*.json"), recursive=True):
            rel_parts = set(os.path.normpath(
                os.path.relpath(jf, base)).split(os.sep)[:-1])
            if rel_parts & SKIP_DIRS:
                continue
            yield jf


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="把报告写入该 JSON 路径")
    ap.add_argument("--root", default=ROOT, help="项目根（默认自动探测）")
    args = ap.parse_args()

    root = args.root
    total_q = total_att = missing_att = 0
    by_cat: dict[str, dict[str, int]] = defaultdict(
        lambda: {"q": 0, "att": 0, "miss": 0})
    missing_examples: list[dict] = []

    for jf in _iter_question_jsons():
        try:
            with open(jf, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception:
            continue
        if "category" not in d and "attachments" not in d:
            continue
        atts = d.get("attachments") or []
        if not atts:
            continue
        cat = str(d.get("category", "?")).lower()
        by_cat[cat]["q"] += 1
        total_q += 1
        for a in atts:
            total_att += 1
            by_cat[cat]["att"] += 1
            p = a if os.path.isabs(a) else os.path.normpath(
                os.path.join(os.path.dirname(jf), a))
            if not os.path.exists(p):
                missing_att += 1
                by_cat[cat]["miss"] += 1
                if len(missing_examples) < 20:
                    missing_examples.append({
                        "question": os.path.relpath(jf, root),
                        "category": cat,
                        "ref": a,
                        "resolved": p,
                    })

    report = {
        "questions_with_attachments": total_q,
        "attachment_refs": total_att,
        "missing": missing_att,
        "missing_pct": round(100 * missing_att / max(total_att, 1), 1),
        "by_category": dict(by_cat),
        "missing_examples": missing_examples,
    }

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print(f"报告已写入 {args.json}")

    print(f"含附件题目数 = {total_q}")
    print(f"附件引用     = {total_att}")
    print(f"缺失         = {missing_att} ({report['missing_pct']}%)")
    print("--- 按题型 ---")
    for c, v in sorted(by_cat.items()):
        print(f"  {c:10s} q={v['q']:3d}  att={v['att']:3d}  missing={v['miss']:3d}")
    print(f"--- 缺失示例(前 {len(missing_examples)}) ---")
    for ex in missing_examples[:8]:
        print(f"  [{ex['category']}] {ex['question']}")
        print(f"      ref={ex['ref']}")

    return 1 if missing_att else 0


if __name__ == "__main__":
    sys.exit(main())
