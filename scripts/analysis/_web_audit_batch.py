#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""web 源码审计批量脚本（B-09 真题消化弹药）：对分类回归确认为 web 的题
逐个跑 web_source_audit，产出 data/results/web_audit_summary.json。

用法：.venv/Scripts/python.exe scripts/analysis/_web_audit_batch.py [--ids 10716,10717]
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from skills.web_source_audit import run  # noqa: E402

CAT = os.path.join(ROOT, "data", "results", "category_regression.json")
WORK = os.path.join(ROOT, "data", "work_web")
OUT = os.path.join(ROOT, "data", "results", "web_audit_summary.json")


def main():
    only_ids = None
    if len(sys.argv) > 1 and sys.argv[1] == "--ids":
        only_ids = set(sys.argv[2].split(","))

    cat = json.load(open(CAT, encoding="utf-8"))
    web_ids = {r["id"] for r in cat if r["category"] == "web"}
    if only_ids:
        web_ids &= only_ids
    print(f"web 题待审计: {len(web_ids)}")

    summary = []
    for d in sorted(os.listdir(WORK)):
        m = re.match(r"^(\d+)_", d)
        if not m or m.group(1) not in web_ids:
            continue
        fp = os.path.join(WORK, d)
        if not os.path.isdir(fp):
            continue
        try:
            r = run({"path": fp, "name": d})
            summary.append({
                "id": m.group(1), "dir": d,
                "flags": len(r["found_flags"]), "backdoors": len(r["backdoors"]),
                "sensitive": len(r["sensitive_files"]),
                "cve": [c["hint"] for c in r["cve_candidates"]],
                "flag_matches": [f["match"][:80] for f in r["found_flags"][:3]],
                "bdoor_files": [b["file"].split(os.sep)[-1] for b in r["backdoors"][:4]],
            })
            print(f"  {m.group(1)} {d[:38]:<40} flags={len(r['found_flags']):<3} bd={len(r['backdoors']):<2} sens={len(r['sensitive_files'])}")
        except Exception as e:  # noqa: BLE001
            print(f"  {m.group(1)} {d[:38]} ERROR {str(e)[:60]}")

    json.dump(summary, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    hit = [s for s in summary if s["flags"] or s["backdoors"]]
    print(f"\n=== {len(summary)} 题完成 → {OUT}")
    print(f"有 flag/后门命中: {len(hit)} 题")
    for s in hit:
        print(f"  {s['id']}: flags={s['flag_matches']} bd={s['bdoor_files']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
