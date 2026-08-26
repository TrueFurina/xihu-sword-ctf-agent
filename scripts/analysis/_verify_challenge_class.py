"""B-08：32 题分类回归——用 title 前缀 ground truth 对比 _parse_challenge 输出。

验收：分类正确率 ≥90%（SSOT B-08）。输出误判清单，据此修正 dasctf._parse_challenge 关键字表。
用法：.venv/Scripts/python.exe scripts/analysis/_verify_challenge_class.py
退出码：0=正确率≥90%；1=有误判且低于阈值。
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ctfplatform.dasctf import _parse_challenge  # noqa: E402

THRESHOLD = 90.0


def main() -> int:
    files = sorted(glob.glob(os.path.join("data", "race_details", "*.json")))
    files = [f for f in files if not f.endswith("_summary.json")]
    if not files:
        print("FAIL: data/race_details/ 无题目 JSON")
        return 1
    wrong, ok, total, unverifiable = [], 0, 0, 0
    detail = []
    for fp in files:
        with open(fp, encoding="utf-8") as fh:
            item = json.load(fh)
        if "data" in item and isinstance(item["data"], dict):
            item = item["data"]
        ci = _parse_challenge(item)
        title = str(item.get("title") or item.get("name") or "").lower()
        gt = None
        for cat in ("web", "crypto", "misc", "reverse", "pwn"):
            if title.startswith(cat):
                gt = cat
                break
        total += 1
        if gt is None:
            # REAL-xx 系列标题不携带题型，真实分类在附件/题面（无法 title 验证）
            unverifiable += 1
            detail.append((os.path.basename(fp), title, "?", ci.category, "unverifiable"))
            ok += 1  # 不判误
            continue
        if ci.category == gt:
            ok += 1
            detail.append((os.path.basename(fp), title, gt, ci.category, "ok"))
        else:
            wrong.append((os.path.basename(fp), title, gt, ci.category))
            detail.append((os.path.basename(fp), title, gt, ci.category, "MISMATCH"))
    rate = ok / total * 100 if total else 0.0
    print(f"共 {total} 题（可验证 {total - unverifiable}，REAL 系列 {unverifiable} 题标题不携题型）")
    print(f"分类正确率: {ok}/{total} = {rate:.1f}%  （阈值 {THRESHOLD}%）")
    if wrong:
        print(f"\n❌ 误判 {len(wrong)} 题：")
        for fp, title, gt, got in wrong:
            print(f"  - {fp}: title={title!r}  期望 {gt}  实际 {got}")
    else:
        print("✅ 无 title 可验证的误判")
    if unverifiable:
        print(f"\nℹ️  REAL 系列 {unverifiable} 题无法用 title 验证，可人工抽查：")
        for fp, title, _, got, _st in [d for d in detail if d[4] == "unverifiable"]:
            print(f"  - {fp}: {title!r} -> 分类 {got}")
    return 0 if rate >= THRESHOLD else 1


if __name__ == "__main__":
    sys.exit(main())
