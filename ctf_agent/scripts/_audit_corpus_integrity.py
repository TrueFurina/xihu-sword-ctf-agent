#!/usr/bin/env python3
"""题库完整性审计（2026-10-10 · 防"交付物悄悄腐烂"）。

为什么需要（真实事故链）
------------------------
2026-10-06 我把 87 道真题导出给 SecAutoMind 当"外部基准"，10-10 复核时发现：
  1. 其中 8 题的**唯一附件是 writeup 文本**，而该文本在 `_archive/` 清理时被删 →
     载荷消失，题目变成必然 0 分的坏题；
  2. 另 8 题的附件**就是答案键**（flag.txt 里存裸值）；
  3. 再 5 题没有可判定的真值。
→ 交付出去的"外部真题基准"实际只有 **10 题**能用于推理能力评测，其中未见题仅 1 题。

三类问题都不会自己报错：跑批时它们只是"解不出"，看起来像模型不行。
**必须有一道机器门禁在交付前把坏题挑出来。**

检查项（每题判定）
  payload_missing   声明了附件但磁盘上没有 → 必然 0 分
  answer_key_only   附件只有答案键形态、无真实载荷 → 坏题
  answer_leak       附件里能直接扫到真值 → 不能用于推理能力分母
  no_truth          无 flag_sha256 且 flag 非 sha256 占位 → 无法机器验真伪
  self_authored     自产训练题（不得计入"外部真题"口径）

用法
----
  python scripts/_audit_corpus_integrity.py --root data/questions_real [--json] [--strict]
  # --strict: 出现 broken 级问题即退出码 1（门禁模式）；默认只报告
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{1,20}\{[^}\s]{4,120}\}")
UUID_LIKE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
KEY_NAMES = ("flag", "answer", "key", "pass", "secret")


def sha_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()


def _matches(cand: bytes, truth: str) -> bool:
    """候选是否命中真值（全串 / 内文 / 裸值三种登记口径）。"""
    if not truth:
        return False
    if sha_hex(cand) == truth:
        return True
    m = re.search(rb"\{(.+)\}", cand, re.DOTALL)
    return bool(m) and sha_hex(m.group(1)) == truth


def audit_question(q: dict, fp: Path, root: Path, att_root: Path | None = None) -> dict:
    qid = str(q.get("id") or fp.stem)
    truth = str(q.get("flag_sha256") or "").strip().lower()
    flag_field = str(q.get("flag") or "").strip().lower()
    if not truth and HEX64.match(flag_field):
        truth = flag_field  # flag 字段本身是 sha256 占位
    base = att_root or Path.cwd()
    issues, atts = [], list(q.get("attachments") or [])
    payload_on_disk, keyish, leak = 0, 0, False
    for rel in atts:
        # 题库里的附件路径是相对**仓库根**（如 data/questions_real/_attachments/...），
        # 初版按题库目录拼接 → 93 题全报 payload_missing（假阳性）。改为多候选探测：
        # 先按 CWD（仓库根）解析，再退回题库根，任一命中即算存在。
        cands = [base / rel, Path(rel), root / rel, root.parent / rel]
        p = next((c for c in cands if c.is_file()), None)
        if p is None:
            continue
        payload_on_disk += 1
        raw = p.read_bytes()
        if any(k in p.name.lower() for k in KEY_NAMES):
            txt = raw.decode("utf-8", errors="ignore").strip()
            if len(txt) <= 200 and (HEX32.match(txt) or UUID_LIKE.match(txt)
                                     or _matches(txt.encode(), truth)):
                keyish += 1
        if len(raw) <= 65536:
            for cand in FLAG_RE.findall(raw) + [raw.strip()]:
                if cand and _matches(cand, truth):
                    leak = True
                    break
    if atts and payload_on_disk == 0:
        issues.append("payload_missing")
    elif atts and keyish == payload_on_disk and keyish > 0:
        issues.append("answer_key_only")
    if leak:
        issues.append("answer_leak")
    if not truth:
        issues.append("no_truth")
    prov = str(q.get("provenance") or "").lower()
    if any(k in prov for k in ("self_authored_training", "self-authored", "自产")):
        issues.append("self_authored")
    level = ("broken" if {"payload_missing", "answer_key_only", "no_truth"} & set(issues)
             else "leaky" if "answer_leak" in issues else "ok")
    return {"id": qid, "file": str(fp), "level": level, "issues": issues,
            "attachments": len(atts), "payload_on_disk": payload_on_disk}


def audit(root: Path, att_root: Path | None = None) -> dict:
    rows = []
    for fp in sorted(root.rglob("*.json")):
        try:
            q = json.loads(fp.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            rows.append({"id": fp.stem, "file": str(fp), "level": "broken",
                         "issues": [f"parse_error:{exc}"], "attachments": 0,
                         "payload_on_disk": 0})
            continue
        rows.append(audit_question(q, fp, root, att_root))
    levels = Counter(r["level"] for r in rows)
    issue_counts = Counter(i.split(":")[0] for r in rows for i in r["issues"])
    usable = [r for r in rows if r["level"] == "ok"]
    return {"generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "root": str(root), "total": len(rows),
            "by_level": dict(levels), "by_issue": dict(issue_counts),
            "usable_for_reasoning": len(usable),
            "broken_list": [r["id"] for r in rows if r["level"] == "broken"],
            "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description="题库完整性审计")
    ap.add_argument("--root", default="data/questions_real")
    ap.add_argument("--att-root", default=".",
                    help="附件相对路径的解析根（默认当前目录=仓库根）")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="有 broken 题即退出码 1")
    args = ap.parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print(f"[audit] 题库目录不存在: {root}")
        return 2
    rep = audit(root, Path(args.att_root))
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        print(f"[audit] {root}：共 {rep['total']} 题")
        print(f"  可用于推理评测(ok): {rep['usable_for_reasoning']}")
        print(f"  分层: {rep['by_level']}")
        print(f"  问题计数: {rep['by_issue']}")
        if rep["broken_list"]:
            print(f"  ❌ 坏题 {len(rep['broken_list'])} 道（前 12）:")
            for qid in rep["broken_list"][:12]:
                print("     -", qid)
    if args.strict and rep["by_level"].get("broken"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
