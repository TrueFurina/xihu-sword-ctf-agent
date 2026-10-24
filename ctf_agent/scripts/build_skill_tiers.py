#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ctf_agent 技能三分支 taxonomy（SkeMex P0）

- generic：跨任务的调度/路由，不直接解题
- task   ：一类任务的流程/范式/方法论（工具选择与顺序）
- action ：单一技术/工具的确定性模板（默认）

分类是**启发式**，每条带 reason 与 confidence；manifest 显式标注 rule_version。
不修改任何现有 skill 文件，只产旁路 manifest。

用法：
  python scripts/build_skill_tiers.py                 # dry-run
  python scripts/build_skill_tiers.py --apply         # 写 tier-manifest.json
  python scripts/build_skill_tiers.py --skills-dir PATH --out PATH
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SKILLS = ROOT / "skills"
DEFAULT_OUT = ROOT / "skills" / "tier-manifest.json"

GENERIC_NAMES = {"reverse_router", "task_analyzer"}
TASK_SUFFIXES = ("_flow", "_analysis", "_audit", "_methodology", "_router", "_general", "_chain")
TASK_MARKERS = ("流程", "范式", "方法论", "全套", "多步", "攻击链", "利用链")
HEAD_CHARS = 80  # 只看 purpose 首句，避免后半句的偶然命中


def classify(name: str, purpose: str) -> tuple[str, str, str]:
    if name in GENERIC_NAMES:
        return "generic", f"调度/路由型（{name}），不直接解题", "high"
    for suf in TASK_SUFFIXES:
        if name.endswith(suf):
            return "task", f"名字后缀 `{suf}`：一类任务的流程/范式", "high"
    head = purpose[:HEAD_CHARS]
    for m in TASK_MARKERS:
        if m in head:
            return "task", f"purpose 首句含「{m}」：任务级流程而非单点动作", "medium"
    return "action", "默认：单一技术/工具模板", "medium"


def py_doc(p: Path) -> str:
    try:
        src = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    i = src.find('"""')
    if i < 0:
        return ""
    j = src.find('"""', i + 3)
    if j < 0:
        return ""
    return src[i + 3 : j].strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skills-dir", default=str(DEFAULT_SKILLS))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    d = Path(args.skills_dir)
    if not d.is_dir():
        print(f"skills 目录不存在：{d}", file=sys.stderr)
        return 1

    entries: dict[str, dict] = {}
    bad = []
    for p in sorted(d.glob("*.json")):
        if p.name in ("tier-manifest.json",):
            continue
        try:
            j = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            bad.append(f"{p.name}: {e}")
            continue
        name = (j.get("name") or p.stem).strip()
        purpose = (j.get("purpose") or "").strip()
        tier, reason, conf = classify(name, purpose)
        if name in entries:
            bad.append(f"重复 name：{name}")
            continue
        entries[name] = {
            "tier": tier,
            "reason": reason,
            "confidence": conf,
            "categories": j.get("categories"),
            "file": p.name,
        }

    # 覆盖只有 .py、没有 .json 元数据的 skill（docstring 首段作 purpose）
    for py in sorted(d.glob("*.py")):
        name = py.stem
        if name == "__init__" or name in entries:
            continue
        tier, reason, _ = classify(name, py_doc(py))
        entries[name] = {
            "tier": tier,
            "reason": reason + "（py-only，无 JSON 元数据）",
            "confidence": "medium",
            "categories": None,
            "file": py.name,
            "source": "py-only",
        }

    counts = {"generic": 0, "task": 0, "action": 0}
    for v in entries.values():
        counts[v["tier"]] += 1

    manifest = {
        "schema": "ctf.skill-tier/v1",
        "rule_version": "heuristic-v1（name suffix + purpose markers）",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "启发式分类，不是事实判断；medium 置信项需人工复核后再用于路由。",
        "counts": counts,
        "total": len(entries),
        "skills": dict(sorted(entries.items())),
    }

    if args.json:
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
    else:
        print(f"total={len(entries)} counts={counts} bad={len(bad)} apply={args.apply}")
        for n, v in sorted(entries.items()):
            if v["tier"] != "action":
                print(f"  {v['tier']:<8} {n:<32} [{v['confidence']}] {v['reason']}")
        for b in bad:
            print("  BAD " + b)

    if bad:
        print("存在坏 JSON/重复 name，拒绝写 manifest", file=sys.stderr)
        return 1
    if args.apply:
        out = Path(args.out)
        out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"WROTE {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
