# -*- coding: utf-8 -*-
"""重建回归索引 category_regression.json（2026-08-22 赛后重锐评 M1.1）。

数据源合并：
- data/questions_real/**/*.json   → 15 道带真值 flag 的真题（回归判分基准）
- data/race_details/*.json        → 33 道初赛挑战详情（无本地 flag，只能跑链路）

产出: data/results/category_regression.json（list，供 scripts/_dryrun_race.py:34 读取）

用法:
    .venv/Scripts/python.exe scripts/_build_regression_index.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

QUESTIONS_REAL = _ROOT / "data" / "questions_real"
RACE_DETAILS = _ROOT / "data" / "race_details"
OUT_PATH = _ROOT / "data" / "results" / "category_regression.json"


def _infer_race_category(name: str) -> str:
    """与 _dryrun_race.race_to_question 相同的 name 前缀推断（保持口径一致）。"""
    up = (name or "").upper()
    if up.startswith("CRYPTO"):
        return "crypto"
    if up.startswith("MISC"):
        return "misc"
    if up.startswith("PWN"):
        return "pwn"
    if up.startswith("REVERSE"):
        return "reverse"
    if up.startswith(("WEB", "REAL", "RANK")):
        return "web"
    return "misc"


def _collect_questions_real() -> list[dict]:
    out = []
    for p in sorted(QUESTIONS_REAL.rglob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        atts = d.get("attachments") or []
        out.append({
            "id": str(d.get("id", p.stem)),
            "category": str(d.get("category", "misc")).lower(),
            "title": d.get("title", p.stem),
            "difficulty": str(d.get("difficulty", "")).upper() or None,
            "flag": d.get("flag"),
            "source": "questions_real",
            "qpath": str(p.resolve()),
            "detail_ref": None,
            "has_local_attachments": all(Path(a).exists() for a in atts) if atts else False,
        })
    return out


def _collect_race_details() -> list[dict]:
    out = []
    if not RACE_DETAILS.exists():
        return out
    for p in sorted(RACE_DETAILS.glob("*.json")):
        if p.name == "_summary.json":
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8")).get("data", {})
        except json.JSONDecodeError:
            continue
        name = str(d.get("name", p.stem))
        out.append({
            "id": str(d.get("id", p.stem)),
            "category": _infer_race_category(name),
            "title": name,
            "difficulty": str(d.get("difficulty", "")).upper() or None,
            "flag": None,
            "source": "race_details",
            "qpath": None,
            "detail_ref": p.name,
            "has_local_attachments": False,
        })
    return out


def main() -> int:
    qr = _collect_questions_real()
    rd = _collect_race_details()

    # 合并：questions_real 优先（id 撞车时保留真值条目）
    merged = {e["id"]: e for e in rd}
    merged.update({e["id"]: e for e in qr})
    index = sorted(
        merged.values(),
        key=lambda e: (0, int(e["id"])) if e["id"].isdigit() else (1, e["id"]),
    )

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(
        json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # 汇总
    by_cat: dict[str, dict] = {}
    n_flag = 0
    n_att = 0
    for e in index:
        c = by_cat.setdefault(e["category"], {"total": 0, "flag": 0, "att": 0})
        c["total"] += 1
        if e.get("flag"):
            c["flag"] += 1
            n_flag += 1
        if e.get("has_local_attachments"):
            c["att"] += 1
            n_att += 1

    print(f"索引已写入: {OUT_PATH}（{len(index)} 题）")
    print(f"  带真值 flag: {n_flag}；本地附件齐全可跑: {n_att}")
    print("  按题型: " + " | ".join(
        f"{k}: {v['total']}题(flag {v['flag']}/att {v['att']})"
        for k, v in sorted(by_cat.items())
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
