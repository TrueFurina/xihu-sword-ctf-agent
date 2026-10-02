"""KPI 锚点 × 答案来源 交叉审计（零成本、只读、纯本地）。

为什么需要 —— 2026-10-01 干净口径复盘发现：内部 92 道语料里 68 道（74%）的真值 flag
**物理上就躺在附件或题面里**（att_leak / desc_leak）。这直接威胁项目唯一对外数字
`offline_verified`（=14，README 引用的绝对计数）：若这 14 道也靠"答案本就在手边"充数，
则 headline KPI 与已被证伪的「presolve 74/92」是同一类注水。

本脚本把台账 `REAL_SOLVES_LEDGER.md` 里**被 `count_offline_verified()` 计入**的题
（`_classify_entry` 判 A/B 类 **且** 状态行含 `✅ offline_verified`）逐题映射到
`data/questions_real/` 的题目 id，再与 `_leak_provenance.py` 的输出 join，回答：
    「这 14 道里，几道是真算出来的，几道是白给的？」

判据（**注意 `unsolved` 的精确语义**）：
  - `att_leak` / `desc_leak` → 🔴 泄漏：答案物理存在 → **KPI 被污染**
  - `computed`               → ✅ 干净：presolve oracle 已离线算出
  - `unsolved`               → ⚠️ **presolve oracle 未命中**。这**不等于**题目不可解——
                                 A 类题本就不是 presolve 的目标，常由专用 verifier 核验
                                 （如 `verify_specialcurve2.py`）。此档需人工/台账复核，
                                 脚本不擅自判"注水"。
  - 台账有记、语料无对应文件  → ⚠️ 台账-语料漂移（2026-10-03 前已知 10733，现已补齐清零）。

本脚本**只读**：不改题库、不改台账、不改 KPI 源。

用法：
    python scripts/_kpi_leak_crossaudit.py \
        --leak heldout_evidence/leak_provenance_real92_20261001.json [--json OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts._merge_gate import _classify_entry, count_offline_verified  # noqa: E402

LEDGER = ROOT / "REAL_SOLVES_LEDGER.md"

_ID_RE = re.compile(r"^\d+\.\s*([A-Za-z0-9_\-]+)")


def parse_ledger(ledger_text: str) -> "list[dict]":
    """从台账文本解析出**被 KPI 计入**的题块。

    口径与 `_merge_gate.count_offline_verified()` 严格一致：题块（`### ` 起）分类为
    A/B 类，且块内首个 `- **状态**` 行含 `✅ offline_verified`。

    Returns:
        [{"title": str, "id": str}]，id 取标题里 "N. <id>" 的 <id>（取不到则为 ""）。
    """
    blocks: "list[dict]" = []
    cur: "dict | None" = None
    for line in ledger_text.splitlines():
        if line.startswith("### "):
            cur = {"title": line[4:].strip(), "status": None}
            blocks.append(cur)
        elif cur is not None and "- **状态**" in line and cur["status"] is None:
            cur["status"] = line.strip()
    out = []
    for b in blocks:
        if _classify_entry(b["title"]) not in ("A", "B"):
            continue
        if not (b["status"] and "✅ offline_verified" in b["status"]):
            continue
        m = _ID_RE.match(b["title"])
        out.append({"title": b["title"], "id": m.group(1) if m else ""})
    return out


def cross_audit(ledger_text: str, leak_rows: "list[dict]") -> dict:
    """把 KPI 计入题 × 答案来源判定做交叉（纯函数，便于测试注入）。

    Args:
        ledger_text: REAL_SOLVES_LEDGER.md 全文。
        leak_rows: _leak_provenance.py 输出的 rows（含 id / provenance）。

    Returns:
        dict：逐题明细 + 汇总 + 是否被污染的判决。
    """
    counted = parse_ledger(ledger_text)
    prov = {r.get("id"): r.get("provenance") for r in leak_rows}

    rows = []
    for c in counted:
        p = prov.get(c["id"]) if c["id"] else None
        if c["id"] and c["id"] in prov:
            in_corpus = True
        else:
            in_corpus = False
        if not in_corpus:
            bucket = "missing_corpus"     # 台账有记、语料无对应文件
        elif p in ("att_leak", "desc_leak"):
            bucket = "leak"               # 🔴 污染
        elif p == "computed":
            bucket = "computed"           # ✅ 干净
        else:
            bucket = "unsolved"           # ⚠️ oracle 未命中（≠不可解）
        rows.append({"id": c["id"], "title": c["title"],
                     "in_corpus": in_corpus, "provenance": p, "bucket": bucket})

    n = len(rows)
    n_leak = sum(1 for r in rows if r["bucket"] == "leak")
    return {
        "counted": n,
        "in_corpus": sum(1 for r in rows if r["in_corpus"]),
        "computed": sum(1 for r in rows if r["bucket"] == "computed"),
        "leak": n_leak,
        "unsolved": sum(1 for r in rows if r["bucket"] == "unsolved"),
        "missing_corpus": sum(1 for r in rows if r["bucket"] == "missing_corpus"),
        "contaminated": n_leak > 0,
        "leak_ids": [r["id"] for r in rows if r["bucket"] == "leak"],
        "unsolved_ids": [r["id"] for r in rows if r["bucket"] == "unsolved"],
        "missing_corpus_ids": [r["id"] for r in rows if r["bucket"] == "missing_corpus"],
        "rows": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="KPI 锚点 × 答案来源交叉审计（只读）")
    ap.add_argument("--leak", required=True, help="_leak_provenance.py 输出的 JSON")
    ap.add_argument("--ledger", default=str(LEDGER))
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    ledger_text = Path(args.ledger).read_text(encoding="utf-8")
    leak_rows = json.loads(Path(args.leak).read_text(encoding="utf-8")).get("rows", [])
    r = cross_audit(ledger_text, leak_rows)

    # 自检：解析出的计入数必须 == 权威口径 count_offline_verified()，否则口径分叉。
    canon = count_offline_verified()
    drift = "" if canon == r["counted"] else f" ⚠️ 与 count_offline_verified()={canon} 不一致"
    print(f"### KPI 计入题 = {r['counted']}  (canonical={canon}){drift}")
    print(f"  ✅ computed(干净)      = {r['computed']}")
    print(f"  🔴 leak(att/desc 泄漏) = {r['leak']}   {r['leak_ids']}")
    print(f"  ⚠️ unsolved(oracle未中) = {r['unsolved']}   {r['unsolved_ids']}")
    print(f"  ⚠️ missing_corpus      = {r['missing_corpus']}   {r['missing_corpus_ids']}")
    print(f"  → 判决：{'🔴 被污染' if r['contaminated'] else '✅ 无 att/desc 泄漏'}")
    if args.json:
        Path(args.json).write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  -> {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
