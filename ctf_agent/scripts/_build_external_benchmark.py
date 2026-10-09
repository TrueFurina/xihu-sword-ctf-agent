#!/usr/bin/env python3
"""外部未见题基准构建器 / 校验器（2026-10-10）。

为什么要有这个
--------------
此前"外部基准"散落在 data/ 下（且 data/ 整目录不入库），谁都不知道哪批题是正式的、
按什么规则选的、什么时候选的。本脚本把口径固化成**可入库、可复算、可校验**的基准：

  ctf_agent/benchmarks/external_unseen/
      MANIFEST.json      选池规则、来源池、题数、题型分布、生成时间、git HEAD、完整性体检摘要
      questions/*.json   题目文件（只含 flag_sha256 占位，无明文答案）
      README.md          用法与口径红线

选池规则（全部机器判定，禁止手挑）
  1. 载荷完整：声明的每个附件都在磁盘上；
  2. 无答案泄漏：附件字节不含真值（sha256 精确比对 + flag{}/裸值形态扫描）；
  3. 有可验真真值：flag_sha256 为 64 位十六进制，或 flag 字段本身是 64 位占位；
  4. 未见：不在 KPI 授权台账 / 已解出 ledger / 历史跑批 solved 记录里；
  5. 跨池同名 id 合并去重（按 id 去重，保留先出现者）。

用法
----
  python scripts/_build_external_benchmark.py            # 构建/刷新
  python scripts/_build_external_benchmark.py --check    # 校验（磁盘 vs MANIFEST，退出码 1=不一致）
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "benchmarks" / "external_unseen"
SRC_POOLS = ("questions_external", "questions_ext", "questions_ext_cybench",
             "questions_ext_A5_20261001", "questions_ext_A_20261001",
             "questions_ext_trial5_20261001")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _load_auditor():
    spec = importlib.util.spec_from_file_location(
        "_audit_corpus_integrity", ROOT / "scripts" / "_audit_corpus_integrity.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _seen_ids() -> set[str]:
    """已解出/已授权的题 id（排除集）。来源三处：KPI 台账、已解出 ledger、历史跑批报告。"""
    seen: set[str] = set()
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from _antifraud import AUTHORIZED_KPI_SOLVES  # type: ignore
        seen |= {str(x) for x in AUTHORIZED_KPI_SOLVES}
    except Exception:  # noqa: BLE001
        pass
    ledger = ROOT.parent / "REAL_SOLVES_LEDGER.md"
    if ledger.is_file():
        seen |= {m.group(1) for m in re.finditer(
            r"\b([a-z]{2,5}[a-z0-9_]*_[a-z0-9_]+|[a-z0-9_]*\d{3,}[a-z0-9_]*)\b",
            ledger.read_text(encoding="utf-8", errors="ignore"))}
    for rep in (ROOT / "data" / "results").glob("**/benchmark_report*.json"):
        try:
            for r in json.loads(rep.read_text(encoding="utf-8")).get("results", []):
                if r.get("solved"):
                    seen.add(str(r.get("question_id")))
        except Exception:  # noqa: BLE001
            pass
    return seen


def build() -> dict:
    aci = _load_auditor()
    seen = _seen_ids()
    picked: dict[str, dict] = {}
    skipped = Counter()
    for pool in SRC_POOLS:
        d = ROOT / "data" / pool
        if not d.is_dir():
            skipped["pool_missing"] += 1
            continue
        rep = aci.audit(d, ROOT)
        for row in rep["rows"]:
            qid = row["id"]
            if row["level"] != "ok":
                skipped[f"not_ok:{row['level']}"] += 1
                continue
            if qid in seen:
                skipped["already_solved_or_authorized"] += 1
                continue
            if qid in picked:
                skipped["duplicate_id_across_pools"] += 1
                continue
            q = json.loads(Path(row["file"]).read_text(encoding="utf-8"))
            atts = list(q.get("attachments") or [])
            if not atts or not all((ROOT / a).is_file() for a in atts):
                skipped["payload_missing"] += 1
                continue
            truth = str(q.get("flag_sha256") or q.get("flag") or "").strip().lower()
            if not HEX64.match(truth):
                skipped["no_verifiable_truth"] += 1
                continue
            picked[qid] = {"id": qid, "category": q.get("category", "misc"),
                           "title": str(q.get("title") or "")[:120],
                           "description": q.get("description", ""),
                           "flag_sha256": truth, "flag": truth,
                           "flag_pattern": r"[A-Za-z0-9_]{1,20}\{[^\}\s]{3,120}\}",
                           "attachments": atts,
                           "difficulty": q.get("difficulty", "MEDIUM"),
                           "source_pool": pool}
    return {"picked": picked, "skipped": dict(skipped), "seen_pool_size": len(seen)}


def write_manifest(built: dict) -> dict:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    qdir = OUT_DIR / "questions"
    qdir.mkdir(exist_ok=True)
    for f in qdir.glob("*.json"):
        f.unlink()
    for qid, q in built["picked"].items():
        (qdir / f"{qid}.json").write_text(json.dumps(q, ensure_ascii=False, indent=1),
                                           encoding="utf-8")
    try:
        head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True).stdout.strip()
    except Exception:  # noqa: BLE001
        head = ""
    cats = Counter(q["category"] for q in built["picked"].values())
    att_files = sum(len(q["attachments"]) for q in built["picked"].values())
    manifest = {
        "schema": "external_unseen_benchmark/v1",
        "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "git_head": head,
        "selection_rules": [
            "载荷完整：所有声明附件在磁盘存在",
            "无答案泄漏：附件字节不含真值（sha256 精确比对 + flag{}/裸值形态扫描）",
            "真值可判定：flag_sha256 64 位十六进制，或 flag 字段为 64 位占位",
            "未见：不在 KPI 台账 / 已解出 ledger / 历史跑批 solved 记录",
            "跨池同名 id 合并去重",
        ],
        "source_pools": list(SRC_POOLS),
        "total": len(built["picked"]),
        "question_ids": sorted(built["picked"]),
        "question_ids": sorted(built["picked"]),
        "by_category": dict(cats),
        "attachment_files": att_files,
        "excluded_seen_ids": built["seen_pool_size"],
        "skipped": built["skipped"],
        "judge": "scripts/_run_validity_guard.py（跑批有效性）+ ctf_agent/verify/flag_checker.py::sha256_matches（判真值）",
        "answers": "本目录不含任何明文答案，仅 flag_sha256 占位",
    }
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _truth_guard import write_truth
    write_truth(OUT_DIR / "MANIFEST.json", manifest,
                schema="external_unseen_benchmark/v1",
                by="scripts/_build_external_benchmark.py", strict_path=False)
    return manifest


def check() -> tuple[bool, list[str]]:
    mpath = OUT_DIR / "MANIFEST.json"
    if not mpath.is_file():
        return False, ["缺少 MANIFEST.json"]
    man = json.loads(mpath.read_text(encoding="utf-8"))
    qdir = OUT_DIR / "questions"
    on_disk = {f.stem for f in qdir.glob("*.json")} if qdir.is_dir() else set()
    problems = []
    if on_disk != set(json.loads(
            (qdir.parent / "MANIFEST.json").read_text(encoding="utf-8")).get("question_ids", [])) \
            and man.get("total") != len(on_disk):
        problems.append(f"题数不一致: MANIFEST={man.get('total')} 磁盘={len(on_disk)}")
    for f in qdir.glob("*.json"):
        q = json.loads(f.read_text(encoding="utf-8"))
        if not HEX64.match(str(q.get("flag_sha256", ""))):
            problems.append(f"{f.stem}: flag_sha256 非法")
        for a in q.get("attachments", []):
            if not (ROOT / a).is_file():
                problems.append(f"{f.stem}: 载荷缺失 {a}")
                break
    return not problems, problems


def main() -> int:
    ap = argparse.ArgumentParser(description="外部未见题基准构建/校验")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.check:
        ok, problems = check()
        print(f"[bench] 校验{'通过' if ok else '失败'}：{OUT_DIR}")
        for p in problems[:10]:
            print("  ❌", p)
        return 0 if ok else 1
    built = build()
    man = write_manifest(built)
    print(f"[bench] 已构建 {man['total']} 题 → {OUT_DIR}")
    print(f"[bench] 题型分布 {man['by_category']}")
    print(f"[bench] 排除统计 {man['skipped']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
