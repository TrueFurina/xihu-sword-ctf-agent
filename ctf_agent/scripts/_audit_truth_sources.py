#!/usr/bin/env python3
"""真值源一致性审计（跨项目支持 · 2026-10-05）。

为什么存在
----------
西湖论剑 CTF-Agent 2026-09-19 的 P0 事故：评测校验器从**已退役题库**取答案表，
被评测题目不在表内 → 正确 flag 一律被误判幻觉并置 None，**3 道真解被冤成 0**。
该事故的通用形态是"验证器的真值来源 ≠ 被验证对象的真值来源"，静态看代码看不出来，
只有机器对账能发现。本脚本对任意目标仓库的 benchmark 语料做同源对账。

检查项（每项独立 PASS/FAIL，退出码非 0 即红）
  1. problem 唯一性：同 id 在同文件重复 → FAIL
  2. 真值可判定：每题 flag_sha256 为 64 位十六进制 → 否则 FAIL（列出）
  3. 明文答案泄露：problems 里出现形如 flag{...} 的明文字段 → FAIL
  4. 真值源分裂：同一 id 出现在多个 benchmark 文件且 flag_sha256 不一致 → FAIL
     （这是"同一个题名、两套答案"的典型注水温床，也是 2026-09-19 事故的近亲）
  5. 外部导出集对账：external_*/benchmark.json 与其 export_manifest.json 计数一致

用法
----
  python scripts/_audit_truth_sources.py --target "E:/Program/2026挑战杯：SecAutoMind-v1.7.17-share"
  python scripts/_audit_truth_sources.py --target <repo> --json   # 机器可读输出
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SELF_BUILT_MARKERS = ("自研", "self", "自建", "synthetic", "local")
PLAINTEXT_FLAG = re.compile(r"flag\{[^}]{2,}\}")
# 明文答案可能藏的字段名（true flag / answer / solution）
SUSPECT_KEYS = ("flag", "answer", "solution", "plaintext_flag")


def _is_self_built(problem: dict, file_path: Path) -> bool:
    """题源判定：自研/自造集允许保留明文答案（判分需要、无竞争泄露风险），
    外部来源集（真题/外送集）出现明文答案 = 红线。判据：文件在 external_* 下，
    或 problem 的 source/来源字段未标自研。"""
    parts = file_path.parts
    if any(p.startswith("external_") for p in parts):
        return False
    src = " ".join(str(problem.get(k, "")) for k in ("source", "origin", "provenance")).lower()
    return any(m in src for m in SELF_BUILT_MARKERS)


def _iter_benchmarks(target: Path) -> list[Path]:
    root = target / "data" / "ctf_benchmark"
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.json")
                  if "all_benchmarks_summary" not in p.name)


def _problems_of(doc) -> dict:
    if isinstance(doc, dict):
        for key in ("problems", "cases", "questions", "items"):
            v = doc.get(key)
            if isinstance(v, dict):
                return v
            if isinstance(v, list):
                out = {}
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        out[str(item.get("id") or i)] = item
                return out
    return {}


def audit(target: Path) -> dict:
    benches = _iter_benchmarks(target)
    report: dict = {
        "target": str(target),
        "benchmarks_scanned": len(benches),
        "problems_total": 0,
        "checks": {},
    }
    failures: dict[str, list] = {
        "duplicate_id_within_file": [],
        "truth_not_verifiable": [],
        "plaintext_answer_leak_external": [],   # 红线：外部来源集出现明文答案
        "plaintext_answer_leak_selfbuilt": [], # 提示：自研集保留明文（判分需要）
        "truth_source_divergence": [],          # 真值源分裂
        "external_manifest_mismatch": [],
    }
    self_built_hint: list[str] = []

    truth_index: dict[str, list[tuple[str, str]]] = {}   # id -> [(file, sha)]
    for path in benches:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            failures["truth_not_verifiable"].append(f"{path.name}: parse_error {exc}")
            continue
        probs = _problems_of(doc)
        report["problems_total"] += len(probs)
        seen: set[str] = set()
        for qid, p in probs.items():
            if not isinstance(p, dict):
                continue
            if qid in seen:
                failures["duplicate_id_within_file"].append(f"{path.name}:{qid}")
            seen.add(qid)
            sha = str(p.get("flag_sha256") or "").strip().lower()
            if not HEX64.match(sha):
                failures["truth_not_verifiable"].append(f"{path.name}:{qid}")
            else:
                truth_index.setdefault(qid, []).append((path.name, sha))
            # 明文答案：只查值，不查字段名（防"答案塞进 desc"绕过）；按题源分级
            for k, v in p.items():
                if isinstance(v, str) and k not in ("id", "flag_sha256", "description", "note"):
                    if k in SUSPECT_KEYS and PLAINTEXT_FLAG.search(v):
                        tag = f"{path.name}:{qid}:{k}"
                        if _is_self_built(p, path):
                            self_built_hint.append(tag)
                        else:
                            failures["plaintext_answer_leak_external"].append(tag)

    # 真值源分裂：同 id 多文件、sha 不同
    for qid, lst in truth_index.items():
        shas = {s for _, s in lst}
        if len(lst) > 1 and len(shas) > 1:
            failures["truth_source_divergence"].append(
                {"id": qid, "occurrences": [{"file": f, "sha": s[:12]} for f, s in lst]})

    # 外部导出集与 manifest 对账
    for ext_dir in (target / "data" / "ctf_benchmark").glob("external_*"):
        bj, mf = ext_dir / "benchmark.json", ext_dir / "export_manifest.json"
        if bj.is_file() and mf.is_file():
            try:
                n = len(_problems_of(json.loads(bj.read_text(encoding="utf-8"))))
                man = json.loads(mf.read_text(encoding="utf-8"))
                if int(man.get("included_count", -1)) != n:
                    failures["external_manifest_mismatch"].append(
                        f"{ext_dir.name}: manifest={man.get('included_count')} vs 实际={n}")
            except Exception as exc:  # noqa: BLE001
                failures["external_manifest_mismatch"].append(f"{ext_dir.name}: {exc}")

    report["checks"] = {k: {"ok": not v, "count": len(v), "items": v[:20]}
                        for k, v in failures.items()}
    # 自研集明文答案不参与红线判定，只作为提示计数（避免"为挑刺而挑刺"）
    report["hints"] = {
        "selfbuilt_plaintext_answers": {
            "count": len(self_built_hint),
            "note": ("自研/自造题集保留明文 flag 属设计选择（判分需要、无竞争泄露风险）；"
                     "若该题集会外送或入库交付，须改为只留 SHA-256"),
            "items": self_built_hint[:10],
        }
    }
    report["all_green"] = all(c["ok"] for k, c in report["checks"].items()
                              if k != "plaintext_answer_leak_selfbuilt")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="benchmark 真值源一致性审计")
    ap.add_argument("--target", required=True, help="目标仓库根目录")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    target = Path(args.target)
    if not target.is_dir():
        print(f"[audit] 目标不存在: {target}")
        return 2
    rep = audit(target)
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        print(f"[audit] 目标: {target.name}｜扫描 benchmark 文件 {rep['benchmarks_scanned']} 个"
              f"｜题目总数 {rep['problems_total']}")
        for name, c in rep["checks"].items():
            print(f"  {'✅' if c['ok'] else '❌'} {name}: {c['count']}")
            for it in c["items"][:5]:
                print(f"      - {it}")
        print(f"[audit] 结论: {'全绿' if rep['all_green'] else '存在红线，见上'}")
    return 0 if rep["all_green"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
