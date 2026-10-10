#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KPI 分母口径守卫（denominator guard，2026-10-11）。

根因
----
同一个真题池 `data/questions_real/` 在代码库里被**三种不同口径**枚举，三者结果不等：

| 取题处 | 口径 | 结果 |
|---|---|---|
| `eval/cases.py:load_questions` | `rglob("*.json")` + 排除 _attachments/answers 等目录名 | 含非 `real_` 前缀题 |
| `scripts/verify_real_questions.py:main` | `glob("**/real_*.json")` 前缀过滤 | **漏掉非 `real_` 前缀题** |
| `scripts/_kpi_canonical.py:count_real_corpus` | `rglob("*.json")` 全含（含 _attachments） | 与 cases.py 在存在附件 json 时会分叉 |

后果有两个方向的风险：
1. **文档漂移**：治理文件声称的题数与实跑分母不一致，而 AGENTS.md 是 KPI 唯一真值源。
2. **保障逃逸**：某道题被实跑链路（`cases.py`）计入分母，却**从不进入**
   `verify_real_questions.py` 的回归保障（flag/附件/sha256 一致性检查），
   因为它不满足 `real_` 前缀约定——即「在分母里、不在保护里」。

本守卫不修改任何既有逻辑，只做**只读度量 + 交叉比对**，并把差异打成机器可读证据。
按「口径先行」原则，本脚本只负责**检出**差异并给出机器可读证据，
修复方案（改取题口径 or 给题文件补 `real_` 前缀）属于治理决策，不在脚本内擅自执行。

用法：
    python scripts/_denominator_guard.py                    # 报告模式（默认）
    python scripts/_denominator_guard.py --json             # 机器可读输出
    python scripts/_denominator_guard.py --strict           # 漂移存在即 exit 1（CI/门禁）
    python scripts/_denominator_guard.py --save             # 落盘 data/results/denominator_guard_<date>.json

退出码：0 = 无漂移（或仅报告模式）；1 = --strict 下检出漂移；2 = 运行异常。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # ctf_agent/
QS_REAL = ROOT / "data" / "questions_real"
RESULTS_DIR = ROOT / "data" / "results"

# 与 eval/cases.py 保持一致的排除目录名（小写）
EXCLUDED_DIRS = {"_attachments", "answers", "_answers", "_keys", "_solutions"}

# 治理文件中声称题数的抓取规则：(文件相对 ctf_agent 的路径, 正则, 语义标签)
CLAIM_PATTERNS = [
    ("../ctf_agent/AGENTS.md", r"questions_real/`（\*\*(\d+)\s*道", "AGENTS.md KPI 章节声称题数"),
    ("../README.md", r"\*\*(\d+)\s*道\*\*历年真题", "README 声称题数"),
]


def enumerate_by_cases_rule(qs_real: Path | None = None) -> list[Path]:
    """口径 A：eval/cases.py 实跑链路（排除附件目录）。"""
    base = qs_real or QS_REAL
    out = []
    for p in sorted(base.rglob("*.json")):
        parts = {x.lower() for x in p.relative_to(base).parts[:-1]}
        if parts & EXCLUDED_DIRS:
            continue
        out.append(p)
    return out


def enumerate_by_current_guard_rule(qs_real: Path) -> list[Path]:
    """口径 B（权威）：**直接调用** `verify_real_questions.iter_question_files`。

    刻意不在这份守卫里重抄一遍枚举规则——重抄就会分叉，分叉正是本次事故的成因。
    口径必须只有一个可执行定义；守卫的角色是「比对」，不是「第二实现」。
    """
    sys.path.insert(0, str(ROOT))
    try:
        from scripts.verify_real_questions import iter_question_files  # type: ignore
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] 无法加载 verify_real_questions（{exc}），口径 B 退化为旧前缀规则",
              file=sys.stderr)
        return [p for p in qs_real.rglob("*.json") if p.name.startswith("real_")]
    return [Path(p) for p in iter_question_files(str(qs_real))]


def enumerate_by_legacy_prefix_rule(qs_real: Path) -> list[Path]:
    """口径 B-legacy：修复前的 real_ 前缀规则，仅用于复现历史读数做回归对照。"""
    return sorted(p for p in qs_real.rglob("*.json") if p.name.startswith("real_"))


def enumerate_by_kpi_rule(qs_real: Path | None = None) -> list[Path]:
    """口径 C：_kpi_canonical.count_real_corpus（全量 rglob，不排除任何目录）。"""
    base = qs_real or QS_REAL
    return sorted(p for p in base.rglob("*.json") if p.is_file())


def scan_claims() -> list[dict]:
    """从治理文档抓取声称的题数（手写数字的唯一合法来源是仓库锚点，不是本脚本）。"""
    claims = []
    for rel, pat, label in CLAIM_PATTERNS:
        fp = (ROOT / rel).resolve()
        if not fp.exists():
            continue
        text = fp.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(pat, text):
            claims.append({"source": label, "file": rel, "value": int(m.group(1))})
    return claims


def load_health(qs_real: Path) -> dict | None:
    """复用既有题库健康度审计器，避免重复发明分层逻辑。失败返回 None（不影响主度量）。"""
    sys.path.insert(0, str(ROOT))
    try:
        from scripts._audit_corpus_integrity import audit  # type: ignore
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] 无法加载 _audit_corpus_integrity（{exc}），跳过健康分层", file=sys.stderr)
        return None
    try:
        # CWD 稳定化：既有审计器用相对路径解析附件（如 data/race_attachments/...），
        # 其结果随运行时 CWD 变化——同一题库在不同目录启动会得到不同健康分层。
        # 这里统一切到题库的上两级（ctf_agent 级）再调用，保证读数与 CWD 无关。
        _old_cwd = os.getcwd()
        try:
            os.chdir(qs_real.parent.parent)
            rep = audit(qs_real)
        finally:
            os.chdir(_old_cwd)
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] 健康审计运行失败（{exc}），跳过", file=sys.stderr)
        return None
    return {
        "total": rep.get("total"),
        "usable_for_reasoning": rep.get("usable_for_reasoning"),
        "by_level": rep.get("by_level", {}),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="KPI 分母口径守卫")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--strict", action="store_true", help="检出漂移即退出码 1")
    ap.add_argument("--save", action="store_true", help="落盘 data/results/")
    ap.add_argument("--questions-dir", default=None,
                    help="题库目录（默认 data/questions_real）。跨 worktree 车道验收时，"
                         "因 data/race_attachments、data/questions_real/_attachments 未入库，"
                         "车道内健康分层读数会失真，须用本参数指向主工作树的真实数据目录")
    args = ap.parse_args()
    qs_real = Path(args.questions_dir).resolve() if args.questions_dir else QS_REAL

    if not qs_real.is_dir():
        print(f"[error] 题库目录不存在: {qs_real}", file=sys.stderr)
        return 2

    A = enumerate_by_cases_rule(qs_real)
    B = enumerate_by_current_guard_rule(qs_real)      # 回归保障的**真实当前**口径
    B_legacy = enumerate_by_legacy_prefix_rule(qs_real)  # 修复前口径（历史读数对照）
    C = enumerate_by_kpi_rule(qs_real)

    only_in_A = [str(p.relative_to(qs_real)) for p in A if p not in set(B)]
    only_in_C = [str(p.relative_to(qs_real)) for p in C if p not in set(A)]

    # 口径 C 与 A 的差异，只可能是存在于被排除目录中的 json（附件残留）
    att_json = [str(p.relative_to(qs_real)) for p in C if p not in set(A)]

    claims = scan_claims()
    health = load_health(qs_real)

    drifts: list[dict] = []
    for claim in claims:
        if claim["value"] != len(A):
            drifts.append({
                "type": "doc_vs_runtime_denominator",
                "source": claim["source"],
                "file": claim["file"],
                "claimed": claim["value"],
                "runtime_cases_rule": len(A),
                "diff": len(A) - claim["value"],
            })
    if only_in_A:
        drifts.append({
            "type": "unguarded_questions",
            "detail": "计入实跑分母但被 verify_real_questions.py 的 real_ 前缀规则排除",
            "files": only_in_A,
        })

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "root": str(qs_real),
        "universes": {
            "A_cases_rglob_excl_attachments": len(A),
            "B_verify_current": len(B),
            "B_legacy_real_prefix": len(B_legacy),
            "C_kpi_canonical_rglob_all": len(C),
        },
        "divergent": {
            "in_A_not_in_B": only_in_A,
            "in_C_not_in_A": only_in_C,
            "attachment_json_excluded_by_A": att_json,
        },
        "document_claims": claims,
        "health": health,
        "drifts": drifts,
        "note": "本守卫只读度量，不修改任何文件；修复方案交由治理决策。",
    }

    if args.save:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out = RESULTS_DIR / f"denominator_guard_{datetime.now():%Y%m%d}.json"
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        report["saved_to"] = str(out)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        u = report["universes"]
        print("══ KPI 分母口径守卫 ══")
        print(f"口径 A（eval/cases.py 实跑，排除附件目录）      : {u['A_cases_rglob_excl_attachments']}")
        print(f"口径 B（verify_real_questions.py 当前真实口径）: {u['B_verify_current']}")
        print(f"口径 B-legacy（修复前 real_ 前缀，仅作对照）   : {u['B_legacy_real_prefix']}")
        print(f"口径 C（_kpi_canonical.count_real_corpus 全量） : {u['C_kpi_canonical_rglob_all']}")
        if health:
            print(f"健康分层（复用既有审计器）                      : {health['by_level']}，"
                  f"可用于推理 {health['usable_for_reasoning']}")
        print("\n── 差异明细 ──")
        print(f"  在 A 但不在 B（分子有了、保障没跟上）: {len(only_in_A)}")
        for f in only_in_A:
            print(f"     - {f}")
        print(f"  C 比 A 多出（附件残留 json，已被 A 正确排除）: {len(only_in_C)}")
        for f in only_in_C[:5]:
            print(f"     - {f}")
        print("\n── 文档声称值 ──")
        for c in claims:
            mark = "❌ 漂移" if c["value"] != len(A) else "✅ 一致"
            print(f"  {c['source']}: 声称 {c['value']} vs 实跑 {len(A)}  {mark}")
        print("\n── 结论 ──")
        if not drifts:
            print("  ✅ 未检出分母口径漂移")
        else:
            print(f"  ❌ 检出 {len(drifts)} 类漂移（详见 --json）")

    if args.strict and drifts:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
