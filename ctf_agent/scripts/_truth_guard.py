#!/usr/bin/env python
"""机器真值写入守卫（2026-10-10）：`benchmarks/` 下所有 JSON 必须受 schema 保护。

事故背景
---------
`benchmarks/` 下的文件全是**机器真值**（基准清单、健康基线、provider 能力档案），
但此前**没有任何统一的写入保护**——每个脚本自己 `write_text`，各写各的：

1. v1 探针档案与 v2 归档档案**共用** `provider_capability.json`，v2 跑一次就把 v1
   的探针数据整段覆盖（解析失败/兜底/步数全失），工作树上无声丢数据。
2. `corpus_health_baseline.json` **根本没有 `schema` 字段**——一份机器真值完全
   不受任何保护，谁都能覆盖，且覆盖后无法判断"这份数据是哪一版规则产生的"。

这类事故的共同形态：**同一路径被不同写入方先后使用，后跑的赢，先跑的结论无声消失**，
且事后无法从文件本身分辨"这是谁写的"。

本守卫把纪律从"每个脚本各自记得"搬到**统一入口**：
任何脚本写 `benchmarks/**/*.json` 前先 `write_truth()`，由它做 schema 登记与冲突拦截。

规则
----
1. **每个真值文件必须有 `schema` 字段**（`<名字>/v<版本>` 形式），否则写入拒绝。
2. **异构 schema 拒写**（退出码 4）：`old_schema != new_schema` 时不写。
3. **同 schema 允许刷新**（机器真值本来就要能更新），但自动追加 `written_at`
   与 `written_by`（git HEAD + 脚本名），使"这份数据什么时候、谁产生的"可追溯。
4. **`questions/` 下的题目 JSON 不走本守卫**——它们是逐题载荷、由基准构建器
   成批生成，每题结构相同但无 schema 字段；它们的完整性由
   `scripts/_build_external_benchmark.py --check` 负责。

用法
----
    from _truth_guard import write_truth, TruthWriteRefused
    write_truth(ROOT / "benchmarks" / "provider_probe.json",
                doc, schema="provider_capability/v1", by="scripts/_provider_toolcap_probe.py")

    # 审计模式：只报有哪些真值文件缺 schema / 有未登记的写入方
    python scripts/_truth_guard.py --audit
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = ROOT / "benchmarks"

# 退出码（专属，不与其它失败原因撞车——见 2026-10-10 教训）
RC_OK = 0
RC_AUDIT_FINDINGS = 1
RC_REFUSED = 4


# schema 必须严格形如 name/vN：恰好一个斜杠、版本段以 v 开头
SCHEMA_RE = re.compile(r"^[A-Za-z0-9_\-]+/v[0-9]+$")


class TruthWriteRefused(Exception):
    """拒绝写入机器真值文件（schema 冲突 / 缺 schema / 路径不在 benchmarks 下）。"""


def _git_head() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def write_truth(path: Path, doc: dict, schema: str, by: str = "",
                strict_path: bool = True) -> Path:
    """统一写入口：登记 schema、拦截异构覆盖、写入可追溯元信息。

    参数
    ----
    path: 目标文件（必须在 benchmarks/ 下，strict_path=True 时）
    doc:  要写的 JSON 对象
    schema: 本次写入的 schema 标识，必须形如 `name/vN`
    by:    写入方标识（脚本路径），落进 written_by 便于溯源
    strict_path: 是否强制路径在 benchmarks/ 下（测试可关掉）

    行为
    ----
    - 目标不存在 → 直接写
    - 目标存在且无 `schema` 字段 → **拒写**（无法判断这是哪一版规则的产物）
    - 目标存在且 schema 不同 → **拒写**（异构覆盖）
    - 目标存在且 schema 相同 → 刷新，并补 `written_at` / `written_by` / `git_head`
    """
    path = Path(path)
    if strict_path:
        try:
            path.resolve().relative_to(BENCHMARKS.resolve())
        except ValueError:
            raise TruthWriteRefused(
                f"拒绝写入 benchmarks/ 之外的路径: {path}——机器真值必须集中在 "
                f"{BENCHMARKS}，散落各处正是覆盖事故的成因")
    if not SCHEMA_RE.match(str(schema or "")):
        raise TruthWriteRefused(
            f"缺 schema 或 schema 格式不对: {schema!r}（须形如 name/vN，"
            f"恰好一个斜杠且版本段以 v 开头）——"
            f"没有合法 schema 的真值文件无法分辨版本，覆盖后不可追溯")

    if path.is_file():
        try:
            old = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            old = None
        if isinstance(old, dict):
            old_schema = old.get("schema")
            if not old_schema:
                raise TruthWriteRefused(
                    f"拒绝对无 schema 的既有文件做覆盖: {path.name}——"
                    f"先人工确认它的来源并补 schema，再改由本守卫写入")
            if old_schema != schema:
                raise TruthWriteRefused(
                    f"拒绝异构覆盖: {path.name} 现有 schema={old_schema!r}，"
                    f"本次要写 {schema!r}。两种真值必须用不同文件名")

    doc = dict(doc)
    doc["schema"] = schema
    doc["written_at"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    doc["written_by"] = by or "(unknown writer)"
    doc["git_head"] = _git_head()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def audit() -> dict:
    """审计 benchmarks/ 下的真值文件：谁有 schema、谁没有、schema 是否重复。"""
    rows, no_schema, by_schema = [], [], {}
    for f in sorted(BENCHMARKS.rglob("*.json")):
        if "questions" in f.parts:      # 逐题载荷由基准构建器 --check 负责
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            rows.append({"file": str(f.relative_to(ROOT)), "error": str(exc)})
            continue
        s = d.get("schema") if isinstance(d, dict) else None
        rel = str(f.relative_to(ROOT))
        if not s:
            no_schema.append(rel)
        else:
            by_schema.setdefault(s, []).append(rel)
        rows.append({
            "file": rel, "schema": s,
            "written_at": d.get("written_at") if isinstance(d, dict) else None,
            "written_by": d.get("written_by") if isinstance(d, dict) else None,
        })
    return {
        "truth_files": rows,
        "files_without_schema": no_schema,
        "schema_collisions": {k: v for k, v in by_schema.items() if len(v) > 1},
        "all_have_schema": not no_schema,
        "no_collision": not any(len(v) > 1 for v in by_schema.values()),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="机器真值写入守卫 / 审计")
    ap.add_argument("--audit", action="store_true",
                    help="只审计 benchmarks/ 下的真值文件（缺 schema / schema 撞车）")
    ap.add_argument("--migrate-legacy", action="store_true",
                    help="给无 schema 的历史真值文件补 schema（需逐个指定映射）")
    ap.add_argument("--migrate", nargs=2, metavar=("FILE", "SCHEMA"),
                    help="对单个文件补 schema：--migrate benchmarks/x.json name/v1")
    args = ap.parse_args()

    if args.migrate:
        f = Path(args.migrate[0])
        if not f.is_absolute():
            f = ROOT / f
        if not f.is_file():
            print(f"[truth-guard] 文件不存在: {f}")
            return RC_AUDIT_FINDINGS
        d = json.loads(f.read_text(encoding="utf-8"))
        if d.get("schema"):
            print(f"[truth-guard] {f.name} 已有 schema={d['schema']!r}，无需迁移")
            return RC_OK
        d["schema"] = args.migrate[1]
        d.setdefault("written_at", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
        d.setdefault("written_by", "scripts/_truth_guard.py --migrate")
        d["git_head"] = _git_head()
        f.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"[truth-guard] 已为 {f.name} 补 schema={args.migrate[1]!r}")
        return RC_OK

    if args.migrate_legacy:
        rep = audit()
        if not rep["files_without_schema"]:
            print("[truth-guard] 无需迁移：全部真值文件已有 schema")
            return RC_OK
        print("[truth-guard] 以下文件缺 schema，需逐个确认来源后用 --migrate 补：")
        for f in rep["files_without_schema"]:
            print(f"  {f}")
        return RC_AUDIT_FINDINGS

    if not args.audit:
        print(__doc__)
        print("用法：脚本应 import 本模块并调用 write_truth()；"
              "本脚本只提供 --audit 模式。")
        return RC_OK

    rep = audit()
    print(f"[truth-guard] 真值文件 {len(rep['truth_files'])} 个")
    for r in rep["truth_files"]:
        flag = "OK " if r.get("schema") else "缺!"
        print(f"  {flag} {r['file']:52s} schema={r.get('schema') or '(无)'}")
    findings = []
    if rep["files_without_schema"]:
        findings.append(f"无 schema: {rep['files_without_schema']}")
    if rep["schema_collisions"]:
        findings.append(f"schema 撞车（两文件同 schema，必有一方在覆盖）: "
                        f"{rep['schema_collisions']}")
    for f in findings:
        print(f"[truth-guard] ❌ {f}")
    if not findings:
        print("[truth-guard] ✅ 全部真值文件有唯一 schema")
        return RC_OK
    return RC_AUDIT_FINDINGS


if __name__ == "__main__":
    raise SystemExit(main())
