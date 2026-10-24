#!/usr/bin/env python
"""覆盖率门禁：只防倒退，不追求高覆盖（2026-10-21）。

**口径声明（先结论）**
--------------------
本门禁的判据是「**不许比上次实测更低**」，不是「达到某个理想值」。
37% 的整体覆盖率对一个 CTF 自动解题系统来说很低，但把阈值定在 60% 只会
得到一个天天红的门禁，然后被人整段注释掉——那才是真正的门禁失效
（同 `check_corpus_health.py` 的 77 道历史坏题同理）。

所以：阈值 = 实测基线向下取整到 5 的倍数再减 5，留出正常波动余量。
要抬高基线，只能先真的把覆盖率做上去，再改 `pyproject.toml` 里的数字——
改动必须是一笔可 review 的 diff，不能靠"顺手放宽"。

**为什么单模块也设阈值**
----------------------
整体 37% 会被高覆盖的大模块掩盖：`main_agent` 75% 拉高均值，
`rea_probe` 49% 的塌陷在均值里看不见。单模块阈值专治这种「结构性下陷」。

**fail-closed**
---------------
coverage.json 缺失 / 字段不全 / 数值非数 → 返回 2（无法判定 ≠ 通过）。
退出码：0 通过 / 1 有模块低于阈值 / 2 无法判定。

用法：
    python scripts/_gate_coverage.py --measure          # 先跑 pytest 再判
    python scripts/_gate_coverage.py                    # 读已有 coverage.json
    python scripts/_gate_coverage.py --report x.json    # 指定报告
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORT = ROOT / "coverage.json"
PYPROJECT = ROOT / "pyproject.toml"


def load_thresholds() -> dict:
    """从 pyproject.toml 读阈值（单一真源，不在脚本里硬编码数字）。"""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    cfg = (data.get("tool") or {}).get("ctf_coverage_gate") or {}
    return {
        "total": cfg.get("total"),
        "modules": cfg.get("modules") or {},
        "metric": cfg.get("metric", "percent_covered"),
    }


def measure(timeout_s: int = 1800) -> int:
    """跑全量默认门禁并产出 coverage.json。返回子进程退出码。"""
    cmd = [
        sys.executable, "-m", "pytest", "-q",
        "-m", "not slow and not local",
        "-p", "no:cacheprovider",
        "--cov=.", "--cov-report=json:" + str(DEFAULT_REPORT),
        "--cov-report=term:skip-covered",
    ]
    print(f"[cov] 运行: {' '.join(cmd[:6])} …（约 7 分钟）")
    try:
        p = subprocess.run(cmd, cwd=ROOT, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        print(f"[cov] ❌ pytest 超时（>{timeout_s}s）")
        return 2
    return p.returncode


def _pct(entry: dict, metric: str) -> float | None:
    val = entry.get(metric)
    return float(val) if isinstance(val, (int, float)) else None


def check(report_path: Path) -> dict:
    """核对报告覆盖率与阈值。返回 {passed, rc, rows, reason}。"""
    if not report_path.is_file():
        return {"passed": False, "rc": 2, "rows": [],
                "reason": f"覆盖率报告不存在：{report_path}（先跑 --measure）"}
    try:
        rep = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"passed": False, "rc": 2, "rows": [],
                "reason": f"覆盖率报告无法解析：{exc}"}

    th = load_thresholds()
    metric = th["metric"]
    if th["total"] is None:
        return {"passed": False, "rc": 2, "rows": [],
                "reason": "pyproject.toml 缺 [tool.ctf_coverage_gate].total，"
                          "阈值无真源 → 无法判定"}

    rows: list[dict] = []
    problems: list[str] = []

    # ① 整体覆盖率
    total = _pct(rep.get("totals") or {}, metric)
    if total is None:
        return {"passed": False, "rc": 2, "rows": [],
                "reason": f"报告缺 totals.{metric}（字段名变更？）→ 无法判定"}
    rows.append({"name": "<整体>", "actual": total, "floor": th["total"],
                 "ok": total >= th["total"]})
    if total < th["total"]:
        problems.append(f"整体 {total:.1f}% < 阈值 {th['total']}%")

    # ② 单模块覆盖率（键为仓库相对路径）
    files = rep.get("files") or {}
    for rel, floor in th["modules"].items():
        key = rel.replace("\\", "/")
        entry = files.get(key)
        if entry is None:
            # 找不到文件 = 路径写错或模块已删/改名 → 不能静默通过
            rows.append({"name": key, "actual": None, "floor": floor,
                         "ok": False, "missing": True})
            problems.append(f"{key} 不在覆盖率报告里（路径错/已删除）")
            continue
        actual = _pct(entry.get("summary") or {}, metric)
        if actual is None:
            rows.append({"name": key, "actual": None, "floor": floor,
                         "ok": False, "missing": True})
            problems.append(f"{key} 缺 summary.{metric}")
            continue
        ok = actual >= floor
        rows.append({"name": key, "actual": actual, "floor": floor, "ok": ok})
        if not ok:
            problems.append(f"{key} {actual:.1f}% < 阈值 {floor}%")

    passed = not problems
    return {
        "passed": passed,
        "rc": 0 if passed else 1,
        "rows": rows,
        "problems": problems,
        "metric": metric,
        "n_files": len(files),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="覆盖率门禁（只防倒退）")
    ap.add_argument("--measure", action="store_true",
                    help="先跑 pytest --cov 产出报告，再判阈值")
    ap.add_argument("--report", default=str(DEFAULT_REPORT), help="覆盖率 JSON 路径")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    args = ap.parse_args()

    if args.measure:
        rc = measure()
        # pytest 有失败用例时 rc=1：报告仍会写出，阈值照样要判——
        # 但用例失败本身已经是另一道闸门的事，这里只提示不吞掉。
        if rc not in (0, 1):
            print(f"[cov] ❌ 覆盖率采集失败（pytest rc={rc}）")
            return 2

    res = check(Path(args.report))

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return res["rc"]

    for r in res["rows"]:
        if r["actual"] is None:
            print(f"  💥 {r['name']:36s} 读数缺失（阈值 {r['floor']}%）")
        else:
            mark = "✅" if r["ok"] else "❌"
            print(f"  {mark} {r['name']:36s} {r['actual']:6.1f}%  阈值 {r['floor']}%")
    if res.get("reason"):
        print(f"  ⚠️  {res['reason']}")
    for p in res.get("problems", []):
        print(f"      · {p}")
    print("覆盖率门禁：" + ("通过（无倒退）" if res["passed"] else "未通过"))
    return res["rc"]


if __name__ == "__main__":
    sys.exit(main())
