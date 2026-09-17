# -*- coding: utf-8 -*-
"""skip 审计工具（fail-closed）—— 让 pytest 的 skip 从"看不见"变"可审计"。

背景（跨项目硬教训 / 交接包 2026-09-17 P0-1）：
    pytest 的 t.Skip 会把"覆盖缺口"伪装成绿灯——SKIPPED 静默计入，
    CI 日志只剩"16 skipped"而看不出为什么跳。本项目实测 16 个 skip 全部是
    "数据集不入库 + 源不可得 / 真实 LLM 未开启"导致的诚实环境跳过，没有代码覆盖缺口。
    但"探测式 skip"（如 test_sandbox_guard 曾写的"未落地则 skip"）会在防护被误删时
    把测试从绿变 skip 而非红，反向掩盖回归。

本工具把"已知合理的 skip"白名单化，任何无法归类的新 skip 一律视为"可疑缺口"，
退出码非 0（fail-closed），逼 CI 关注——新出现的不可解释 skip 必红灯。

分类规则：
    data_missing : 数据/附件缺失（本地比赛数据 git 不入库、源不可得）→ 合法
    env_off      : 环境未开启（真实 LLM smoke / API key 未配置）→ 合法
    suspect      : 其他 → 可疑缺口，报警

用法：
    python scripts/_skip_audit.py                 写 logs/skip_audit_<date>.md
    python scripts/_skip_audit.py --check         仅校验无 suspect skip，挂 CI（退出码 0/1）
    python scripts/_skip_audit.py --tests-dir path 指定测试目录（默认 tests/）
"""
from __future__ import annotations

import argparse
import datetime as _dt
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # ctf_agent/

_SKIP_RE = re.compile(r"SKIPPED\s+\[\d+\]\s+(\S+?\.py):(\d+):\s*(.*)")
_SUMMARY_RE = re.compile(r"(\d+)\s+passed.*?(\d+)\s+skipped", re.IGNORECASE)

_DATA_KW = (
    "未解压", "不存在", "不在版本库", "本地保留", "附件",
    "race_extract", "race_attachments", "data/attachments", "data/answers",
)
_ENV_KW = ("未开启", "smoke", "api key", "无 api", "未配置", "未启用", "real llm")


def _categorize(reason: str) -> str:
    r = reason.lower()
    if any(k.lower() in r for k in _DATA_KW):
        return "data_missing"
    if any(k.lower() in r for k in _ENV_KW):
        return "env_off"
    return "suspect"


def run_pytest(tests_dir: str) -> str:
    cmd = [
        sys.executable, "-m", "pytest", tests_dir,
        "-rs", "--tb=no", "-q", "-p", "no:cacheprovider",
    ]
    proc = subprocess.run(
        cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=900
    )
    return proc.stdout + proc.stderr


def parse_skips(output: str) -> list[dict]:
    skips = []
    for m in _SKIP_RE.finditer(output):
        path, line, reason = m.group(1), int(m.group(2)), m.group(3).strip()
        skips.append({
            "path": path, "line": line, "reason": reason,
            "category": _categorize(reason),
        })
    return skips


def parse_summary(output: str):
    m = _SUMMARY_RE.search(output)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def build_report(skips: list[dict], summary):
    by_cat = {"data_missing": [], "env_off": [], "suspect": []}
    for s in skips:
        by_cat[s["category"]].append(s)

    out = []
    out.append("# Skip 审计报告 — %s\n" % _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if summary:
        out.append(
            "> pytest 汇总：%d passed / **%d skipped**（解析命中 %d 条 skip 记录）\n"
            % (summary[0], summary[1], len(skips))
        )
    else:
        out.append("> 未能从 pytest 输出解析汇总行，以解析命中为准\n")

    titles = {
        "data_missing": "数据/附件缺失（合法 skip：本地比赛数据 git 不入库、源不可得）",
        "env_off": "环境未开启（合法 skip：真实 LLM smoke / API key 未配置）",
        "suspect": "可疑缺口（无法归类 -> fail-closed 报警，需人工判定是否为代码覆盖缺口）",
    }
    for cat in ("data_missing", "env_off", "suspect"):
        items = by_cat[cat]
        out.append("\n## %s — %d 条\n" % (titles[cat], len(items)))
        if not items:
            out.append("_无_\n")
            continue
        out.append("| # | 测试文件:行 | 原因 |")
        out.append("|---|---|---|")
        for i, s in enumerate(items, 1):
            reason = s["reason"].replace("|", "\\|")
            out.append("| %d | `%s:%d` | %s |" % (i, s["path"], s["line"], reason))

    out.append("\n---\n")
    out.append(
        "**治理规约**：data_missing / env_off 为已知合法 skip（数据集不入库、"
        "真实 LLM 未开启），CI 静默跳过正确。任何 `suspect` 类 skip 出现即触发"
        "工具退出码非 0（fail-closed）——新增的不可解释 skip 必红灯，逼人工判定"
        "是否把覆盖缺口伪装成了绿灯。\n"
    )
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="pytest skip 审计（fail-closed）")
    ap.add_argument("--tests-dir", default="tests", help="测试目录（默认 tests/）")
    ap.add_argument("--check", action="store_true",
                    help="仅校验无 suspect skip，挂 CI（退出码 0/1）")
    args = ap.parse_args(argv)

    output = run_pytest(args.tests_dir)
    skips = parse_skips(output)
    summary = parse_summary(output)
    report = build_report(skips, summary)

    suspect = [s for s in skips if s["category"] == "suspect"]

    if args.check:
        if suspect:
            print("[skip_audit] FAIL-closed: %d 个无法归类的可疑 skip：" % len(suspect))
            for s in suspect:
                print("  - %s:%d  %s" % (s["path"], s["line"], s["reason"]))
            return 1
        print("[skip_audit] OK: 全部 %d 个 skip 已归类（无可疑缺口）" % len(skips))
        return 0

    logs_dir = ROOT / "logs"
    logs_dir.mkdir(exist_ok=True)
    report_path = logs_dir / ("skip_audit_%s.md" % _dt.datetime.now().strftime("%Y%m%d"))
    report_path.write_text(report, encoding="utf-8")
    print(report)
    print("\n报告已写入: %s" % report_path)

    # 非 --check 模式也暴露 suspect（但不强制非零退出，避免破坏既有 CI 习惯）
    if suspect:
        print("\n[skip_audit] 警告：%d 个 suspect skip（见报告第三节）" % len(suspect))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
