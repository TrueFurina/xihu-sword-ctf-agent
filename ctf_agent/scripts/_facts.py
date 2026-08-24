#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""机器事实采集器（2026-08-23）——单一事实源（Single Source of Truth）。

根治「文档手写状态断言 → 漂移」（三轮锐评裁定"写文档不查证，没有用实测校验
输出"）。关键状态——租约模式、G0-G4 落地、诚实口径门禁、HEAD——由本脚本从
**代码与 git 实时采集**，而非任何文档手写。文档里的状态表引用本 FACTS，不再
各自维护一份手写的、必然漂移的断言。

用法：
    python scripts/_facts.py            # 打印机器事实（stdout）
    python scripts/_facts.py --write    # 生成 ../deliverables/协同协议/FACTS.md
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACTS_PATH = os.path.abspath(os.path.join(ROOT, "..", "deliverables", "协同协议", "FACTS.md"))


def _has(path: str, needle: str) -> bool:
    """文件存在且含 needle 文本。"""
    if not os.path.isfile(path):
        return False
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return needle in f.read()
    except OSError:
        return False


def _git_head() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True,
        ).stdout
        return out.strip()
    except Exception:
        return ""


# ── 状态快照（--snapshot）：治「拿记忆当事实」──
# 防错三律第 1 条：凡陈述「当前是 X」，必须先跑本快照拿到当次输出。
# 聚合 provider 有效值 / HEAD / 工作树 / 租约全景 / 机器校验结果，全部实时采集。


def _effective_provider() -> str:
    """实际生效的 LLM provider：环境变量优先，否则 config.py 默认（baidu 千帆）。"""
    env = os.environ.get("CTF_AGENT_LLM_PROVIDER", "").strip()
    if env:
        return f"env={env}"
    try:
        with open(os.path.join(ROOT, "config.py"), encoding="utf-8", errors="ignore") as f:
            for line in f:
                # 匹配 `llm_provider: str = "baidu"`（类型注解）或 `llm_provider = "baidu"`
                m = re.match(r'\s*llm_provider\s*[:=][^"]*"([^"]+)"', line)
                if m:
                    return f"config默认={m.group(1)}"
    except OSError:
        pass
    return "unknown"


def _git_worktree_summary() -> str:
    """工作树状态摘要（git status --porcelain 计数）。"""
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, timeout=10,
        )
        text = out.stdout.decode("utf-8", errors="ignore")
    except Exception:
        return "unknown"
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return "clean"
    modified = sum(1 for l in lines if l[:2].strip() in ("M", "D", "A", "R", "C"))
    untracked = sum(1 for l in lines if l.startswith("??"))
    return f"{len(lines)} 处改动（tracked M/D/A={modified}，??={untracked}）"


def _lease_snapshot() -> str:
    """租约全景：谁持什么 scope、是否 stale。复用 _lease.load/is_stale。"""
    try:
        scripts = os.path.join(ROOT, "scripts")
        sys.path.insert(0, scripts)
        import _lease  # noqa: PLC0415 - 快照内局部导入，避免顶层依赖
        doc = _lease.load(_lease.COOR_DEFAULT)
    except Exception:
        return "（coordination.json 不可读或无租约）"
    if not doc:
        return "（无租约文件）"
    leases = doc.get("leases") or {}
    if not leases:
        return "（无存活租约）"
    parts = []
    for sid, l in leases.items():
        scope = ",".join(l.get("scope", []) or [])
        try:
            stale = _lease.is_stale(l)
        except Exception:
            stale = False
        la_raw = l.get("last_active")
        if isinstance(la_raw, str):
            la = la_raw.replace("T", " ")[:19]
        elif isinstance(la_raw, (int, float)):
            la = time.strftime("%Y-%m-%d %H:%M", time.localtime(la_raw))
        else:
            la = "?"
        parts.append(f"{sid}[{scope}]{'STALE' if stale else ''}@{la}")
    return "; ".join(parts)


def _run_check(script: str, args: list) -> str:
    """跑一个机器校验脚本，返回 OK/FAIL。"""
    try:
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", script)] + args,
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        if out.returncode == 0:
            return "OK"
        first = (out.stdout or out.stderr or "").strip().splitlines()
        return f"FAIL({out.returncode})" + (f" {first[0][:80]}" if first else "")
    except Exception as exc:  # noqa: BLE001
        return f"ERR({exc})"


def render_snapshot() -> str:
    """生成实时状态快照（文本，供会话引用为「当前状态」的唯一来源）。"""
    head = _git_head()
    lines = [
        "═══ 状态快照（机器实时采集，勿用记忆替代）═══",
        f"生成时间 : {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"provider  : {_effective_provider()}",
        f"HEAD      : {head or '（无 commit）'}",
        f"工作树    : {_git_worktree_summary()}",
        f"租约      : {_lease_snapshot()}",
        f"机器校验  : 文档一致性 {_run_check('_doc_consistency.py', [])} · "
        f"诚实口径 {_run_check('_honesty_scan.py', [])}",
        "═══ 快照结束（引用状态时以上述输出为准）═══",
    ]
    return "\n".join(lines)


def collect_facts() -> dict:
    """从代码与 git 实时采集关键事实（不信任任何文档）。"""
    scripts = os.path.join(ROOT, "scripts")
    lease_mode = "multi" if _has(os.path.join(scripts, "_lease.py"), "def scopes_conflict") else "single"
    return {
        "lease_mode": lease_mode,
        "g1_landed": lease_mode == "multi",
        "g2_landed": _has(os.path.join(scripts, "_sign.py"), "def init_session"),
        "g3_landed": os.path.isfile(os.path.join(scripts, "_closeout.py")),
        "g4_landed": _has(os.path.join(scripts, "_coupling_cluster.py"), "def cluster_average_linkage"),
        "honesty_gate": os.path.isfile(os.path.join(scripts, "_honesty_scan.py")),
        "doc_consistency": os.path.isfile(os.path.join(scripts, "_doc_consistency.py")),
        "git_bind": _has(os.path.join(scripts, "_sign.py"), "def bind_author"),
        "task_board": os.path.isfile(os.path.join(scripts, "_task_board.py")),
        "reviewer_gate": os.path.isfile(os.path.join(scripts, "_reviewer_gate.py")),
        "head": _git_head(),
    }


def render_md(facts: dict) -> str:
    def yn(b): return "✅ 已落地" if b else "⏳ 未落地"
    return f"""# FACTS.md · 机器事实源（勿手写，用 `scripts/_facts.py --write` 重新生成）

> 本文件由 `scripts/_facts.py` 从代码与 git 实时采集生成，是协同状态的**单一事实源**。
> 任何文档要引用「租约模式 / G0-G4 落地 / 门禁状态 / HEAD」，一律以本文件为准，不得手写。
> 生成时间由采集脚本输出；手工编辑本文件无效，下次 `--write` 会被覆盖。

## 核心状态（机器采集）

| 状态 | 值 | 采集依据 |
|---|---|---|
| 租约模式 | {facts["lease_mode"]}（{'目录级多写者' if facts["lease_mode"] == 'multi' else '全局单写者'}） | `_lease.py` 是否含 `scopes_conflict` |
| G1 目录级多写者租约 | {yn(facts["g1_landed"])} | 同上（lease_mode == multi） |
| G2 会话唯一 ID 登记 | {yn(facts["g2_landed"])} | `_sign.py` 是否含 `init_session` |
| G3 收尾脚本 | {yn(facts["g3_landed"])} | `_closeout.py` 是否存在 |
| G4 写耦合度聚类 | {yn(facts["g4_landed"])} | `_coupling_cluster.py` 是否含 `cluster_average_linkage` |
| 诚实口径门禁 | {yn(facts["honesty_gate"])} | `_honesty_scan.py` 是否存在 |
| 文档一致性门禁 | {yn(facts["doc_consistency"])} | `_doc_consistency.py` 是否存在 |
| git 身份绑定（P1-7） | {yn(facts["git_bind"])} | `_sign.py` 是否含 `bind_author` |
| 声明式任务板（T-09） | {yn(facts["task_board"])} | `_task_board.py` 是否存在 |
| Reviewer 验收门禁（T-10） | {yn(facts["reviewer_gate"])} | `_reviewer_gate.py` 是否存在 |
| 当前 HEAD | `{facts["head"]}` | `git rev-parse --short HEAD` |

## 为什么需要本文件

三轮锐评的裁定是「写文档不查证」。根因：文档**手写**状态断言（如「单写者全局租约」），
落地后没回写，就从「诚实说明」漂移成「过时谎言」。本文件让状态**由机器采集、由文档引用**，
从机制上杜绝这类漂移。
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="机器事实采集器（单一事实源 + 状态快照）")
    ap.add_argument("--write", action="store_true", help=f"生成 {FACTS_PATH}")
    ap.add_argument("--snapshot", action="store_true", help="输出实时状态快照（会话开工/状态断言前必跑）")
    args = ap.parse_args()

    if args.snapshot:
        print(render_snapshot())
        return 0

    facts = collect_facts()
    if args.write:
        os.makedirs(os.path.dirname(FACTS_PATH), exist_ok=True)
        with open(FACTS_PATH, "w", encoding="utf-8") as f:
            f.write(render_md(facts))
        print(f"✅ 已生成单一事实源：{FACTS_PATH}")
        return 0
    for k, v in facts.items():
        print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
