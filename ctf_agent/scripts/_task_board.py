#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""声明式任务板（T-09，2026-08-23）。

白皮书 §7 设计：反共识「不上全职 LLM Orchestrator」——编排器是成本中心（Anthropic
15× token 的「编排者开销」主因）。改用**声明式任务板 + 薄脚本**：任务板只声明
「要做什么 / 谁认领 / 什么状态」，会话自己看板认领，无需中央调度器派单。

数据：tasks/ 目录，每任务一个 <id>.json。认领靠**乐观并发**——claim 前检查状态
为 ready 才原子置为 claimed（原子写），跨会话的最终仲裁交给 git 的 non-fast-forward
拒绝（后提交者失败，pull --rebase 后重读任务板再认领，最多 3 次，对应 GNAP 先例）。

状态机（合法转移）：
    backlog → ready → claimed → in_progress → review → done
                 └→ cancelled          ├→ blocked
                                       └→ cancelled
    blocked → in_progress / cancelled
    review → done / in_progress（打回）

用法：
    python scripts/_task_board.py list
    python scripts/_task_board.py add --id T-xx --title <标题> --scope <scope...>
    python scripts/_task_board.py claim <id> --session <sid>
    python scripts/_task_board.py update <id> --status <s> --session <sid>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List, Optional, Set

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TASKS_DIR = os.path.join(ROOT, "tasks")

# 合法状态转移（from -> {to...}）
VALID_TRANSITIONS = {
    "backlog": {"ready"},
    "ready": {"claimed", "cancelled"},
    "claimed": {"in_progress", "cancelled"},
    "in_progress": {"review", "blocked", "cancelled"},
    "review": {"done", "in_progress"},
    "blocked": {"in_progress", "cancelled"},
    "done": set(),
    "cancelled": set(),
}
ALL_STATUSES: Set[str] = set(VALID_TRANSITIONS)


def _task_path(task_id: str, tasks_dir: str) -> str:
    return os.path.join(tasks_dir, f"{task_id}.json")


def load_task(task_id: str, tasks_dir: Optional[str] = None):
    td = tasks_dir or DEFAULT_TASKS_DIR
    try:
        with open(_task_path(task_id, td), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _write_task(task_id: str, doc: dict, tasks_dir: str) -> None:
    os.makedirs(tasks_dir, exist_ok=True)
    tmp = _task_path(task_id, tasks_dir) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, _task_path(task_id, tasks_dir))  # 原子写（防并发半写）


def add_task(task_id: str, title: str, scopes: List[str], tasks_dir: Optional[str] = None) -> dict:
    td = tasks_dir or DEFAULT_TASKS_DIR
    if load_task(task_id, td):
        raise ValueError(f"任务 {task_id} 已存在")
    doc = {
        "id": task_id, "title": title, "scope": list(scopes),
        "status": "backlog", "claimed_by": None, "claimed_at": None,
        "reviewer": None, "result": None,
    }
    _write_task(task_id, doc, td)
    return doc


def transition_allowed(frm: str, to: str) -> bool:
    """状态机校验：frm → to 是否合法。"""
    return to in VALID_TRANSITIONS.get(frm, set())


def claim_task(task_id: str, session: str, tasks_dir: Optional[str] = None) -> dict:
    """认领任务（ready → claimed）。乐观并发：非 ready 即拒（后认领者失败）。"""
    td = tasks_dir or DEFAULT_TASKS_DIR
    doc = load_task(task_id, td)
    if not doc:
        raise ValueError(f"任务 {task_id} 不存在")
    if doc["status"] != "ready":
        raise ValueError(f"任务 {task_id} 状态为 {doc['status']}，不可认领（须 ready）")
    doc["status"] = "claimed"
    doc["claimed_by"] = session
    doc["claimed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _write_task(task_id, doc, td)
    return doc


def update_status(task_id: str, status: str, session: str, tasks_dir: Optional[str] = None) -> dict:
    """更新状态（校验合法转移 + 持有者权限）。"""
    td = tasks_dir or DEFAULT_TASKS_DIR
    doc = load_task(task_id, td)
    if not doc:
        raise ValueError(f"任务 {task_id} 不存在")
    if status not in ALL_STATUSES:
        raise ValueError(f"非法状态 {status}，合法：{sorted(ALL_STATUSES)}")
    if not transition_allowed(doc["status"], status):
        raise ValueError(f"非法转移：{doc['status']} → {status}")
    if doc["claimed_by"] and doc["claimed_by"] != session:
        raise ValueError(f"任务 {task_id} 由 {doc['claimed_by']} 持有，{session} 无权改")
    doc["status"] = status
    _write_task(task_id, doc, td)
    return doc


def list_tasks(tasks_dir: Optional[str] = None) -> List[dict]:
    td = tasks_dir or DEFAULT_TASKS_DIR
    if not os.path.isdir(td):
        return []
    tasks = []
    for fn in sorted(os.listdir(td)):
        if fn.endswith(".json"):
            doc = load_task(fn[:-5], td)
            if doc:
                tasks.append(doc)
    return tasks


def main() -> int:
    ap = argparse.ArgumentParser(description="声明式任务板（T-09）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="列出任务板")

    pa = sub.add_parser("add", help="新建任务")
    pa.add_argument("--id", required=True)
    pa.add_argument("--title", required=True)
    pa.add_argument("--scope", nargs="+", required=True)

    pc = sub.add_parser("claim", help="认领任务")
    pc.add_argument("id")
    pc.add_argument("--session", required=True)

    pu = sub.add_parser("update", help="更新状态")
    pu.add_argument("id")
    pu.add_argument("--status", required=True)
    pu.add_argument("--session", required=True)

    for p in (pl, pa, pc, pu):
        p.add_argument("--tasks-dir", default=DEFAULT_TASKS_DIR)

    a = ap.parse_args()
    td = a.tasks_dir

    try:
        if a.cmd == "list":
            tasks = list_tasks(td)
            for t in tasks:
                holder = t["claimed_by"] or "—"
                print(f"  [{t['status']:11}] {t['id']}  {t['title']}  (持有: {holder})")
            if not tasks:
                print("  （任务板为空）")
            return 0
        if a.cmd == "add":
            add_task(a.id, a.title, a.scope, td)
            print(f"✅ 已添加任务 {a.id}（backlog）")
            return 0
        if a.cmd == "claim":
            claim_task(a.id, a.session, td)
            print(f"✅ {a.session} 已认领 {a.id}（claimed）")
            return 0
        if a.cmd == "update":
            doc = update_status(a.id, a.status, a.session, td)
            print(f"✅ {a.id} → {doc['status']}")
            return 0
    except ValueError as e:
        print(f"❌ {e}")
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
