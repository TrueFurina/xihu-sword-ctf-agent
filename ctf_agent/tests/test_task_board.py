# -*- coding: utf-8 -*-
"""声明式任务板（scripts/_task_board.py）单测（T-09）。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _task_board as tb  # noqa: E402


def _d(tmp_path):
    return str(tmp_path / "tasks")


def test_add_and_list(tmp_path):
    d = _d(tmp_path)
    tb.add_task("T-01", "门禁修复", ["tests/test_x.py"], tasks_dir=d)
    tasks = tb.list_tasks(tasks_dir=d)
    assert len(tasks) == 1
    assert tasks[0]["id"] == "T-01" and tasks[0]["status"] == "backlog"


def test_add_duplicate_rejected(tmp_path):
    d = _d(tmp_path)
    tb.add_task("T-01", "x", ["a.py"], tasks_dir=d)
    try:
        tb.add_task("T-01", "y", ["b.py"], tasks_dir=d)
        assert False, "应拒绝重复 id"
    except ValueError:
        pass


def test_claim_requires_ready(tmp_path):
    d = _d(tmp_path)
    tb.add_task("T-01", "x", ["a.py"], tasks_dir=d)  # backlog，非 ready
    try:
        tb.claim_task("T-01", "gu", tasks_dir=d)
        assert False, "backlog 不可认领"
    except ValueError:
        pass


def test_full_flow_ready_to_done(tmp_path):
    d = _d(tmp_path)
    tb.add_task("T-01", "x", ["a.py"], tasks_dir=d)
    tb.update_status("T-01", "ready", "coordinator", tasks_dir=d)
    doc = tb.claim_task("T-01", "gu", tasks_dir=d)
    assert doc["claimed_by"] == "gu" and doc["status"] == "claimed"
    tb.update_status("T-01", "in_progress", "gu", tasks_dir=d)
    tb.update_status("T-01", "review", "gu", tasks_dir=d)
    tb.update_status("T-01", "done", "gu", tasks_dir=d)
    assert tb.load_task("T-01", tasks_dir=d)["status"] == "done"


def test_claim_conflict_two_sessions(tmp_path):
    """乐观并发：A 认领后 B 再认领同一任务被拒。"""
    d = _d(tmp_path)
    tb.add_task("T-01", "x", ["a.py"], tasks_dir=d)
    tb.update_status("T-01", "ready", "coordinator", tasks_dir=d)
    tb.claim_task("T-01", "gu-a", tasks_dir=d)
    try:
        tb.claim_task("T-01", "gu-b", tasks_dir=d)
        assert False, "已 claimed 的任务不可再认领"
    except ValueError:
        pass


def test_illegal_transition_rejected(tmp_path):
    d = _d(tmp_path)
    tb.add_task("T-01", "x", ["a.py"], tasks_dir=d)
    try:
        tb.update_status("T-01", "done", "coordinator", tasks_dir=d)  # backlog → done 非法
        assert False, "backlog 不可直接 done"
    except ValueError:
        pass


def test_update_by_other_holder_rejected(tmp_path):
    d = _d(tmp_path)
    tb.add_task("T-01", "x", ["a.py"], tasks_dir=d)
    tb.update_status("T-01", "ready", "coordinator", tasks_dir=d)
    tb.claim_task("T-01", "gu-a", tasks_dir=d)
    try:
        tb.update_status("T-01", "review", "gu-b", tasks_dir=d)  # 非持有者无权改
        assert False, "非持有者不可改"
    except ValueError:
        pass
