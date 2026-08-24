# -*- coding: utf-8 -*-
"""多会话写租约（scripts/_lease.py）单测——不变行为回归。

⚠️ 退役状态（2026-08-24）：租约已降级为「车道边界提示」（worktree 物理隔离为主）。
本测试保留作**历史回归锚点**（不新增用例、不删除——删测试 = 隐藏问题），
验证 _lease.py 兼容接口（acquire/precommit/status/release/heartbeat）不被破坏。

G1 改造后：并发/越界/接管/fail-closed 行为由 test_lease_multiwriter.py（T1-T10）覆盖；
本文件只保留「不受改造影响」的行为回归：scope 匹配边界、释放权限、原子写、同会话续租。
全部用 tmp coor 文件，不触碰真实 .atomcode/coordination.json。
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _lease  # noqa: E402


def _mk(tmp_path, name="co.json"):
    return str(tmp_path / name)


def test_acquire_same_session_renew(tmp_path):
    """同一会话重复 acquire = 覆盖自己的租约，不算冲突。"""
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["a/**"], coor_path=coor) is True
    assert _lease.acquire("A", ["b/**"], coor_path=coor) is True
    assert _lease.load(coor)["leases"]["A"]["scope"] == ["b/**"]
    _lease.release("A", coor_path=coor)


def test_path_in_scope_matrix():
    assert _lease.path_in_scope("agents/math_engine.py", ["agents/**"])
    assert _lease.path_in_scope("agents/a/b.py", ["agents/**"])
    assert _lease.path_in_scope("tests/test_x.py", ["agents/**", "tests/**"])
    assert not _lease.path_in_scope("scripts/_lease.py", ["agents/**"])
    assert not _lease.path_in_scope("agentsX/foo.py", ["agents/**"])  # 前缀陷阱
    assert _lease.path_in_scope("AGENTS.md", ["AGENTS.md"])           # 精确文件
    assert _lease.path_in_scope("agents/a.py", ["agents"])            # 裸目录名前缀


def test_release_wrong_session_refused(tmp_path):
    coor = _mk(tmp_path)
    _lease.acquire("A", ["a/**"], coor_path=coor)
    assert _lease.release("B", coor_path=coor) is False
    assert _lease.load(coor) is not None  # A 的租约还在
    assert _lease.release("A", coor_path=coor) is True
    assert _lease.load(coor) is None  # leases 清空后删除整个文件


def test_write_atomic_no_partial_json(tmp_path):
    coor = _mk(tmp_path)
    _lease.acquire("A", ["a/**"], coor_path=coor)
    # 直接读盘验证是合法 JSON（多租约结构）
    with open(coor, "r", encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["version"] == 1
    assert "A" in doc["leases"]
    _lease.release("A", coor_path=coor)


def test_old_format_migrated_on_acquire(tmp_path):
    """旧单 session 格式在 acquire 时迁移为 leases 映射（不丢既有租约）。"""
    coor = _mk(tmp_path)
    with open(coor, "w", encoding="utf-8") as f:
        json.dump({"session": "OLD", "scope": ["agents/**"],
                   "last_heartbeat": 0, "ttl_min": 30}, f)
    # OLD 的 last_heartbeat=0 早已 stale，B 持不相交 scope 可 acquire
    assert _lease.acquire("B", ["skills/**"], coor_path=coor) is True
    doc = _lease.load(coor)
    assert "B" in doc["leases"]
    _lease.release("B", coor_path=coor)


def test_staged_files_unicode_path(monkeypatch):
    """_staged_files 用 -z 返回原始 UTF-8 路径，中文文件名不被八进制转义。"""
    class FakeResult:
        def __init__(self, stdout):
            self.stdout = stdout

    payload = "scripts/_lease.py\0data/results/深刻反思与总结.md\0".encode("utf-8")
    monkeypatch.setattr(_lease.subprocess, "run",
                        lambda *a, **k: FakeResult(payload))
    files = _lease._staged_files()
    assert "data/results/深刻反思与总结.md" in files
    assert "scripts/_lease.py" in files
