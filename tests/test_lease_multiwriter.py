# -*- coding: utf-8 -*-
"""目录级多写者租约（G1 改造）单测 T1-T10。

⚠️ 退役状态（2026-08-24）：租约已降级为「车道边界提示」（worktree 物理隔离为主）。
本测试保留作**历史回归锚点**（不新增用例、不删除——删测试 = 隐藏问题），
验证 _lease.py 兼容接口在并发/接管/死锁场景下不被破坏。

核心回归锚点：T1（A 持 agents/** 与 B 持 skills/** 并行成功）——改造前
单写者锁必失败、改造后必通过，是「单写者→多写者」的直接证据。
全部用 tmp coor 文件，不触碰真实 .atomcode/coordination.json。
"""
import sys
import time

import pytest

sys.path.insert(0, __import__("os").path.join(
    __import__("os").path.dirname(__import__("os").path.dirname(
        __import__("os").path.abspath(__file__))), "scripts"))

import _lease  # noqa: E402


def _mk(tmp_path, name="co.json"):
    return str(tmp_path / name)


def _force_stale(coor, session):
    """把某会话租约的 last_active 拨到 TTL 之前，制造 stale。"""
    doc = _lease.load(coor)
    lease = doc["leases"][session]
    lease["last_active"] = time.time() - (lease["ttl_min"] * 60 + 5)
    _lease._write(coor, doc)


def _stub_staged(monkeypatch, files):
    monkeypatch.setattr(_lease, "_staged_files", lambda: list(files))


# ── T1 核心回归锚点：多写者并行 ──

def test_t1_multiwriter_parallel_acquire(tmp_path):
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor) is True
    assert _lease.acquire("B", ["skills/**"], coor_path=coor) is True  # 改造前这里必 False
    doc = _lease.load(coor)
    assert set(doc["leases"].keys()) == {"A", "B"}
    _lease.release("A", coor_path=coor)
    _lease.release("B", coor_path=coor)


# ── T2 scope 前缀包含冲突 ──

def test_t2_scope_prefix_contains_conflict(tmp_path):
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor) is True
    assert _lease.acquire("B", ["agents/planner/**"], coor_path=coor) is False
    _lease.release("A", coor_path=coor)


# ── T3 不相交放行 ──

def test_t3_disjoint_scope_passes(tmp_path):
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor) is True
    assert _lease.acquire("B", ["data/**"], coor_path=coor) is True
    _lease.release("A", coor_path=coor)
    _lease.release("B", coor_path=coor)


# ── T4 scope 相交判定边界 ──

def test_t4_scopes_conflict_boundary():
    assert _lease.scopes_conflict(["a/**"], ["a/b/**"]) is True   # 前缀包含
    assert _lease.scopes_conflict(["a/**"], ["ab/**"]) is False   # 命名陷阱
    assert _lease.scopes_conflict(["agents/**"], ["skills/**"]) is False
    assert _lease.scopes_conflict(["agents/**"], ["agents/planner/**"]) is True
    assert _lease.scopes_conflict(["a/b/**"], ["a/**"]) is True   # 对称
    assert _lease.scopes_conflict(["data/10793/**"], ["data/10794/**"]) is False


# ── T5 无租约提交 fail-closed ──

def test_t5_no_lease_precommit_fail_closed(tmp_path, monkeypatch):
    coor = _mk(tmp_path, "absent.json")
    _stub_staged(monkeypatch, ["anything.py"])
    assert _lease.precommit("solo", coor_path=coor) is False  # 改造前这里必 True
    assert _lease.precommit("anyone", coor_path=coor) is False


# ── T6 越界拒绝 ──

def test_t6_out_of_scope_commit_rejected(tmp_path, monkeypatch):
    coor = _mk(tmp_path)
    assert _lease.acquire("B", ["skills/**"], coor_path=coor) is True
    _stub_staged(monkeypatch, ["agents/x.py"])  # B 提交 agents/ 文件（越界）
    assert _lease.precommit("B", coor_path=coor) is False
    _lease.release("B", coor_path=coor)


# ── T7 活跃心跳不 stale ──

def test_t7_active_heartbeat_keeps_alive(tmp_path):
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor, ttl_min=1) is True
    for _ in range(5):
        assert _lease.heartbeat("A", coor_path=coor) is True
        time.sleep(0.01)
    doc = _lease.load(coor)
    assert not _lease.is_stale(doc["leases"]["A"])  # 心跳续租，不 stale
    _lease.release("A", coor_path=coor)


# ── T8 超时 stale 可接管 ──

def test_t8_stale_takeover(tmp_path):
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor, ttl_min=1) is True
    _force_stale(coor, "A")
    assert _lease.is_stale(_lease.load(coor)["leases"]["A"])
    assert _lease.acquire("B", ["agents/**"], coor_path=coor, force=True,
                          reason="A 挂死") is True
    doc = _lease.load(coor)
    assert "A" not in doc["leases"]  # A 的 stale 租约被接管删除
    assert "B" in doc["leases"]
    _lease.release("B", coor_path=coor)


# ── T8b stale 自动接管（2026-08-23：无需 --force，Lease 理论资源可重分配）──

def test_t8b_stale_auto_takeover(tmp_path):
    """stale 租约 = 死会话，正常 acquire 自动接管（不要求 force）。"""
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor, ttl_min=1) is True
    _force_stale(coor, "A")
    # 无 force 的普通 acquire 直接接管 stale 冲突租约
    assert _lease.acquire("B", ["agents/**"], coor_path=coor) is True
    doc = _lease.load(coor)
    assert "A" not in doc["leases"]
    assert "B" in doc["leases"]
    # 自动接管留痕
    assert "接管 A" in doc["leases"]["B"].get("takeover_note", "")
    _lease.release("B", coor_path=coor)


# ── T8c 存活租约仍拒绝（自动接管不误伤活会话）──

def test_t8c_alive_lease_still_rejected(tmp_path):
    """存活且相交的租约：普通 acquire 拒绝（只有 --force 可强接管）。"""
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor, ttl_min=30) is True
    assert _lease.acquire("B", ["agents/**"], coor_path=coor) is False  # 存活冲突拒绝
    doc = _lease.load(coor)
    assert "A" in doc["leases"]  # A 未被误接管
    assert "B" not in doc["leases"]
    _lease.release("A", coor_path=coor)


# ── T8d 残留锁死锁检测（2026-08-23：根治 coordination.lock 残留卡死）──

def test_t8d_deadlock_auto_recover(tmp_path, monkeypatch):
    """锁文件持有 PID 已死 → acquire 原子抢占，不死等超时。"""
    coor = _mk(tmp_path)
    lock = coor + ".coordination.lock"
    with open(lock, "w", encoding="utf-8") as f:
        f.write("999999")  # 死 PID
    # monkeypatch 强制"持有者已死"，验证 acquire 抢占路径（不依赖真实 tasklist）
    monkeypatch.setattr(_lease, "_pid_alive", lambda pid: False)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor, ttl_min=1) is True
    doc = _lease.load(coor)
    assert "A" in doc["leases"]
    _lease.release("A", coor_path=coor)


def test_t8d_alive_lock_not_recovered(tmp_path, monkeypatch):
    """锁持有 PID 存活 → 不抢占，_acquire_lock 超时返回 False（保守不误伤活进程）。"""
    coor = _mk(tmp_path)
    lock = coor + ".coordination.lock"
    with open(lock, "w", encoding="utf-8") as f:
        f.write("12345")
    monkeypatch.setattr(_lease, "_pid_alive", lambda pid: True)
    # 直接测锁层（_acquire_lock 接受 timeout；acquire 外层用默认 10s）
    assert _lease._acquire_lock(coor, timeout=0.3) is False


# ── T9 迟到写被 fencing 拦截 ──

def test_t9_late_write_fenced(tmp_path, monkeypatch):
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor, ttl_min=1) is True
    _force_stale(coor, "A")
    assert _lease.acquire("B", ["agents/**"], coor_path=coor, force=True) is True
    # A 迟到写：A 已无租约 → fail-closed 拒绝
    _stub_staged(monkeypatch, ["agents/x.py"])
    assert _lease.precommit("A", coor_path=coor) is False
    _lease.release("B", coor_path=coor)


# ── T10 接管留痕 ──

def test_t10_takeover_note_recorded(tmp_path):
    coor = _mk(tmp_path)
    assert _lease.acquire("A", ["agents/**"], coor_path=coor, ttl_min=1) is True
    _force_stale(coor, "A")
    assert _lease.acquire("B", ["agents/**"], coor_path=coor, force=True,
                          reason="A 会话挂死") is True
    doc = _lease.load(coor)
    note = doc["leases"]["B"].get("takeover_note", "")
    assert "接管 A" in note and "A 会话挂死" in note
    _lease.release("B", coor_path=coor)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
