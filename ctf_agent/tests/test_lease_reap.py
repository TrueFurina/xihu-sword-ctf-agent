# -*- coding: utf-8 -*-
"""僵尸租约「只报告 / 手动删除」测试（2026-09-19 防复发 A1 修订，缺口 G4）。

背景与结论（team-lead A1 决策）：
  初版把「僵尸自动回收」接到会话启动路径（boot 即删）。判据纯 `age > ttl*factor`、
  **零存活检查**（lease 不存 PID）→ 一个「存活但 90min 无心跳」的会话租约会被
  另一会话 boot 时**自动删掉**，等于给并发写开了隐蔽后门（QA 实测复现）。
  修订后：boot 路径 **一个字节都不写** coordination.json；删除必须显式 --force。

全部在 tmp_path 里跑，绝不触碰真 .atomcode/coordination.json。
"""
import json
import os
import subprocess
import sys

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS)

import _lease  # noqa: E402


def _write_coor(path, leases):
    doc = {"version": 1, "identity": {}, "leases": leases}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)


def _entry(age_seconds, ttl_min=30, scope=None):
    now = _lease._now()
    return {"scope": scope or ["agents/**"], "acquired_at": _lease._iso(now),
            "last_active": now - age_seconds, "last_commit": now - age_seconds,
            "ttl_min": ttl_min, "key_id": "", "lease_version": 0}


def _raw(path):
    with open(path, "rb") as f:
        return f.read()


# ── 1. 纯只读巡检：一个字节都不写 ──────────────────────────────────────────
def test_find_zombies_is_readonly_and_lists_suspects(tmp_path):
    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {
        "alive_recent": _entry(60),            # 1min 前活跃 → 非僵尸
        "alive_but_stale": _entry(90 * 60),    # 90min 无心跳 → 判据视为"怀疑僵尸"
    })
    before = _raw(coor)
    suspects = _lease.find_zombies(coor)
    after = _raw(coor)
    assert suspects == ["alive_but_stale"]
    assert before == after, "find_zombies 必须零写入（字节级一致）"
    doc = _lease.load(coor)
    assert "alive_but_stale" in doc["leases"], "只读巡检绝不删租约"


# ── 2. 无 --force → 任何路径都不删 ─────────────────────────────────────────
def test_reap_without_force_deletes_nothing(tmp_path):
    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {"alive_but_stale": _entry(90 * 60)})
    before = _raw(coor)
    reported = _lease.reap_zombies(coor)                 # force 默认 False
    assert reported == ["alive_but_stale"], "应报告但不得删除"
    assert _raw(coor) == before, "force=False 时不得写盘（字节级一致）"
    assert "alive_but_stale" in _lease.load(coor)["leases"]


def test_reap_cli_default_is_report_only(tmp_path):
    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {"alive_but_stale": _entry(90 * 60)})
    before = _raw(coor)
    r = subprocess.run([sys.executable, os.path.join(SCRIPTS, "_lease.py"),
                        "reap", "--coor", coor],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert r.returncode == 0
    assert "未删除" in r.stdout
    assert _raw(coor) == before, "CLI 默认（dryn-run）不得写盘"
    assert "alive_but_stale" in _lease.load(coor)["leases"]


# ── 3. 未过期租约：任何路径都不删（含 force=True）──────────────────────────
def test_expired_none_keeps_unexpired_under_force(tmp_path):
    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {
        "fresh": _entry(60),                 # 未过期
        "zombie": _entry(90 * 60),           # 过期
    })
    _lease.reap_zombies(coor, force=True)
    doc = _lease.load(coor)
    assert "fresh" in doc["leases"], "未过期租约任何路径都不得删"
    assert "zombie" not in doc["leases"]


def test_no_file_returns_empty(tmp_path):
    assert _lease.find_zombies(str(tmp_path / "nope.json")) == []
    assert _lease.reap_zombies(str(tmp_path / "nope.json"), force=True) == []


# ── 4. force=True 才真删（且只删怀疑名单）─────────────────────────────────
def test_reap_force_deletes_only_suspects(tmp_path):
    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {
        "fresh": _entry(60),
        "zombie": _entry(30 * 60 * 3),
    })
    deleted = _lease.reap_zombies(coor, force=True)
    assert deleted == ["zombie"]
    doc = _lease.load(coor)
    assert "zombie" not in doc["leases"]
    assert "fresh" in doc["leases"]


def test_reap_cli_force_deletes(tmp_path):
    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {"zombie": _entry(90 * 60)})
    r = subprocess.run([sys.executable, os.path.join(SCRIPTS, "_lease.py"),
                        "reap", "--coor", coor, "--force"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert r.returncode == 0
    assert "已删除" in r.stdout
    assert "zombie" not in (_lease.load(coor) or {"leases": {}}).get("leases", {})


# ── 5. 回归锁：boot 路径不得删除 alive_but_stale（核心要求）────────────────
def test_boot_does_not_delete_alive_but_stale(tmp_path, monkeypatch):
    """会话启动（boot）必须只报告、绝不动 coordination.json。"""
    import _session_boot  # noqa: PLC0415

    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {
        "alive_recent": _entry(60),
        "alive_but_stale": _entry(90 * 60),   # 90min 无心跳，但可能仍存活
    })
    before = _raw(coor)
    # 让 _lease 的默认协调文件指向 tmp（find_zombies 在调用时解析 COOR_DEFAULT）
    monkeypatch.setattr(_lease, "COOR_DEFAULT", coor)
    _session_boot.main([])                    # ⓪b 在分支/干净等门禁之前执行
    after = _raw(coor)
    assert before == after, "boot 路径一个字节都不许写 coordination.json"
    doc = _lease.load(coor)
    assert "alive_but_stale" in doc["leases"], "boot 不得删除 alive_but_stale(90m)"


def test_boot_source_never_calls_reap_zombies():
    """源码回归锁：boot 只能用只读 find_zombies，禁止 reap_zombies（防重新引入自动删）。"""
    with open(os.path.join(SCRIPTS, "_session_boot.py"), encoding="utf-8") as f:
        src = f.read()
    assert "find_zombies" in src
    assert "reap_zombies" not in src, "boot 不得调用 reap_zombies（自动删除已废除）"
