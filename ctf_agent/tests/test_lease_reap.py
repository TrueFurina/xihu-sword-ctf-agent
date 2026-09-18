# -*- coding: utf-8 -*-
"""僵尸租约自动回收测试（2026-09-19 防复发，缺口 G4）。

背景：lease 曾"能记录、不能保护"——stale 僵尸租约不自动回收。`reap_zombies`
按 last_active 距今 > TTL×factor（默认 ×2）回收死租约。全部在 tmp_path 里跑，
不触碰真 coordination.json。
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


def test_reap_removes_only_zombies(tmp_path):
    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {
        "alive": _entry(60),               # 1min 前活跃 → 存活
        "zombie": _entry(30 * 60 * 3),     # 90min 前 → 阈值 TTL(30)*2=60min → 僵尸
    })
    reaped = _lease.reap_zombies(coor)
    assert reaped == ["zombie"]
    doc = _lease.load(coor)
    assert "alive" in doc["leases"]
    assert "zombie" not in doc["leases"]


def test_reap_dry_run_keeps_all(tmp_path):
    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {"zombie": _entry(30 * 60 * 3)})
    reaped = _lease.reap_zombies(coor, dry_run=True)
    assert reaped == ["zombie"]
    doc = _lease.load(coor)
    assert "zombie" in doc["leases"]


def test_reap_no_file_returns_empty(tmp_path):
    assert _lease.reap_zombies(str(tmp_path / "nope.json")) == []


def test_reap_cli(tmp_path):
    coor = str(tmp_path / "coordination.json")
    _write_coor(coor, {"zombie": _entry(30 * 60 * 3)})
    r = subprocess.run([sys.executable, os.path.join(SCRIPTS, "_lease.py"),
                        "reap", "--coor", coor],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert r.returncode == 0
    assert "回收僵尸租约" in r.stdout
