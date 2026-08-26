# -*- coding: utf-8 -*-
"""B-18 回归测试：看板任务状态持久化 + _run_all 运行锁（决赛备战 2026-08-21）。

验证：
1. _save_state/_load_state 落盘后可跨重启恢复（临时文件原子替换）
2. _run_all 运行锁：并发触发只执行一轮，杜绝重复解题双烧 LLM 额度
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web import server as srv


def test_state_persist_roundtrip(tmp_path, monkeypatch):
    """保存 → 清空 → 恢复：任务状态跨重启可恢复。"""
    state_file = tmp_path / "dashboard_tasks.json"
    monkeypatch.setattr(srv, "_STATE_FILE", state_file)
    monkeypatch.setattr(srv, "_state_loaded", False)
    srv._tasks = {
        "t1": {"task_id": "t1", "status": "solved", "flag": "flag{ok}", "category": "crypto"},
        "t2": {"task_id": "t2", "status": "running", "flag": None},
    }
    srv._save_state()
    assert state_file.is_file(), "状态文件应已落盘"

    # 模拟进程重启：内存清空后 load
    srv._tasks = {}
    monkeypatch.setattr(srv, "_state_loaded", False)
    srv._load_state()
    assert srv._tasks.get("t1", {}).get("status") == "solved"
    assert srv._tasks["t1"]["flag"] == "flag{ok}"
    assert srv._tasks["t2"]["status"] == "running"


def test_state_load_ignores_corrupt_file(tmp_path, monkeypatch):
    """状态文件损坏时静默忽略，不阻断看板启动。"""
    state_file = tmp_path / "dashboard_tasks.json"
    state_file.write_text("{broken json!!", encoding="utf-8")
    monkeypatch.setattr(srv, "_STATE_FILE", state_file)
    monkeypatch.setattr(srv, "_state_loaded", False)
    srv._tasks = {"keep": {"task_id": "keep", "status": "pending"}}
    srv._load_state()  # 不应抛异常
    assert "keep" in srv._tasks  # 原内存状态保留


def test_run_all_lock_concurrent_trigger(monkeypatch):
    """运行锁：_run_all 进行中再次触发 → 直接返回，只执行一轮。"""
    started: list[int] = []

    async def fake_inner():
        started.append(1)
        await asyncio.sleep(0.1)  # 挂起期间第二次触发会命中锁

    monkeypatch.setattr(srv, "_run_all_inner", fake_inner)
    srv._running = False

    async def main():
        t1 = asyncio.create_task(srv._run_all())
        await asyncio.sleep(0.01)  # 确保 t1 已进入 inner（_running=True）
        t2 = asyncio.create_task(srv._run_all())  # 命中锁 → 直接返回
        await asyncio.gather(t1, t2)

    asyncio.run(main())
    assert len(started) == 1, f"应只执行一轮，实得 {len(started)}"


def test_run_all_sequential_ok(monkeypatch):
    """锁只防并发，不阻碍串行轮次（前一轮结束后可再跑）。"""
    ran: list[int] = []

    async def fake_inner():
        ran.append(1)

    monkeypatch.setattr(srv, "_run_all_inner", fake_inner)
    srv._running = False
    asyncio.run(srv._run_all())
    asyncio.run(srv._run_all())
    assert len(ran) == 2
