# -*- coding: utf-8 -*-
"""P0-2 回归测试：墙钟/取消语义（2026-08-21 赛后批量修复）。

覆盖：
1. 取消进行中的沙盒子进程 → CancelledError 传播且 _kill 被调用（Windows taskkill 杀进程树）
2. 数学引擎总时间预算：到点后不再启动新引擎（慢引擎不拖死矩阵）
3. _brute_5digit 时间预算：5 位爆破到点即放弃
"""

import asyncio
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_cancel_subprocess_run_kills_child(monkeypatch):
    """取消进行中的沙盒子进程：CancelledError 传播 + _kill 被调用。"""
    from sandbox.subprocess_executor import SubprocessExecutor

    killed = []
    orig_kill = SubprocessExecutor._kill

    def spy(proc):
        killed.append(proc)
        return orig_kill(proc)

    monkeypatch.setattr(SubprocessExecutor, "_kill", staticmethod(spy))
    sb = SubprocessExecutor(default_timeout=60)
    code = "python: import time; time.sleep(30)"

    async def main():
        task = asyncio.create_task(sb.run(code, timeout=60))
        await asyncio.sleep(1.2)  # 等子进程真正启动
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            return "cancelled"
        return "completed"

    assert asyncio.run(main()) == "cancelled"
    # 取消路径必须触发 _kill（P0-2 此前只捕 TimeoutError，CancelledError 泄漏子进程）
    assert len(killed) == 1


def test_math_engine_deadline_skips_later_engines():
    """总时间预算：首个引擎超过 deadline 后，不再启动后续引擎。"""
    from agents import math_engine as me

    original_engines = dict(me.MathEngineMatrix._engines)
    original_order = me.MathEngineMatrix._priority_order
    me.MathEngineMatrix._engines = {}
    me.MathEngineMatrix._priority_order = classmethod(lambda cls: ["_a_slow", "_b_should_not_run"])
    calls = []

    @me.MathEngineMatrix.register("_a_slow")
    def _a_slow(question):
        time.sleep(0.3)
        return None

    @me.MathEngineMatrix.register("_b_should_not_run")
    def _b_should_not_run(question):
        calls.append("b")
        return None

    try:
        q = type("Q", (), {"id": "t1", "category": "crypto", "attachments": []})()
        t0 = time.monotonic()
        name, flag = me.MathEngineMatrix.solve(q, timeout=0.1)
        dt = time.monotonic() - t0
        assert (name, flag) == (None, None)
        assert calls == []  # 超时后不再启动新引擎
        assert dt < 1.0     # 不被慢引擎拖死（>0.3s 但远小于无预算时的无限等待）
    finally:
        me.MathEngineMatrix._engines = original_engines
        me.MathEngineMatrix._priority_order = original_order


def test_brute_5digit_time_budget():
    """_brute_5digit 时间预算：到点即放弃（慢分支不阻塞矩阵）。"""
    from agents.math_engine import _brute_5digit

    class FakeZip:
        def read(self, name, pwd=None):
            raise RuntimeError("wrong password")

    t0 = time.monotonic()
    result = _brute_5digit(FakeZip(), "x", time_budget=0.2)
    dt = time.monotonic() - t0
    assert result is None
    assert dt < 1.5  # 预算 0.2s，不应跑满 10 万次
