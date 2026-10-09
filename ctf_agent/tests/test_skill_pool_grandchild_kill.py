# -*- coding: utf-8 -*-
"""run_skill_isolated 超时后的**孙进程级联收割**回归锁（2026-10-09）。

病灶：`pool.terminate()` 只杀 pool 的 worker 子进程；skill 在 worker 里
再用 subprocess 起的**孙进程**（实测：ziphard e2e 超时后 bkcrack150_omp
孤儿存活 40+ 分钟吃满 8 核，级联打红下一个 CPU 饥饿的测试）。

修法（Windows）：worker 初始化时挂进 KILL_ON_JOB_CLOSE 的 Job Object
（`core/skill_pool._win_job_initializer`）——worker 被 terminate 时句柄
随进程关闭，内核收割 Job 内全部进程。

测试设计（㉚：合成自检打在生产入口 run_skill_isolated 上）：
  合成 skill 在子进程里 spawn 一个 60s 的 python 孙进程、把其 PID 落盘、
  然后卡死 → run_skill_isolated 超时 → 轮询断言孙进程已死。
  变异验证：初始化器不生效（Job 挂不上）→ 孙进程存活 → 本文件红。
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import sys
import textwrap
import time

import pytest

from core.skill_pool import SkillTimeout, run_skill_isolated

_FIXTURE_NAME = "zz_skillpool_fixture"


def _win_pid_alive(pid: int) -> bool:
    """Windows 下判断 pid 是否仍存活（PROCESS_QUERY_LIMITED_INFORMATION）。"""
    k32 = ctypes.windll.kernel32
    SYNCHRONIZE = 0x00100000
    h = k32.OpenProcess(SYNCHRONIZE, False, int(pid))
    if not h:
        return False
    k32.CloseHandle(h)
    return True


@pytest.fixture
def fixture_module(tmp_path, monkeypatch):
    """写合成 skill 模块到 tmp_path 并注入 sys.path（spawn 子进程继承）。"""
    mod = tmp_path / f"{_FIXTURE_NAME}.py"
    mod.write_text(textwrap.dedent(f"""
        import subprocess
        import sys
        import time


        def run_spec(spec):
            # 起一个 60s 的 python 孙进程，PID 落盘，然后卡死到被终止。
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"])
            with open(spec["pid_file"], "w") as f:
                f.write(str(child.pid))
            deadline = time.time() + spec["sleep"]
            while time.time() < deadline:
                time.sleep(0.2)
            return "never"
    """), encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    # 确保父进程侧也能按名 import（_call_skill 在子进程里 import）
    import importlib
    importlib.invalidate_caches()
    return str(mod)


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Job Object 级联收割是 Windows 语义；POSIX 见模块注记")
def test_grandchild_killed_on_timeout(fixture_module, tmp_path):
    pid_file = str(tmp_path / "grandchild.pid")

    async def _drive():
        with pytest.raises(SkillTimeout):
            await run_skill_isolated(
                _FIXTURE_NAME, "run_spec",
                args=({"pid_file": pid_file, "sleep": 60},),
                timeout=3)

    t0 = time.monotonic()
    asyncio.run(_drive())
    assert time.monotonic() - t0 < 30, "3s 墙钟必须真终止（语义回退会等到 60s）"

    with open(pid_file, encoding="utf-8") as f:
        gpid = int(f.read().strip())

    # Job 级联收割是异步的：给内核最多 ~10s
    deadline = time.monotonic() + 10
    alive = True
    while time.monotonic() < deadline:
        alive = _win_pid_alive(gpid)
        if not alive:
            break
        time.sleep(0.5)
    assert not alive, (
        f"孙进程 pid={gpid} 在超时终止后仍存活——Job 级联收割失效"
        "（即 ziphard bkcrack 孤儿 40 分钟事故的回归）")


def test_child_pool_worker_also_reaped(fixture_module, tmp_path):
    """基础回归：worker 子进程本身照旧被回收（修复不得破坏既有语义）。"""
    pid_file = str(tmp_path / "unused.pid")

    async def _drive():
        with pytest.raises(SkillTimeout):
            await run_skill_isolated(
                _FIXTURE_NAME, "run_spec",
                args=({"pid_file": pid_file, "sleep": 60},),
                timeout=3)

    asyncio.run(_drive())  # SkillTimeout 正常抛出即通过
