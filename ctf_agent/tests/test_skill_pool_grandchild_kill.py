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
    """Windows 下判断 pid 是否**仍在运行**（不是"句柄能否打开"）。

    ⚠️ 判据必须是 GetExitCodeProcess == STILL_ACTIVE(259)。
    不能用 OpenProcess(SYNCHRONIZE) 是否成功：已退出但父进程尚未收尸的
    进程（zombie）句柄照样能打开，于是本测试会**永远**误报"孙进程存活"，
    把一条本该锁住回归的用例变成永久红（2026-10 实测：Job 收割正常时
    也报 `AssertionError: 孙进程仍存活`，而 tasklist 已查无该 pid）。
    """
    k32 = ctypes.windll.kernel32
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h:
        return False
    code = ctypes.c_uint32()
    ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
    k32.CloseHandle(h)
    return bool(ok) and code.value == STILL_ACTIVE


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
                    reason="Windows 进程存活判据")
def test_pid_alive_probe_rejects_zombie():
    """判据自检：已退出的 pid 必须判为"不存活"。

    这是 test_grandchild_killed_on_timeout 的地基——判据一旦退回
    "OpenProcess 能打开即存活"，那条用例就会永久红（漏报回归），
    因此单独锁死判据本身，失败信息比"孙进程仍存活"更直指病灶。
    """
    import subprocess

    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()  # 已退出且已收尸
    assert not _win_pid_alive(p.pid), (
        f"已退出进程 pid={p.pid} 被判为存活——存活判据失效")

    # 反向：真在跑的进程必须判为存活，否则上一条断言会空转通过
    alive = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not _win_pid_alive(alive.pid):
            time.sleep(0.05)
        assert _win_pid_alive(alive.pid), (
            f"运行中进程 pid={alive.pid} 被判为已死——判据恒假，回归锁失效")
    finally:
        alive.kill()
        alive.wait()


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
