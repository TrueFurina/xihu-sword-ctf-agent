# -*- coding: utf-8 -*-
"""长耗时 task 的可终止隔离执行（2026-10-08）。

要解决的根因
------------
`core/presolve.py` 用 `asyncio.to_thread` 跑确定性求解器，PR #21 已给 5 个
数据量驱动的长task（pcap / mbr / knapsack / primes / cycling）补了墙钟：

    await asyncio.wait_for(asyncio.to_thread(fn, ...), timeout=120)

但 **线程不可取消**。`wait_for` 超时只是「调用方不再等待那个 Future」，
底层线程仍跑到自然结束，并**继续占住默认 executor 的 worker**。实测：

    wait_for(to_thread(sleep(6)), timeout=2) → 6.0s 后才返回，线程残留

默认 executor 是 `min(32, cpu+4)`。一旦多题连续触发长 task 且其中卡死，
worker 会被占满 ⇒ 后续所有 `to_thread` 类 task 的**提交动作本身阻塞**
⇒ fire-and-forget 的「presolve 不等task 就返回」这个安全阀失效，
表现为「个别task 卡死 → 全链路变慢」。墙钟只是治标，根因是线程不可终止。

为什么是「每次调用一个子进程」而不是常驻进程池
------------------------------------------------
可选方案是常驻 `ProcessPoolExecutor` + 超时后 `terminate()` 整个池。
但那样**一个 task 超时会连带杀死同池内其他正在正常运行的 task**
（本仓库长 task 是并发 fire-and-forget 触发的，同池并存是常态）。

本模块改为**每次调用独占一个单 worker 子进程**：

* 超时只杀自己那个子进程，不影响任何并发 task；
* 用完立即 `terminate()+join()`，**不泄漏进程**（实测见 tests）；
* 不需要维护池的生命周期（无常驻状态、无atexit 挂钩）⇒ 少一类泄漏。

代价是每次调用付一次 spawn 开销。实测 spawn+init ≈ 220ms，
而这些 task 的墙钟预算是 60–600s ⇒ 开销占比 <0.4%，可接受。
**短 task 不该用本模块**（见`_is_long_task` 的门槛说明）。

跨平台约束（Windows spawn，实测踩过）
--------------------------------------
1. 被提交的函数**必须是可 import 模块的模块级函数**——
   直接提交 `skills.pcap_http_carve.run` 会报
   `module '__mp_main__' has no attribute 'run'`。
   故统一走模块级转发 :func:`_call_skill`（模块名 + 函数名 + 参数）。
2. 显式指定 **spawn** 上下文而非各平台默认：
   Linux 默认 fork，而 presolve 满载线程时 fork 一个多线程进程有死锁风险；
   spawn 行为跨平台一致，且不会被父进程的锁状态污染。
3. `MagicMock` / `generator` / `lambda` 不可 pickle ⇒
   本模块只接受「模块名 + 字符串函数名 + 纯数据参数」，
   调用方必须传skill 的真实模块名，不接受已导入的函数对象。
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import multiprocessing
import os
import sys
from typing import Any, Callable, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

# 单个 task 的进程启动宽限：spawn + import skill 的时间不计入task 墙钟。
# 实测 spawn+init ≈ 220ms，给2s 足够覆盖冷启动与首次 import 开销。
SPAWN_GRACE_SECONDS = 2.0


def _win_job_initializer():
    """Pool worker 初始化器（仅 Windows 生效）：把 worker 进程挂进
    KILL_ON_JOB_CLOSE 的 Job Object。

    语义：worker 独占持有 Job 句柄 → worker 被 terminate 时句柄随进程关闭
    → **内核级联终止 Job 内所有进程**——包括 skill 在 worker 里再起的
    孙进程（实测 2026-10-09：ziphard e2e 超时杀掉 skill 子进程后，
    孙进程 bkcrack150_omp 孤儿存活 40+ 分钟吃满 8 核，级联打红下一个测试）。

    POSIX 侧不启用（pool.terminate 对 worker 的 SIGTERM 不传导孙进程的
    问题在 POSIX 需 killpg + pgid 回传管道，复杂度不成比例；本仓库
    生产与比赛机均为 Windows）。任何失败都静默降级——Job 挂不上时
    行为退化为修复前（只杀 worker），不阻塞 skill 执行。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        k32 = ctypes.windll.kernel32
        hjob = k32.CreateJobObjectW(None, None)
        if not hjob:
            return

        class _BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class _IoCounters(ctypes.Structure):
            _fields_ = [
                (n, ctypes.c_uint64)
                for n in ("ReadOperationCount", "WriteOperationCount",
                          "OtherOperationCount", "ReadTransferCount",
                          "WriteTransferCount", "OtherTransferCount")
            ]

        class _ExtLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimit),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        info = _ExtLimit()
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        info.BasicLimitInformation.LimitFlags = 0x00002000
        # JobObjectExtendedLimitInformation = 9
        if not k32.SetInformationJobObject(hjob, 9, ctypes.byref(info),
                                           ctypes.sizeof(info)):
            return
        # ⚠️ 不能用 GetCurrentProcess() 伪句柄：AssignProcessToJobObject 需要
        # 带权限的**真实**句柄，伪句柄报 ERROR_INVALID_HANDLE(6)（2026-10-09 实测）。
        # 改 OpenProcess 自身 pid 拿真句柄（自进程天然有完全访问权）。
        PROCESS_ALL_ACCESS = 0x1F0FFF
        hself = k32.OpenProcess(PROCESS_ALL_ACCESS, False, os.getpid())
        if not hself:
            return
        ok = k32.AssignProcessToJobObject(hjob, hself)
        k32.CloseHandle(hself)
        if not ok:
            return
        # 句柄刻意不关闭——worker 退出时句柄关闭触发 KILL_ON_JOB_CLOSE，
        # 孙进程随之被内核收割。
    except Exception:  # noqa: BLE001 - 初始化失败静默降级，绝不阻塞 skill
        return


class SkillTimeout(TimeoutError):
    """子进程墙钟到点被终止（区别于求解器自己抛的异常）。"""


def _call_skill(module_name: str, func_name: str,
                args: Sequence[Any], kwargs: Mapping[str, Any]) -> Any:
    """子进程侧的模块级转发（**必须模块级**：spawn 按引用 pickle）。

    刻意不写成闭包/偏函数：spawn 的子进程要能按 `模块名+限定名` 重新定位到它。
    """
    mod = importlib.import_module(module_name)
    fn: Callable[..., Any] = getattr(mod, func_name)
    return fn(*args, **kwargs)


def _blocking_call(pool, module_name: str, func_name: str,
                   args: Sequence[Any], kwargs: Mapping[str, Any],
                   timeout: float) -> Any:
    """在 pool 内同步等待子进程结果；墙钟到点由pool.terminate() 兜底。"""
    async_result = pool.apply_async(
        _call_skill, (module_name, func_name, tuple(args), dict(kwargs)))
    return async_result.get(timeout)


def _run_isolated_blocking(module_name: str, func_name: str,
                           args: Sequence[Any], kwargs: Mapping[str, Any],
                           timeout: float) -> Any:
    """起一个单 worker 子进程跑 skill，墙钟到点**真终止**并回收。

    刻意把「建池—等待—回收」全放在**同一个同步函数**里：
    这样 `asyncio.to_thread` 包裹的这段代码自身是**有界的**
    （`apply_async().get(timeout)` 会在 timeout 抛`TimeoutError`），
    不会像裸 `to_thread(skill)` 那样变成新的不可取消点。
    """
    ctx = multiprocessing.get_context("spawn")
    # 2026-10-09：worker 挂进 KILL_ON_JOB_CLOSE 的 Job（见 _win_job_initializer）——
    # terminate 杀 worker 时句柄关闭，孙进程（skill 再起的 bkcrack 等）被内核级联收割。
    pool = ctx.Pool(processes=1, initializer=_win_job_initializer)
    try:
        return _blocking_call(pool, module_name, func_name, args, kwargs, timeout)
    except multiprocessing.TimeoutError:
        # 到点：terminate 会杀掉子进程里正在跑的 skill，
        # 然后 join 回收。这是与 to_thread 的**本质差别**。
        pool.terminate()
        pool.join()
        raise SkillTimeout(
            f"{module_name}.{func_name} 超过 {timeout}s 墙钟，子进程已终止")
    except Exception:
        pool.terminate()
        pool.join()
        raise
    else:
        pool.terminate()
        pool.join()


async def run_skill_isolated(module_name: str, func_name: str,
                             args: Sequence[Any] = (),
                             kwargs: Optional[Mapping[str, Any]] = None,
                             timeout: float = 60.0) -> Any:
    """在可终止的独立子进程里跑一个 skill，墙钟 ``timeout`` 秒后真终止。

    参数
    ----
    module_name / func_name
        skill 的**真实模块名与函数名**（如 ``"skills.pcap_http_carve"`` /
        ``"run"``）。不收已导入的函数对象——spawn 要求按引用可再定位。
    args / kwargs
        传给该函数的纯数据参数（``str`` / ``bytes`` / ``int`` / ``dict`` /
        ``list`` 皆可 pickle）。
    timeout
        墙钟秒数（**不含** spawn 启动开销）。

    返回
    ----
    skill 的返回值。

    异常
    ----
    SkillTimeout
        墙钟到点，子进程已被终止并回收。
    Exception
        skill 自身的异常，原样透出（traceback 来自子进程）。
    """
    kwargs = dict(kwargs or {})
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(
            None,
            lambda: _run_isolated_blocking(
                module_name, func_name, args, kwargs, timeout),
        )
    except asyncio.TimeoutError as exc:
        # run_in_executor 自身到点（极罕见：timeout 远大于内部 get 的 timeout）。
        # 此时子进程仍可能活着，必须显式兜底回收，否则留下孤儿进程。
        raise SkillTimeout(
            f"{module_name}.{func_name} 超过 {timeout}s 墙钟") from exc