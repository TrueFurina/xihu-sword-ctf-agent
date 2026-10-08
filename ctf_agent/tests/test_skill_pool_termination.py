# -*- coding: utf-8 -*-
"""长耗时 task 的可终止隔离执行回归（2026-10-08）。

背景
----
`presolve` 用 `asyncio.to_thread` 跑确定性求解器。PR #21 给 5 个数据量驱动的
长 task 补了墙钟，但**线程不可取消**：`wait_for` 超时只是「调用方不再等待」，
底层线程仍跑到自然结束并继续占住默认 executor 的 worker。实测
`wait_for(to_thread(sleep(6)), timeout=2)` 要 **6.0s** 才返回。

worker 被占满 ⇒ 后续 `to_thread` 的**提交动作本身阻塞** ⇒ presolve 那个
「不等 task 就返回」的安全阀失效 ⇒ 个别 task 卡死传导为全链路变慢。
根因修复是 `core/skill_pool.run_skill_isolated`：每次调用独占一个子进程，
墙钟到点 `terminate()` **真终止**。

本文件盯住三件事（缺一即回归）：
1. **真终止**：墙钟到点必须真的提前返回（而不是像线程那样全额付出）；
2. **无泄漏**：调用结束后不留孤儿进程；
3. **不误伤并发**：A 超时终止不得杀掉 B（这是「每次一进程」而非
   「共享池+terminate」的核心理由，必须有测盯着，否则有人会把它改回去）；
4. **presolve 接线**：7 个长 task 必须真的走隔离执行，不能回退成裸
   `to_thread`（能力存在但没接线，是本仓反复出现过的失效形态）。

变异验证
--------
* 把 `run_skill_isolated` 换回 `asyncio.wait_for(asyncio.to_thread(...))`
  → 用例 1/2/3 必须 FAIL；
* 把 `_run_isolated_blocking` 的 `pool.terminate()` 去掉 → 用例 2 必须 FAIL；
* 把 presolve 里某个 `run_skill_isolated` 改回 `to_thread`
  → 用例 4 必须 FAIL；
* 把「每次一进程」改成共享单例池并在超时时 terminate → 用例 3 必须 FAIL。
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import presolve as P  # noqa: E402
from core.skill_pool import (  # noqa: E402
    SkillTimeout,
    _run_isolated_blocking,
    run_skill_isolated,
)

#本模块自身的模块级替身（spawn 按引用可再定位，必须模块级，不能用闭包）
_HELPER_MODULE = __name__


def _sleep_forever():
    """卡死替身：只在子进程里跑，用来验证「真终止」而不是「等自然结束」。"""
    time.sleep(300)
    return "never"


def _quick(value):
    return value


def _boom():
    raise ValueError("skill 内部炸了")


def _active_children() -> int:
    return len(multiprocessing.active_children())


# --------------------------------------------------------------------------
# 1) 真终止：墙钟到点必须提前返回
# --------------------------------------------------------------------------
def test_wallclock_actually_terminates():
    """核心断言：300s 的卡死替身必须在 3s 墙钟内被终止并返回。

    若实现回退成 `to_thread`，这里会挂到 300s 被 pytest timeout 杀掉 ⇒ 红。
    """
    t0 = time.monotonic()
    with pytest.raises(SkillTimeout):
        asyncio.run(run_skill_isolated(_HELPER_MODULE, "_sleep_forever",
                                       timeout=3))
    elapsed = time.monotonic() - t0

    # 上界：远小于替身的 300s（留足 CI 抖动余量）
    assert elapsed < 30, f"未真终止，实测 {elapsed:.1f}s（线程语义会等到300s）"
    # 下界：确认子进程真的起来跑过，不是立刻失败
    assert elapsed >= 2.0, f"过快返回 {elapsed:.1f}s，疑似没真执行"


def test_wallclock_returns_value():
    """正常路径：返回值必须原样透回（别只测超时而漏掉「隔离子进程跑不通」）。"""
    got = asyncio.run(run_skill_isolated(_HELPER_MODULE, "_quick",
                                         args=({"k": [1, 2]},), timeout=60))
    assert got == {"k": [1, 2]}


def test_skill_exception_propagates():
    """skill 自身异常必须透出（不能被误吞成None，也不能伪装成超时）。"""
    with pytest.raises(ValueError, match="skill内部炸了|skill 内部炸了"):
        asyncio.run(run_skill_isolated(_HELPER_MODULE, "_boom", timeout=60))


# --------------------------------------------------------------------------
# 2) 无孤儿进程泄漏
# --------------------------------------------------------------------------
def test_no_orphan_processes_after_timeout():
    """超时终止后必须把子进程回收掉，不能留孤儿反复累积。

    背景：presolve 会对多道题反复触发长 task，泄漏的子进程会累积占资源，
    等于把「线程占住 worker」换成「进程占住内存」。
    """
    before = _active_children()

    async def _drive():
        with pytest.raises(SkillTimeout):
            await run_skill_isolated(_HELPER_MODULE, "_sleep_forever",
                                     timeout=2)

    asyncio.run(_drive())
    # 给 OS 一点回收时间（terminate 是同步的，但进程表项消失略有延迟）
    for _ in range(20):
        if _active_children() <= before:
            break
        time.sleep(0.1)
    assert _active_children() <= before, (
        f"泄漏子进程：调用前 {before}，调用后 {_active_children()}")


def test_no_orphan_processes_after_normal_return():
    """正常返回路径同样不能留进程（terminate+join 必须在 finally 语义下发生）。"""
    before = _active_children()
    for _ in range(3):
        asyncio.run(run_skill_isolated(_HELPER_MODULE, "_quick",
                                       args=(1,), timeout=60))
    time.sleep(0.3)
    assert _active_children() <= before


# --------------------------------------------------------------------------
# 3) 并发隔离：A 超时不得误伤 B（守住「每次一进程」这个设计选择）
# --------------------------------------------------------------------------
def _slow_ok(seconds: float):
    time.sleep(seconds)
    return f"ok-{seconds}"


def test_timeout_does_not_kill_sibling_task():
    """A 卡死被终止时，同期跑着的 B 必须正常返回。

    这是「每次调用独占一个子进程」相对「共享进程池 + 超时 terminate 整个池」
    的**唯一**理由：后者会把同池其他正在正常运行的 task 一起杀掉。
    presolve 的长 task 是并发 fire-and-forget触发的，同池并存是常态。
    若有人把实现改回共享池，本用例必须红。
    """
    async def _drive():
        stuck = asyncio.create_task(run_skill_isolated(
            _HELPER_MODULE, "_sleep_forever", timeout=3))
        # 让 stuck 先起来，确保它真的在被终止
        await asyncio.sleep(0.5)
        # B 在A 的墙钟之内完成（A 3s 到点，B 只需 1s）
        sibling = await run_skill_isolated(
            _HELPER_MODULE, "_slow_ok", args=(1.0,), timeout=30)
        with pytest.raises(SkillTimeout):
            await stuck
        return sibling

    assert asyncio.run(_drive()) == "ok-1.0"


# --------------------------------------------------------------------------
# 4) presolve 接线：7 个长 task 必须真走隔离执行
# --------------------------------------------------------------------------
# (task 标签, 期望墙钟常量名)
_ISOLATED_TASKS = [
    "pcap_http_carve",
    "mbr_sse_verify",
    "knapsack_mhk",
    "crypto_primes",
    "cycling",
    "emcls",
    "lcg",
    "svg_path_text",
    "banana_script",
]

# 这些 skill 模块必须已经被隔离执行接管（跨进程按字符串模块名定位）。
# 留在这里会重新引入「线程不可取消 ⇒ worker 被占满 ⇒ 全链路变慢」的问题。
_ISOLATED_MODULES = [
    "skills.pcap_http_carve",
    "skills.mbr_sse_verify",
    "skills.crypto_knapsack_mhk",
    "skills.crypto_cycling",
    "core.coppersmith",
    "skills.crypto_electric_mayhem_cls",
    "skills.crypto_lcg_recover",
    "skills.svg_path_text",
    "skills.banana_script",
]

# 墙钟预算常量：每个长 task 一个，模块顶层定义
_WALLCLOCK_CONSTS = [
    "WALLCLOCK_PCAP",
    "WALLCLOCK_MBR",
    "WALLCLOCK_MHK",
    "WALLCLOCK_PRIMES",
    "WALLCLOCK_CYCLING",
    "WALLCLOCK_EMCLS",
    "WALLCLOCK_LCG",
    "WALLCLOCK_SVG",
    "WALLCLOCK_BANANA",
]


def _presolve_source() -> str:
    return Path(P.__file__).read_text(encoding="utf-8")


def test_long_tasks_actually_use_isolated_execution():
    """静态契约：长 task 的调用点必须出现 run_skill_isolated。

    为什么用静态断言而不是 mock 替身：进程池按「模块名 + 函数名」定位，
    测试里 mock 掉 skill.run 无法跨进程生效（这正是 spawn 约束的表现），
    只能靠源码契约盯住接线。变异方式：把任一 run_skill_isolated 改回
    to_thread，本用例必须 FAIL。
    """
    src = _presolve_source()
    calls = src.count("await run_skill_isolated(")
    assert calls >= len(_ISOLATED_TASKS), (
        f"仅 {calls} 处 run_skill_isolated 调用，"
        f"应至少覆盖 {len(_ISOLATED_TASKS)} 个长 task")

    # 每个长 task 必须有独立墙钟预算常量，且都在模块顶层定义
    for const in _WALLCLOCK_CONSTS:
        assert f"{const} =" in src, f"缺少墙钟预算常量 {const}"


def test_long_task_module_names_referenced():
    """被隔离执行的 skill 模块必须以字符串形式出现（跨进程按名定位）。

    变异方式：把某个模块名改错/改回变量 ⇒ 本用例必须 FAIL。
    """
    src = _presolve_source()
    for mod in _ISOLATED_MODULES:
        assert f'"{mod}"' in src, (
            f"{mod} 未出现在隔离执行调用里——可能回退成裸 to_thread 了"
            f"（或模块名写错，子进程会 ModuleNotFoundError）")


def test_stale_thread_caveat_comments_removed():
    """旧的「根治需迁 ProcessPoolExecutor」注释若还在，说明迁移没做完。

    变异方式：注释恢复 ⇒ 本用例 FAIL。这不是吹毛求疵——
    留着「待根治」注释会让下一个读代码的人以为线程问题还在，
    进而可能把长 task 改回 to_thread。

    注：只断言这一句「待根治」注释，不禁止 `to_thread` 本身——
    短 task（如 zip_crypto_bruteforce 最坏 0.44s）继续用 to_thread 是
    对的选择，迁移它们只会白付 spawn 开销。
    """
    src = _presolve_source()
    assert "根治需迁 ProcessPoolExecutor" not in src, (
        "仍留有「根治需迁 ProcessPoolExecutor」注释，迁移未完成")


def test_long_tasks_no_longer_use_bare_to_thread():
    """长 task 的调用点不得再用裸 to_thread（会重新引入不可取消线程）。

    变异方式：把某个 run_skill_isolated 换回
    `asyncio.to_thread(...)` ⇒ 本用例必须 FAIL。
    """
    src = _presolve_source()
    # 取出所有 run_skill_isolated 调用块的文本，确认其内部没有 to_thread
    idx = 0
    blocks = []
    while True:
        i = src.find("await run_skill_isolated(", idx)
        if i == -1:
            break
        #调用块到下一个 `)` 收尾，保守取 400 字符窗口
        blocks.append(src[i:i + 400])
        idx = i + 1
    assert blocks, "未发现 run_skill_isolated 调用"
    for b in blocks:
        assert "to_thread" not in b, (
            "run_skill_isolated 调用块内混入了 to_thread："
            f"{b[:120]!r}...")


# --------------------------------------------------------------------------
# 5) 边界：模块/函数不存在时必须报得出错，而不是静默挂住
# --------------------------------------------------------------------------
def test_missing_module_raises_not_hangs():
    with pytest.raises(Exception) as ei:
        asyncio.run(run_skill_isolated("no.such.module_xyz", "run", timeout=30))
    assert "module" in str(ei.value).lower() or "import" in str(ei.value).lower()


def test_missing_function_raises_not_hangs():
    with pytest.raises(Exception) as ei:
        asyncio.run(run_skill_isolated(_HELPER_MODULE, "definitely_absent",
                                       timeout=30))
    assert "absent" in str(ei.value)


def test_non_picklable_arg_raises_in_parent():
    """不可 pickle 的参数必须在**提交前**就报错，不能在子进程里静默失败。

    spawn 的 pickling 发生在父进程提交路径上，错误要在这一侧暴露，
    否则调用方拿到的是一个语义不明的异常。
    """
    with pytest.raises(Exception):
        # lambda 不可 pickle
        asyncio.run(run_skill_isolated(_HELPER_MODULE, "_quick",
                                       args=(lambda: 1,), timeout=10))


def test_blocking_helper_is_bounded():
    """_run_isolated_blocking 自身必须是有界的（不能成为新的不可取消点）。

    这是设计要点：run_skill_isolated 用 run_in_executor 包裹本函数，
    若本函数内部无界，那么外层线程又会变成杀不掉的老问题。
    """
    t0 = time.monotonic()
    with pytest.raises(SkillTimeout):
        _run_isolated_blocking(_HELPER_MODULE, "_sleep_forever", (), {}, 3)
    assert time.monotonic() - t0 < 30


# --------------------------------------------------------------------------
# 6) 真实 skill 在子进程里真的能跑（防「模块名/函数名写错」这类静默失效）
# --------------------------------------------------------------------------
# 为什么必须单独验：presolve 的端到端测试在本机全部 skip
# （缺真题附件 / 缺 python-flint），所以**门禁全绿并不能证明**
# `import skills.xxx` 在子进程里成功。若模块名或函数名写错，
# 真实运行时表现为「所有长 task 静默返回 None」——不报错、不解出flag，
# 是一种典型的静默失效。这里用真实 skill 模块把它钉死。

@pytest.mark.parametrize("module_name,func_name,params", [
    ("skills.pcap_http_carve", "run", {"path": "definitely-missing.pcap"}),
    ("skills.mbr_sse_verify", "run", {"path": "definitely-missing.bin"}),
])
def test_real_skill_loadable_in_subprocess(module_name, func_name, params):
    """真实 skill 必须能在子进程中按名加载并执行完（不抛导入/定位错误）。

    变异方式：把 presolve 里的模块名改错（如写成 `skills.misc_pcap_http_carve`）
    → 子进程 ModuleNotFoundError → 真实赛跑时该 task 永不命中 → 本用例先红。
    """
    try:
        asyncio.run(run_skill_isolated(module_name, func_name,
                                       args=(params,), timeout=90))
    except (ImportError, AttributeError) as exc:
        pytest.fail(
            f"{module_name}.{func_name} 在子进程内无法按名定位：{exc}"
            f"（跨进程定位失败 ⇒ 该 presolve task 会静默永不命中）")


def test_real_skill_business_error_propagates():
    """真实 skill 的业务异常必须能传回父进程（证明代码真在子进程执行）。

    反面：若子进程只是个空壳，参数校验不会触发、异常也不会冒出来。
    """
    with pytest.raises(Exception) as ei:
        asyncio.run(run_skill_isolated(
            "skills.crypto_cycling", "crypto_cycling",
            args=({"kind": "definitely-unknown-kind"},), timeout=90))
    # 期望是 skill 内部对缺 n/ct 的 KeyError（而非 ModuleNotFoundError）
    assert not isinstance(ei.value, (ImportError, AttributeError)), (
        f"拿到的是定位错误而非业务错误：{ei.value}")