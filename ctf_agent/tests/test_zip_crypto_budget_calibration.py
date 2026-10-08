# -*- coding: utf-8 -*-
"""zip_crypto 爆破预算校准与隔离执行回归（2026-10-08）。

背景
----
`presolve._try_zip_crypto_bruteforce` 此前用
`_ZIPCRYPTO_MAXLEN = 3` + `_ZIPCRYPTO_MAX_CAND = 20_000`，
并在注释里写「max_len=4 时 17s+」。

**本文件锁死两件事**：

1. **旧参数存在真实盲区**（不是「稳妥」而是「不够」）
   --------------------------------------------------
   `skills/zip_crypto_bruteforce.run()` 的 `max_candidates` 是**全局累计**
   （`tried > max_cand` 即整体返回失败）。在生产 charsets
   `digits + lower + alnum` 下，20_000 只够走到：

       digits 1..4位(11,110) + lower 1..3位(18,278) + alnum 1..2位(3,906)

   ⇒ **3 位以上的 alnum 混合密码根本没被覆盖**。

   证据：仓库自带 fixture `tests/fixtures/zipcrypto_66688.zip`
   （由 **bkcrack 独立 C 实现**生成，避免同源实现自证循环，
   密码 **66688 = 5 位数字**）：

       max_len=3, cap=20_000    -> 0.30s  ok=False← 旧参数解不出
       max_len=5, cap=20_000    -> 0.27s  ok=False   ← 即使放宽 max_len 也不够
       max_len=5, cap=2_000_000 -> 1.05s  ok=True    ← 必须同时放宽 cap

   ⇒ 关键教训：**旧参数的问题不在 max_len，在 max_candidates**。
   只放宽 max_len 是无效的（第二行证明了）。

2. **放宽后的预算必须有据可依**
   实测速率（真ZipCrypto 包，密码**刻意不在搜索空间内** ⇒ 走满全空间）：

       max_len=4, cap=20_000    -> 0.28s
       max_len=4, cap=2_000_000 -> 27.95s   ⇒ 约 71,500 候选/秒

   ⇒ 耗时几乎**只由 cap 决定**（旧注释「4 位 17~19s」把两者混了）。
   `_ZIPCRYPTO_WALLCLOCK = 60` 按此速率留足spawn 与 IO 余量。

变异验证
--------
* 把 `_ZIPCRYPTO_MAX_CAND` 改回 20_000 ⇒ `test_budget_covers_fixture_password`
  必须 FAIL（fixture 解不出）；
* 把调用点改回 `to_thread` ⇒ `test_uses_terminable_isolation` 必须 FAIL
  （放宽后的 28s 活会占住 worker 到自然结束，见 skill_pool 根因说明）；
* 把 `_zc_run_with_common` 改回闭包形式（捕获外部 `run_fn`）⇒
  `test_helper_is_module_level_picklable` 必须 FAIL（spawn 无法 pickle 闭包）。
"""

from __future__ import annotations

import ast
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import presolve as P  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "zipcrypto_66688.zip"
_FIXTURE_PWD = "66688"

pytestmark = pytest.mark.skipif(
    not FIXTURE.exists(), reason="fixture zipcrypto_66688.zip 缺失")


# --------------------------------------------------------------------------
# 1) 预算必须覆盖 fixture 密码（旧参数覆盖不到）
# --------------------------------------------------------------------------
def test_budget_covers_fixture_password():
    """端到端：生产参数下必须能解出 fixture 的 5 位密码。

    这是本次放宽的**存在理由**。旧参数（cap=20_000）解不出。
    """
    from skills.zip_crypto_bruteforce import run as zc_run

    res = zc_run({
        "zip_path": str(FIXTURE),
        "entry": "Readme.txt",
        "max_len": P._ZIPCRYPTO_MAXLEN,
        "max_candidates": P._ZIPCRYPTO_MAX_CAND,
        "charsets": ["digits", "lower", "alnum"],
    })
    assert res.get("ok"), (
        f"生产参数（max_len={P._ZIPCRYPTO_MAXLEN}, "
        f"cap={P._ZIPCRYPTO_MAX_CAND}）解不出 fixture 密码 {_FIXTURE_PWD} —— "
        f"错误={res.get('error')} tried={res.get('tried')}。"
        f"旧参数 cap=20_000 在此样本上失败，是本次放宽的直接依据")
    assert str(res.get("password")) == _FIXTURE_PWD


def test_old_budget_cannot_reach_5_digit_password():
    """反证：把 cap 退回旧值 20_000 **确实**解不出（锁死放宽的必要性）。

    若哪天旧参数也能解出，说明 skill 变快了或fixture 变了 ⇒
    本PR 的理由消失，应重新评估是否还需要这么大的预算。
    """
    from skills.zip_crypto_bruteforce import run as zc_run

    res = zc_run({
        "zip_path": str(FIXTURE),
        "entry": "Readme.txt",
        "max_len": 6,
        "max_candidates": 20_000,          # 旧值
        "charsets": ["digits", "lower", "alnum"],
    })
    assert not res.get("ok"), (
        "旧参数（cap=20_000）竟然解出了 5 位密码 —— skill 可能已提速，"
        "请重新评估 _ZIPCRYPTO_MAX_CAND 是否还需要这么大")


def test_candidate_cap_reaches_past_alnum_3_chars():
    """预算必须让 alnum 至少能走到 3 位（旧参数只到 2 位）。

    这是本次放宽的**核心盲区**：`_gen_passwords` 按 `digits → lower → alnum`
    顺序枚举、`tried` 全局累计 ⇒ cap 太小会让后面的 charset 几乎没机会。
    """
    tables = {"digits": 10, "lower": 26, "alnum": 62}
    # 复刻 run() 的累计逻辑，算出 alnum 实际能走到几位
    rem = P._ZIPCRYPTO_MAX_CAND
    for name in ("digits", "lower", "alnum"):
        n = tables[name]
        reached = 0
        for length in range(1, P._ZIPCRYPTO_MAXLEN + 1):
            cost = n ** length
            if reached + cost > rem:
                break
            reached += cost
        rem -= reached
        if name == "alnum":
            assert reached >= 62 ** 3, (
                f"alnum 只能走到 {reached:,} 个候选（不足 3 位空间 "
                f"{62**3:,}）⇒ 3 位以上混合密码仍是盲区。"
                f"当前 cap={P._ZIPCRYPTO_MAX_CAND:,}")


# --------------------------------------------------------------------------
# 2) 隔离执行：放宽后必须用可终止的方式（否则 28s 活占住 worker）
# --------------------------------------------------------------------------
def _presolve_src() -> str:
    return (ROOT / "core" / "presolve.py").read_text(encoding="utf-8")


def test_zip_crypto_uses_terminable_isolation():
    """调用点必须走 `run_skill_isolated`（墙钟到点真终止子进程）。

    变异方式：改回 `asyncio.wait_for(asyncio.to_thread(...))` ⇒ 必须 FAIL。
    理由：cap=2e6 实测满空间 27.95s。留在 `to_thread` 时线程跑到自然结束
    并继续占住默认 executor 的 worker ⇒ 多题连续触发即耗尽线程池
    ⇒ 全链路变慢（这正是 PR #22 要根治的问题，不该在放宽时重新引入）。
    """
    src = _presolve_src()
    assert '"core.presolve", "_zc_run_with_common"' in src, (
        "zip_crypto 调用点已不通过 run_skill_isolated —— "
        "放宽后的 28s 预算绝不能回到不可取消的 to_thread")

    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr == "to_thread"):
            continue
        callee = getattr(node.args[0], "id", None) if node.args else None
        assert callee != "_zc_run_with_common", (
            "_zc_run_with_common 又被塞进 to_thread 了 —— "
            "线程不可取消，28s 的活会占住 worker 到自然结束")


def test_helper_is_module_level_picklable():
    """`_zc_run_with_common` 必须是模块级函数且自行 import skill。

    spawn 按 `模块名 + 限定名` 定位被调函数 ⇒
    - 闭包形式（捕获外部 run_fn）⇒ **无法 pickle**；
    - 直接提交 `skills.zip_crypto_bruteforce.run` ⇒ Windows spawn 报
      `module '__mp_main__' has no attribute 'run'`（实测踩过）。
    """
    tree = ast.parse(_presolve_src())
    fn = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == "_zc_run_with_common"),
        None)
    assert fn is not None, "_zc_run_with_common 不见了"
    # 不能有嵌套函数/闭包捕获外部变量
    #⚠️ `ast.walk(fn)` **包含 fn 自己**，所以必须排除它本身——
    # 第一版没排除，导致本用例恒红（又是「守卫自己有洞」）。
    nested = [n for n in ast.walk(fn)
              if n is not fn and isinstance(n, (ast.FunctionDef, ast.Lambda))]
    assert not nested, (
        f"_zc_run_with_common 内出现 {len(nested)} 个嵌套函数 ⇒ "
        f"很可能退化成闭包，spawn 无法 pickle"
        f"（第一版守卫漏了排除 fn 自身，会恒红——同类教训见 PR #23）")
    # 必须自行 import skill（不能在外部注入）
    src = ast.get_source_segment(_presolve_src(), fn) or ""
    assert "from skills.zip_crypto_bruteforce import" in src, (
        "_zc_run_with_common 必须自己 import skill —— "
        "跨进程时外层的 run_fn 引用不存在")


def test_isolated_execution_recovers_fixture_end_to_end():
    """端到端走 `run_skill_isolated`（真实 spawn 子进程）验证能解出 fixture。

    这条比静态断言强：它证明 spawn 路径上 **模块能导入、参数能 pickle、
    返回值能回传** 三件事同时成立。任何一环坏掉都会红。
    """
    import asyncio
    from core.skill_pool import run_skill_isolated

    params = {
        "zip_path": str(FIXTURE),
        "entry": "Readme.txt",
        "max_len": P._ZIPCRYPTO_MAXLEN,
        "max_candidates": P._ZIPCRYPTO_MAX_CAND,
        "charsets": ["digits", "lower", "alnum"],
    }
    t0 = time.monotonic()
    res = asyncio.run(run_skill_isolated(
        "core.presolve", "_zc_run_with_common",
        args=(params, P._ZIPCRYPTO_COMMON),
        timeout=P._ZIPCRYPTO_WALLCLOCK))
    elapsed = time.monotonic() - t0

    assert res and res.get("ok"), f"隔离执行未解出：{res}"
    assert str(res.get("password")) == _FIXTURE_PWD
    # 实测 1.05~1.9s（含 spawn）；给 20s 上界做性能护栏
    assert elapsed < 20, (
        f"隔离执行耗时 {elapsed:.1f}s，超出预期（实测约 1~2s）。"
        f"若突然变慢，先查 max_candidates 是不是被改大了")


# --------------------------------------------------------------------------
# 3) 墙钟预算与实测速率的一致性
# --------------------------------------------------------------------------
def test_wallclock_matches_measured_rate():
    """墙钟必须与实测速率自洽（cap 对应的耗时应显著低于墙钟）。

    实测：cap=2e6 ⇒ 27.95s ⇒ 约 71,500 候选/秒。
    若 cap 被改大而不动墙钟，这条会先红。
    """
    rate = 2_000_000 / 27.95          # 候选/秒
    predicted = P._ZIPCRYPTO_MAX_CAND / rate
    assert predicted < P._ZIPCRYPTO_WALLCLOCK * 0.75, (
        f"按实测速率 {rate:,.0f} 候选/秒，cap={P._ZIPCRYPTO_MAX_CAND:,} "
        f"预计需 {predicted:.1f}s，但墙钟只有 {P._ZIPCRYPTO_WALLCLOCK}s "
        f"⇒ 留的余量不足 25%，CI 慢机上会频繁超时")


def test_weak_password_list_intact():
    """内置弱口令表不得被放宽预算的动作顺带删掉（它是最快的一轮）。"""
    common = P._ZIPCRYPTO_COMMON
    assert len(common) >= 20, f"弱口令表被削弱：仅 {len(common)} 条"
    for pwd in ("password", "123456", "12345678"):
        assert pwd in common, f"弱口令表缺 {pwd}（实测这轮 0.02s 就命中）"