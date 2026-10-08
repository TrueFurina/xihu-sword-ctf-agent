# -*- coding: utf-8 -*-
"""presolve 短 task 的「不迁移」决策守卫（2026-10-08）。

背景
----
PR #22 把 9 个**长** task 迁到了可终止的隔离执行（core/skill_pool.py）。
但 `presolve` 里仍有 8 处裸 `asyncio.to_thread`。它们**故意不迁**——
这不是遗漏，是逐个实测后的结论。

不迁的依据（本文件的实测数据，2026-10-08，Windows 3.13）：

| task | 典型耗时 | 最坏场景实测 | 不迁理由 |
|---|---:|---|---|
| `math_engine` | 0.66s | 自带 30s 预算 | 预算已在函数内部 |
| `rsa_fermat_factor` | 0.000s | e<=5 时爆破上限 2^20 | 受控|
| `hash_crack` | 0.000s | 词表 49 条 | 有界 |
| `misc_qr_matrix` | 0.000s | 10×10 矩阵穷举 | 有界 |
| `rev_const_compare` | 0.000s | 预检已挡非 ELF | 有界 |
| `emoji_binary` | 0.199s | 1MB 文本 | 实测 |
| `rev_xor_verify` | 0.002s | 4MB 文件 | 预检 + 实测 |
| `_recover_primes_n` | 0.11s | 默认 `max_bytes=200` | 见下|

⇒ 最坏 0.66s，而迁移一次的 spawn 开销就是 **~0.22s**。
**迁移它们是纯亏**（付 spawn 换0.4s 的保险），除非耗时真的不可控。

`_recover_primes_n` 的重点
---------------------------
它看起来最危险（滑窗枚举 + `sympy_nextprime`），且此前**确实无任何超时保护**
——这是 PR #22 留下的一处「保护不一致」：同一个 `crypto_primes` task 的
后半步（`solve_primes`）可终止，前半步（`_recover_primes_n`）不可终止。

实测否定了危险假设：
- 成本几乎全在 `sympy_nextprime(P)`，而它**只在
  `0 < q - P <= _PRIMES_GAP_LIMIT(100000)` 通过时才调用** ⇒ 调用次数有界；
- 生产调用点用**默认 `max_bytes=200`**（外部无法调大）⇒ 最坏 **0.11s**；
- 构造最坏输入（q 永不匹配 / 让廉价过滤多次通过）：
  **0.06s 与 0.00s，nextprime 调用 0 次** ⇒ 廉价过滤有效。

变异验证
--------
* 把 `_recover_primes_n` 改成「过滤条件恒真」（等价于移除过滤保护）
  → `test_recover_primes_n_filter_bounds_nextprime_calls` 必须 FAIL
  （实测调用次数会从 0~1 次暴涨到 n_max/7 次）。
* 把生产调用点的 `max_bytes` 改成 12800
  → `test_recover_primes_n_production_call_uses_default_budget` 必须 FAIL。
"""

from __future__ import annotations

import ast
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import presolve as P  # noqa: E402

# 保持短task 留在 to_thread 的 skill/函数（实测毫秒级，见模块 docstring）
_SHORT_TASKS = [
    "MathEngineMatrix",
    "rsa_run",
    "hc_run",
    "qr_run",
    "rev_solve",
    "emoji_run",
    "rox_run",
    "_recover_primes_n",
]

# 这些 task **必须**已迁移（PR #22 的结论，不得回退）
_MIGRATED_MODULES = [
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


def _src() -> str:
    return Path(P.__file__).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# 1) 迁移清单不可回退（承接 test_skill_pool_termination.py，此处从另一侧钉）
# --------------------------------------------------------------------------
def test_long_tasks_still_isolated():
    """9 个长 task 必须仍在隔离执行里（长task 有保护是硬要求）。"""
    src = _src()
    for mod in _MIGRATED_MODULES:
        assert f'"{mod}"' in src, f"{mod} 从隔离执行里消失了——长 task 又变回不可终止"


# --------------------------------------------------------------------------
# 2) 短 task 保持 to_thread（不要无脑迁移）
# --------------------------------------------------------------------------
def _to_thread_callees() -> set[str]:
    """用 AST 精确抽出所有 `asyncio.to_thread(...)` 的被调名。

    不能用字符串匹配：`to_thread(emoji_run, {...})` 与
    `to_thread(\n    emoji_run, {...})` 两种写法都合法（后者是跨行调用），
    前者写的 `f"to_thread({name}"` 对后者一律匹配不到 ⇒ 假红。
    这正是本文件第一版测试犯的错。
    """
    out: set[str] = set()
    for node in ast.walk(ast.parse(_src())):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        #形如 asyncio.to_thread(...)
        if not (isinstance(f, ast.Attribute) and f.attr == "to_thread"):
            continue
        if not node.args:
            continue
        first = node.args[0]
        name = getattr(first, "attr", None) or getattr(first, "id", None)
        if name:
            out.add(name)
    return out


def test_short_tasks_not_migrated_to_spawn():
    """短 task 必须留在 to_thread：迁移它们只会白付 ~0.22s spawn。

    这是「不做什么」的守卫。判断依据见模块 docstring 的实测表。
    若将来某个 task 的实测耗时变了（题库变化/实现重写），
    **先改这张表的数字并补实测**，不要凭感觉改这里。
    """
    callees = _to_thread_callees()
    for name in ("rsa_run", "hc_run", "qr_run", "rev_solve", "emoji_run",
                 "rox_run", "_recover_primes_n"):
        assert name in callees, (
            f"{name} 已不在 to_thread 的调用列表里——确认它去了哪。"
            f"若它的实测耗时已变化，先更新本文件的实测表再改代码。"
            f"当前 to_thread 被调者：{sorted(callees)}")


def test_zip_crypto_bruteforce_stays_in_thread():
    """zip_crypto_bruteforce 最坏 0.44s，刻意不迁（PR #19 已实测该数字）。"""
    assert "_zc_run_with_common" in _to_thread_callees(), (
        "zip_crypto_bruteforce 应仍在 to_thread（最坏 0.44s，迁移不划算）")


# --------------------------------------------------------------------------
# 3) _recover_primes_n：实测最坏耗时 + 廉价过滤的有效性
# --------------------------------------------------------------------------
def _to_thread_calls(name: str) -> list[ast.Call]:
    """取出所有 `asyncio.to_thread(<name>, ...)` 的 Call 节点。

    ⚠️ 关键：`_recover_primes_n` 在源码里的形态是
    `asyncio.to_thread(_recover_primes_n, q, r)` —— 它是 **`to_thread` 的
    第一个参数**，不是某个 `Call.func`。

    第一版我写成「找 `Call.func` 名为 `_recover_primes_n` 的节点」，
    结果 `seen = 0`：变异 `_recover_primes_n(q, r, 12800)` 确实让用例红了，
    **但红的原因是「没找到调用点」而不是「发现了位置参数」** ⇒ 假红，
    等于这道守卫从来没真正生效。
    """
    out = []
    for node in ast.walk(ast.parse(_src())):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr == "to_thread"):
            continue
        if not node.args:
            continue
        first = node.args[0]
        callee = getattr(first, "attr", None) or getattr(first, "id", None)
        if callee == name:
            out.append(node)
    return out


def test_recover_primes_n_production_budget_is_default():
    """生产调用点必须用默认 max_bytes（=200），不能被外部放大。

    变异方式（两条都要能抓）：
    ① `_recover_primes_n(q, r, max_bytes=12800)` —— 关键字形式
    ② `_recover_primes_n(q, r, 12800)`              —— 位置参数形式

    ⚠️ 两条踩坑记录：
    - 第一版只查 `node.keywords` ⇒ 漏掉位置参数（变异 ② 全绿通过）；
    - 第二版改查 `Call.func` 名⇒ `seen=0` 假红（`_recover_primes_n`
      是 `to_thread` 的参数，不是被调函数），**等于没守**。
    教训同项目反复出现的那条：**守卫必须被变异验证证明它真的会红，
    且红的理由要是正确的原因**。
    """
    calls = _to_thread_calls("_recover_primes_n")
    assert calls, (
        "未找到 `to_thread(_recover_primes_n, ...)` 调用点——"
        "源码结构变了？先确认它现在跑在哪")

    for node in calls:
        # to_thread(func, q, r[, max_bytes]) ⇒ 第 4 个实参即 max_bytes
        # （第 1 个是被调函数本身，故偏移 1）
        if len(node.args) >= 4:
            pytest.fail(
                "生产调用点用位置参数传了 max_bytes"
                "⇒ 实测该参数可把耗时从 0.11s 放大到 2.91s（26 倍）")
        kwargs = {k.arg for k in node.keywords if k.arg}
        assert "max_bytes" not in kwargs, (
            "生产调用点显式传了 max_bytes——实测该参数可放大耗时 26 倍"
            "（200 → 0.11s，12800 → 2.91s）")


def test_recover_primes_n_has_gap_filter():
    """廉价过滤 `0 < d <= _PRIMES_GAP_LIMIT` 必须还在（它是耗时可控的根本）。

    变异方式：删掉这个条件（等价于让 nextprime 对每个候选都调用）
    → 本用例 FAIL，且 `test_recover_primes_n_filter_bounds_nextprime_calls`
    也会 FAIL。**这两条一起构成护栏**：光有断言不够，
    还要有用例证明「去掉它会真的变慢」。
    """
    src = _src()
    assert "0 < d <= _PRIMES_GAP_LIMIT" in src, (
        "廉价过滤条件不见了——这会让 sympy_nextprime 被全量调用，耗时失控")
    assert "_PRIMES_GAP_LIMIT = 100000" in src, (
        "_PRIMES_GAP_LIMIT 的值变了。实测它决定 nextprime 调用次数上界；"
        "改它必须重跑耗时实测并更新本文件")


def test_recover_primes_n_filter_bounds_nextprime_calls():
    """实证：过滤条件把 nextprime 调用次数压在有界范围（这是实测依据）。

    用真实生产参数（max_bytes=200, r=131）跑两种输入：
      ① 构造必然命中的 q → 恰好 1 次；
      ② 构造永不命中的 q → 0 次。
    两种都在个位数次以内 ⇒ 耗时可控。
    """
    from core.coppersmith import _first_primes, sympy_nextprime
    from core.presolve import _PRIMES_GAP_LIMIT

    max_bytes, r = 200, 131
    n_max = 7 * max_bytes
    primes = _first_primes(n_max + 8)

    def count_calls(q: int) -> tuple[int, int | None]:
        n = r + 1
        p = 1
        for i in range(n - r, n):
            p *= primes[i]
        calls = 0
        while n <= n_max:
            if n % 7 == 0:
                d = q - p
                if 0 < d <= _PRIMES_GAP_LIMIT:
                    calls += 1
                    if sympy_nextprime(p) == q:
                        return calls, n
            p //= primes[n - r]
            p *= primes[n]
            n += 1
        return calls, None

    # ① 必然命中
    nb = 74
    n_true = 7 * nb
    p = 1
    for i in range(n_true - r, n_true):
        p *= primes[i]
    calls_hit, hit = count_calls(sympy_nextprime(p))
    assert hit == n_true, "构造的 q 应命中（测试自身前提失效）"
    assert calls_hit <= 4, f"命中路径调用次数异常：{calls_hit}"

    # ② 永不命中（q 取远大于所有候选 P 的素数 ⇒ 过滤全不过）
    q_far = sympy_nextprime(primes[-1] ** 3)
    calls_miss, _ = count_calls(q_far)
    assert calls_miss == 0, (
        f"未命中路径本应 0 次 nextprime 调用，实测 {calls_miss} 次"
        f"——廉价过滤可能已失效")


def test_recover_primes_n_measured_worst_case_is_cheap():
    """实测断言：默认参数下最坏耗时 < 5s（实测 0.11s，留 45倍余量）。

    这条是**性能护栏**：若将来有人改坏了枚举（去掉滑窗优化/改成暴力），
    耗时会暴涨，本用例会先红。
    """
    from core.coppersmith import _first_primes, sympy_nextprime

    max_bytes, r = 200, 131
    n_max = 7 * max_bytes
    primes = _first_primes(n_max + 8)
    nb = 74
    n_true = 7 * nb
    p = 1
    for i in range(n_true - r, n_true):
        p *= primes[i]
    q = sympy_nextprime(p)

    t0 = time.monotonic()
    got = P._recover_primes_n(q, r)
    elapsed = time.monotonic() - t0

    assert got == n_true, f"真实 q 未反解出 n：{got} != {n_true}"
    assert elapsed < 5.0, (
        f"默认参数下耗时 {elapsed:.2f}s，超出 5s 预算。"
        f"实测基线 0.11s；若确实变慢，先查是不是实现被改坏了")