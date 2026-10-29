# -*- coding: utf-8 -*-
"""fast_solve 返回契约 + `_PROVEN_FAST_SOLVE_KINDS` 清单真实性守卫。

背景（全部 2026-10-25 实测发现，非推断）：

① **rsa / fermat 分支违反 fast_solve 的返回契约。**
   `fast_solve` 对外一律返回 dict，唯独这一个分支是
   `return _fermat(params)` —— 直接透传 `skills.rsa_fermat_factor.run()`
   的返回值，而 run() 的文档契约是「解出的明文 bytes 或 None」。
   实测：`fast_solve("rsa", s=...)` / `("fermat", s=...)` 均返回 **None**。
   危害链：presolve `_try_fast_solve` 的 `flag = str(r.get("flag", ""))` 写在
   `try` **外面** ⇒ None/bytes 必抛 AttributeError 且**无人兜**；
   `scripts/_batch_bruteforce.py` 同款按 dict 用，被自己的 try 静默吞掉。

② **`_PROVEN_FAST_SOLVE_KINDS` 记账错（声明与实际断裂，第 4 次）。**
   `deterministic_decode` 曾被列在「真题实证解出过」清单里，但 fast_solve
   **根本没有这个 kind** —— 实测返回
   `{'ok': False, 'error': '未知题型 deterministic_decode'}`。
   真实解出路径是 math_engine.misc_decode → DeterministicDecodeAdapter，
   **不是 fast_solve**：把别人的战果记在 fast_solve 名下。
   （与 2026-10-15 修的 `zip` 同型：清单说已接线，实际从未被调用。）

③ **common_modulus / small_e 硬下标取值。**
   `int(params["c1"])` / `int(params["c"])`，而唯一生产调用方
   presolve `_try_fast_solve` **只传 `s`**（附件正文文本）⇒ 题面含「共模」
   「小指数」时必抛 KeyError，被外层 except 兜成
   `"…直出失败: KeyError 'c1'"` ⇒ 该路 100% 死、日志无痕。
   （同 vigenere/wiener NameError 同型，仓库内第 5、6 次。）

为什么 2026-10-15 的 `test_fast_solve_kind_liveness.py` 没抓到这些：
它的 `_KIND_PROBES` 只挑「契约明确」的 kind，**恰好整批跳过了 RSA 系**
（rsa / fermat / common_modulus / small_e / zip），而问题全在被跳过的那批里。
本测试专补这批，并加「清单 ↔ 实现」一致性守卫，防止再出现清单自夸。
"""
import pytest

from agents.crypto_toolkit import fast_solve
from core import presolve as P

try:
    from skills import rsa_fermat_factor as _RF
    HAS_DEPS = bool(getattr(_RF, "HAS_DEPS", False))
except Exception:  # noqa: BLE001
    HAS_DEPS = False

# p 已知的真解样本（常数量硬编码，测试自身不依赖 sympy/gmpy2 造素数）
_P = 1000000000000000000000000000000000000003
_Q = 1000000000000000000100000000000000000219
_N = 1000000000000000000100000000000000000222000000000000000000300000000000000000657
_E = 65537
_C = 643253765599634615834959539201450391421815464161243761643707046692920271701134
_FLAG = "flag{rsa_contract_ok}"


# ── ① rsa / fermat 必须遵守 dict 契约 ──────────────────────────────────────
@pytest.mark.parametrize("kind", ["rsa", "fermat"])
def test_rsa_kind_returns_dict_on_garbage_params(kind):
    """垃圾参数也必须返回 dict —— 原实现透传 run() 的 None 出来。"""
    r = fast_solve(kind, s="ZmxhZ3thYmN9", n=100)
    assert isinstance(r, dict), (
        f"fast_solve({kind!r}) 返回 {type(r).__name__}（{r!r}），"
        "必须是 dict：presolve 的 r.get() 不兜异常")


@pytest.mark.parametrize("kind", ["rsa", "fermat"])
def test_rsa_kind_returns_dict_on_empty(kind):
    r = fast_solve(kind)
    assert isinstance(r, dict), f"fast_solve({kind!r}) 空参返回 {type(r).__name__} 而非 dict"
    assert "ok" in r, f"{kind} 返回值缺 'ok' 键: {r}"


@pytest.mark.skipif(not HAS_DEPS, reason="缺 gmpy2/pycryptodome，RSA 攻击不可用")
@pytest.mark.parametrize("kind", ["rsa", "fermat"])
def test_rsa_kind_solves_p_known(kind):
    """p 已知时真解得出 flag（证明分支接的是真能力，不是摆设）。"""
    r = fast_solve(kind, n=_N, e=_E, c=_C, p=_P, q=_Q)
    assert isinstance(r, dict), f"{kind} 返回 {type(r).__name__} 而非 dict"
    assert r.get("flag") == _FLAG, f"{kind} 未解出: {r}"


# ── ② _PROVEN_FAST_SOLVE_KINDS 必须与 fast_solve 实际能力一致 ──────────────
def _proven():
    return sorted(P._PROVEN_FAST_SOLVE_KINDS)


@pytest.mark.parametrize("kind", _proven())
def test_proven_kind_is_real_fast_solve_kind(kind):
    """清单里的 kind 必须是 fast_solve 认识的 kind（防「清单自夸」）。

    `deterministic_decode` 曾在这里：fast_solve 无此分支，调用直接返回
    「未知题型」，真实解出走的是 math_engine 的 decode 适配器。
    """
    r = fast_solve(kind, s="")
    assert isinstance(r, dict), f"{kind} 返回 {type(r).__name__} 而非 dict"
    assert "未知题型" not in str(r.get("error", "")), (
        f"{kind} 被列在 _PROVEN_FAST_SOLVE_KINDS「已实证解出」清单里，"
        f"但 fast_solve 根本不认识它: {r}")


@pytest.mark.parametrize("kind", _proven())
def test_proven_kind_returns_dict(kind):
    """清单里每个 kind 的返回值都必须是 dict（契约守卫）。"""
    r = fast_solve(kind, s="")
    assert isinstance(r, dict), (
        f"{kind} 返回 {type(r).__name__}（{r!r}）——presolve 会 r.get() 崩")


def test_proven_list_size_is_bounded():
    """清单不得无限膨胀：>20 个 kind 几乎必然掺进未接线/不存在的项。

    独立硬编码红线（不引用被测常量），防「守卫引用被测值 ⇒ 恒绿」的假绿。
    """
    assert len(P._PROVEN_FAST_SOLVE_KINDS) <= 20, (
        f"实证清单膨胀到 {len(P._PROVEN_FAST_SOLVE_KINDS)} 项，"
        "远超真题复盘能支撑的规模——多半混入了未实证 kind")


# ── ③ common_modulus / small_e：缺参不得崩溃 ──────────────────────────────
@pytest.mark.parametrize("kind", ["common_modulus", "small_e"])
def test_missing_structural_params_no_silent_crash(kind):
    """只传 s（presolve 的真实调用形态）不得出现「直出失败」。

    原实现硬下标 `params["c1"]` / `params["c"]` ⇒ KeyError 被静默兜底。
    """
    r = fast_solve(kind, s="n=12345\ne=65537\nc=67890\n")
    assert isinstance(r, dict), f"{kind} 返回 {type(r).__name__} 而非 dict"
    blob = str(r)
    assert "直出失败" not in blob, (
        f"{kind} 崩溃被静默兜底（很可能是缺参 KeyError）: {blob[:160]}")
    assert "KeyError" not in blob, f"{kind} 出现 KeyError: {blob[:160]}"
    assert r.get("ok") is False, f"{kind} 缺参时不应报 ok=True: {r}"
    assert r.get("note"), f"{kind} 缺参必须给出可读的 note，而不是空结果: {r}"


def test_common_modulus_happy_path():
    """共模攻击真能算对（e1=3 / e2=7 互素 ⇒ 恢复明文）。

    ⚠️ m 必须 **< n**：c = pow(m, e, n) 只保留 m mod n，m > n 时数学上
    无法恢复（作者第一次写这条用例时用了 8 字节明文、n≈1e8，解出的是
    m mod n 而非 m —— 是样本错，不是实现错）。
    """
    n = 10007 * 10009
    m = int.from_bytes(b"cm", "big")
    assert m < n
    c1 = pow(m, 3, n)
    c2 = pow(m, 7, n)
    r = fast_solve("common_modulus", n=n, e1=3, e2=7, c1=c1, c2=c2)
    assert isinstance(r, dict), f"返回 {type(r).__name__} 而非 dict"
    assert r.get("ok") is True, f"共模未解出: {r}"
    assert int(r["flag"]) == m, f"共模解出的 m 不对: {r['flag']} != {m}"


def test_small_e_happy_path():
    """小指数：m^e < n 时直接开方恢复明文。"""
    e = 3
    m = int.from_bytes(b"flag{se}", "big")
    c = m ** e
    r = fast_solve("small_e", c=c, e=e)
    assert isinstance(r, dict), f"返回 {type(r).__name__} 而非 dict"
    assert r.get("ok") is True, f"小指数未解出: {r}"
    assert int(r["flag"]) == m, f"小指数解出的 m 不对: {r['flag']} != {m}"
