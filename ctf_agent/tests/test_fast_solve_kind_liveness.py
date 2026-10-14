# -*- coding: utf-8 -*-
"""fast_solve 各 kind「活着」守卫 + 摩斯 / 维吉尼亚 / 维纳三处静默失败修复。

背景（全部为 2026-10-15 实测发现，非推测）：

① **两个 kind 100% 抛异常，且被静默吞掉。**
   `fast_solve()` 的 vigenere 分支调 `vigenere_crack(...)`、wiener 分支调
   `wiener_attack(...)` —— 这两个名字只存在于 `attack_templates` 的**字符串模板**
   里（供 LLM 沙盒 exec 用），本模块从未定义 ⇒ 必抛 `NameError`，又被 fast_solve
   外层 `except Exception` 兜成 `{"ok": False, "error": "<kind> 直出失败: NameError"}`。
   表现是：题面含「维吉尼亚/维纳」的题恒 0 解出，**日志无痕、指标只显示未命中**。

   同仓库这类坑已是第 4 次（decode_multi_layer / crack_hash / common_modulus），
   所以本测试不只修这两个点，而是加「每个 kind 都不得因未定义名崩溃」的**运行时**
   守卫——静态 AST 检查有盲区：函数内 `import re` 写在调用点之后时，AST 认为名字
   已定义，实际运行仍 NameError（本轮作者自己就又踩了一次）。

② **摩斯内联码表残缺**：缺 `F`（`..-.`）且完全没有数字 0-9，未知 token 还用
   `.get(tok, "")` 静默丢弃 ⇒ 实测 `flagmorse`→`LAGMORSE`、`m0rse2026`→`MRSE`。
   而 `skills.morse_decoder` 的码表（A-Z + 0-9）是完整的，这条路径却没用它。

③ **Wiener 攻击从未解出过任何题**：`skills.rsa_fermat_factor._continued_fraction`
   的递推初值写反，返回的是 **(分母, 分子)**，而 `_wiener_attack` 按
   `for k, d in cf` 解包 ⇒ k 拿到分母、d 拿到分子，`(e*d-1) % k == 0` 恒不成立。
   实测 d/n 比值 0.18 / 0.20 / 0.22 全部返回 None（全部满足 Wiener 理论条件）。
"""
import re

import pytest

from agents.crypto_toolkit import fast_solve

try:  # 摩斯编码用 skill 的完整码表反查，避免测试自己再写一份（防漂移）
    from skills.morse_decoder import MORSE_TABLE as _MT
except Exception:  # noqa: BLE001
    _MT = {}
_MORSE_INV = {v: k for k, v in _MT.items()}


def _morse_enc(plain: str) -> str:
    return " ".join(_MORSE_INV.get(ch, "?") for ch in plain.lower())


def _vig_enc(plain: str, key: str) -> str:
    out, ki = [], 0
    for ch in plain:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + (ord(key[ki % len(key)]) - 97)) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


# ── ① 运行时「活着」守卫：任何 kind 都不得因未定义名崩溃 ────────────────────
# 只选不需要外部文件/网络、且契约明确的 kind，避免测试本身不可靠。
_KIND_PROBES = (
    ("morse", {"s": _morse_enc("hello")}),
    ("morse", {"s": ""}),
    ("vigenere", {"s": _vig_enc("flag{vigenere}", "key")}),
    ("vigenere", {"s": _vig_enc("flag{vigenere}", "key"), "key": "key"}),
    ("vigenere", {"s": ""}),
    ("wiener", {"s": ""}),
    ("caesar", {"s": "khoor"}),
    ("b64", {"s": "ZmxhZ3t4fQ=="}),
    ("bacon", {"s": "AAAAA"}),
    ("rail", {"s": "abc"}),
    ("affine", {"s": "abc"}),
    ("base58", {"s": "Z"}),
    ("hash", {"s": "5d41402abc4b2a76b9719d911017c592"}),
)


@pytest.mark.parametrize("kind,params", _KIND_PROBES,
                         ids=[f"{k}-{i}" for i, (k, _) in enumerate(_KIND_PROBES)])
def test_kind_does_not_crash_on_undefined_name(kind, params):
    """每个 kind 都必须能跑完，不得出现「直出失败」（NameError 等未定义名崩溃）。

    这是本测试存在的首要理由：vigenere / wiener 曾 100% 抛 NameError，
    被外层 except 静默兜成 ok=False，日志无痕。
    """
    r = fast_solve(kind, **params)
    assert r is not None, f"{kind} 返回 None（应返回 dict）"
    assert isinstance(r, dict), f"{kind} 返回 {type(r)} 而非 dict"
    blob = str(r)
    assert "直出失败" not in blob, (
        f"{kind} 崩溃被静默兜底（很可能是调用了未定义的名字）: {blob[:160]}")
    assert "NameError" not in blob, f"{kind} 出现 NameError: {blob[:160]}"


# ── ② 摩斯：数字与 F 必须解得出，未知 token 不得静默丢弃 ────────────────────
def test_morse_decodes_digits():
    """含数字的摩斯必须解对（原内联码表无 0-9 ⇒ m0rse2026 → MRSE）。"""
    r = fast_solve("morse", s=_morse_enc("m0rse2026"))
    assert r.get("flag") == "m0rse2026", r


def test_morse_decodes_letter_f():
    """含 F 的摩斯必须解对（原内联码表缺 `..-.` ⇒ flagmorse → LAGMORSE）。"""
    assert fast_solve("morse", s=_morse_enc("flagmorse")).get("flag") == "flagmorse"


def test_morse_unknown_token_is_not_silently_dropped():
    """未知 token 必须留 '?' 占位，不得静默丢弃（静默丢弃 = 少字但不报错）。"""
    r = fast_solve("morse", s=".... . .-.. .-.. --- ....... ")
    assert r.get("flag", "").count("?") >= 1, f"未知 token 被静默丢弃: {r}"


# ── ③ 维吉尼亚：有 key 走精确路径；无 key 不得崩溃 ──────────────────────────
def test_vigenere_with_key_decodes_exactly():
    """有 key 时必须精确解出（原实现这一步就 NameError，根本走不到）。"""
    plain = "flag{v1genere_ok}"
    r = fast_solve("vigenere", s=_vig_enc(plain, "key"), key="key")
    assert r.get("ok") is True, r
    assert plain in str(r.get("flag", "")), r


def test_vigenere_without_key_returns_dict_not_crash():
    """无 key 时不得崩溃。

    诚实标注：无 key 走卡方频率分析，对**短文本**不可靠（实测解不出），
    所以这里只断言「不崩溃且返回 dict」，不断言解对——避免测试自己骗自己。
    """
    r = fast_solve("vigenere", s=_vig_enc("flag{short}", "key"))
    assert isinstance(r, dict), r
    assert "直出失败" not in str(r), r


# ── ④ 维纳：连分数语义 + 真解出 ─────────────────────────────────────────────
def test_continued_fraction_returns_numerator_over_denominator():
    """`_continued_fraction(e, n)` 必须返回 (分子, 分母)，最后一个收敛子 = e/n。

    这是 Wiener 修复的根因断言：原实现初值写反 ⇒ 返回 (分母, 分子)，
    修复前 cf(3, 7)[-1] == (7, 3)，修复后 == (3, 7)。
    """
    from skills.rsa_fermat_factor import _continued_fraction
    assert _continued_fraction(3, 7)[-1] == (3, 7)
    assert _continued_fraction(7, 3)[-1] == (7, 3)


def test_wiener_missing_params_is_note_not_crash():
    """缺 n/e/c 时给 note，不得崩成「直出失败」。"""
    r = fast_solve("wiener", s="")
    assert isinstance(r, dict) and r.get("ok") is False, r
    assert "直出失败" not in str(r), r
    assert "缺参数" in str(r.get("note", "")), r


def test_wiener_solves_small_private_exponent():
    """维纳攻击必须真解出（修复前：d/n = 0.18~0.25 全部 None）。"""
    gmpy2 = pytest.importorskip("gmpy2")
    pytest.importorskip("Crypto.Util.number")
    from Crypto.Util.number import bytes_to_long, getPrime, inverse

    p, q = getPrime(256), getPrime(256)
    n, phi = p * q, (p - 1) * (q - 1)
    # Wiener 条件：d < (1/3)·n^0.25；取 n^0.20 留足余量
    d = int(gmpy2.mpz(n) ** gmpy2.mpfr("0.20")) | 1
    for _ in range(20000):
        try:
            if gmpy2.gcd(d, phi) == 1:
                e = int(inverse(d, phi))
                if 1 < e < phi:
                    break
        except Exception:  # noqa: BLE001
            pass
        d += 2
    else:
        pytest.skip("未能构造出合法 (e, d) 对")

    expect = "flag{wiener_ok_2026}"
    c = pow(bytes_to_long(expect.encode()), e, n)
    r = fast_solve("wiener", n=n, e=e, c=c)
    assert r.get("ok") is True, r
    assert expect in str(r.get("flag", "")), f"维纳未解出: {r}"
