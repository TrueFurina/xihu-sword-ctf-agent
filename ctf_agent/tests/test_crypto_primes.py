# -*- coding: utf-8 -*-
"""google-ctf-2023 PRIMES（子集积 mod q → Coppersmith 平滑因子）回归测试。

覆盖四件事：
1. **精确求根器** :func:`roots_hensel`：巨系数下必须既找得到根、又不伪造根。
   历史上这里踩过两次坑——``sympy.ground_roots`` 在 4 万 bit 系数上要分解整数（实测挂死
   17 分钟），``nroots`` 在 400+ 位精度下不收敛。Hensel 提升可避开二者。
2. **格构造前提**：所有基多项式在真根处必须被 ``T^m`` 整除（Howgrave-Graham 的立足点）。
   这条挂了，后面全白跑。
3. **端到端（小实例已知答案）**：自造实例必须解出原明文。
4. **端到端（真实例真值）**：Google CTF 2023 真 (q, x) → flag 的 sha256 必须等于题库里的
   ``flag_sha256``（慢测，``-m slow``）。

另外钉死一条**设计决策**：X 必须大于真 y。X 给小了不会报错，只会"格范数明明低于阈值、
基多项式也全被 T^m 整除，但一个整数根都没有"——这是本项目实测踩过的坑，必须有测看着。

变异验证（改动实现后必须手工复跑，确认本文件真的会红）
-----------------------------------------------------
* 把 ``_build_lattice`` 的 ``f = [c % N, 1]`` 改回非首一的 ``[x, q]`` 形式 → 端到端用例必须 FAIL
  （非首一时的可达 X 上限只有 M^0.073，覆盖不到真 y）；
* 把 ``roots_hensel`` 的 Hensel 提升去掉、只做模 p 枚举 → 端到端用例必须 FAIL；
* 把 ``_bits_to_flag`` 的 ``val |= (b << j)`` 改成 ``val = (val << 1) | b``（MSB-first）
  → 端到端用例必须 FAIL（7-bit 是 LSB-first）；
* 把 ``divisor_to_bits`` 的 ``T % p == 0`` 写成 ``T % p != 0`` → 端到端用例必须 FAIL。
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.coppersmith import (  # noqa: E402
    CoppersmithError, _bits_to_flag, _build_lattice, _first_primes,
    divisor_to_bits, find_small_divisor, gen_q_x, roots_hensel, solve_primes,
)
from core.lattice import has_backend  # noqa: E402

pytestmark = pytest.mark.skipif(
    not has_backend(), reason="python-flint 未安装（格后端缺失）")

# Google CTF 2023 «PRIMES» 真实例（chal.sage 注释里的 q/x；源码里的 m 是诱饵）
REAL_Q = int(
    "D2F8711CB5502C512ACEA59BE181A8FCF12F183B540D9A6998BF66370F9538F7E39FC507545DAD9AA2"
    "E71D3313F0B4408695A0A2C03A790662A9BD01650533C584C90779B73604FB8157F0AB7C9A82E724"
    "700E5937D9FF5FCF1EE3BE1EDD7E07B4C0F035A58CC2B9DB8B79F176F595C1B0E90B7957309B9610"
    "6A50A01B78171599B41C8744BCB1C0E6A24F60AE8946D37F4D4BD8CF286A336E1022996B3BA3918E"
    "4D808627D0315BFE291AEB884CBE98BB620DAA735B0467F3287D158231D", 16)
REAL_X = int(
    "947062E712C031ADD0B60416D3B87D54B50C1EFBC8DBB87346F960B242AF3DF6DD47406FEC98053A"
    "967D28FE91B130FF0FE93689122931F0BA6E73A3E9E6C873B8E2344A459244D1295E99A241E59E1"
    "EEA796E9738E6B1EDEED3D91AE6747E8ECA634C030B90B02BAF8AE0088058F6994C7CAC232835AC"
    "72D8B23A96F10EF03D74F82C49D4513423DAC298698094B5C631B9C7C62850C498330E9D112BB9C"
    "AA574AEE6B0E5E66D5B234B23C755AC1719B4B68133E680A7BCF48B4CFD0924D", 16)
REAL_FLAG_SHA256 = "df18e59de0157907864737b5f2a3d1a0fb5ffc4fe7e64a5f467c92054a783d56"


def _poly_mul(u, v):
    o = [0] * (len(u) + len(v) - 1)
    for i, ui in enumerate(u):
        for j, vj in enumerate(v):
            o[i + j] += ui * vj
    return o


def _build_case(flag: bytes):
    """构造已知答案实例，返回 (primes, M, q, x, T_true, y_true)。"""
    n = 7 * len(flag)
    r = max(1, round(n * 131 / 518))     # 必须与真实题同比例，否则 q 过小 -> y 过大不可行
    q, x, _ = gen_q_x(flag, r)
    primes = _first_primes(n)
    M = 1
    for p in primes:
        M *= p
    bits = [(b >> j) & 1 for b in flag for j in range(7)]
    T = 1
    for p, bi in zip(primes, bits):
        if bi:
            T *= p
    return primes, M, q, x, T, (T - x) // q


# --------------------------------------------------------------------------
# 1) 精确求根器
# --------------------------------------------------------------------------
def test_hensel_finds_large_integer_root():
    y0 = (1 << 1209) | 0xDEADBEEF
    G = _poly_mul(_poly_mul([-y0, 1], [-12345, 1]), [6789, 1])
    roots = roots_hensel(G, 1 << 1210)
    assert y0 in roots, "Hensel 未找回 1209-bit 整数根"
    for r in roots:  # 不得伪造：每个返回根都必须真的是根
        acc = 0
        for co in reversed(G):
            acc = acc * r + co
        assert acc == 0


def test_hensel_no_integer_root_returns_empty():
    assert roots_hensel([1, 0, 1], 1 << 64) == []          # y^2 + 1
    assert roots_hensel([3, 0, 0, 1], 1 << 64) == []       # y^3 + 3


def test_hensel_respects_X_bound():
    y0 = 123456789
    G = _poly_mul([-y0, 1], [-7, 1])          # 根：7 与 123456789
    lo = roots_hensel(G, y0)                  # 区间 [0, y0) 只应含 7
    assert 7 in lo and y0 not in lo
    assert y0 in roots_hensel(G, y0 + 1)


# --------------------------------------------------------------------------
# 2) 格构造前提：基多项式在真根处被 T^m 整除
# --------------------------------------------------------------------------
def test_basis_polys_vanish_mod_T_power():
    primes, M, q, x, T, y_true = _build_case(b"CTF{abcdefgh}")
    m, t = 4, 4
    X = 1 << (y_true.bit_length() + 6)
    c = (x * pow(q, -1, M)) % M
    rows = _build_lattice(M, c, X, m, t)
    w = m + t
    Tm = T ** m
    for row in rows:
        coeffs = [row[j] // (X ** j) for j in range(w)]
        acc = 0
        for co in reversed(coeffs):
            acc = acc * y_true + co
        assert acc % Tm == 0, "基多项式未在真根处被 T^m 整除（首一化或构造有误）"


# --------------------------------------------------------------------------
# 3) 端到端：小实例已知答案
# --------------------------------------------------------------------------
def test_solve_primes_small_end_to_end():
    flag = b"CTF{abcdefgh}"
    n = 7 * len(flag)
    r = max(1, round(n * 131 / 518))
    q, x, _ = gen_q_x(flag, r)
    _, _, _, _, T, y_true = _build_case(flag)
    got = solve_primes(q, x, n, r, X=1 << (y_true.bit_length() + 6))
    assert got == flag.decode("ascii")


def test_find_small_divisor_returns_true_y():
    primes, M, q, x, T, y_true = _build_case(b"CTF{hensel}")
    y = find_small_divisor(x, q, M, 1 << (y_true.bit_length() + 6))
    assert y == y_true
    assert (x + y * q) % T == 0


def test_X_smaller_than_true_y_yields_no_solution():
    """钉死坑 #2：X 小于真 y 时必须干净地报无解，不能返回错的 y。"""
    flag = b"CTF{abcdefgh}"
    n = 7 * len(flag)
    r = max(1, round(n * 131 / 518))
    q, x, _ = gen_q_x(flag, r)
    _, _, _, _, _, y_true = _build_case(flag)
    with pytest.raises(CoppersmithError):
        # X 比真 y 小一个数量级 -> 扫不到根。阶梯只取两档小格，避免大维格拖慢 CI
        solve_primes(q, x, n, r, X=1 << max(8, y_true.bit_length() // 8),
                     mt_ladder=((4, 4), (6, 6)), max_attempts=2)


# --------------------------------------------------------------------------
# 4) 比特重组（7-bit LSB-first）
# --------------------------------------------------------------------------
def test_bits_to_flag_roundtrip():
    primes, _, _, _, T, _ = _build_case(b"CTF{abcdefgh}")
    bits = divisor_to_bits(T, primes)
    assert _bits_to_flag(bits) == "CTF{abcdefgh}"
    # MSB-first 会得到乱码，确保不是那种实现
    msb = bytearray()
    for k in range(0, len(bits), 7):
        val = 0
        for b in bits[k:k + 7]:
            val = (val << 1) | b
        msb.append(val)
    assert bytes(msb) != b"CTF{abcdefgh}"


# --------------------------------------------------------------------------
# 5) 真实例真值（慢测）
# --------------------------------------------------------------------------
@pytest.mark.slow
def test_solve_primes_real_gctf2023_matches_flag_sha256():
    """真实例：真值锚点是题库里的 flag_sha256，不是"能跑通"。"""
    msg = solve_primes(REAL_Q, REAL_X, 518, 131, X=1 << 1460)
    i = msg.index("CTF{")
    flag = msg[i:msg.index("}", i) + 1]
    assert hashlib.sha256(flag.encode()).hexdigest() == REAL_FLAG_SHA256
    assert flag == "CTF{w0W_c0Nt1nUed_fr4Ct10ns_suR3_Ar3_fUn_Huh}"


@pytest.mark.slow
def test_solve_primes_real_default_X_ladder():
    """不给 X（skill 真实调用形态）也必须自己扫到正确量级并命中。"""
    msg = solve_primes(REAL_Q, REAL_X, 518, 131)
    i = msg.index("CTF{")
    flag = msg[i:msg.index("}", i) + 1]
    assert hashlib.sha256(flag.encode()).hexdigest() == REAL_FLAG_SHA256


# --------------------------------------------------------------------------
# 6) presolve 接线（未接线 = 只是库，不算能力）
# --------------------------------------------------------------------------
def test_skill_is_wired_into_presolve():
    from core import presolve as P

    assert "skills.crypto_primes_subset" in P.wired_skill_modules()
    assert callable(getattr(P, "_try_crypto_primes", None))


def test_recover_n_from_q_is_deterministic():
    """n 不给在题面里，必须由 q 反解（next_prime 自校验）——这条挂了整路就废了。"""
    from core import presolve as P

    assert P._recover_primes_n(REAL_Q, 131) == 518
    assert P._recover_primes_n(REAL_Q + 1, 131) is None      # 假 q 不得误判


@pytest.mark.slow
def test_presolve_path_solves_real_problem():
    """真实题目对象端到端：必须用 load_questions()（自建对象会因 flag_pattern
    缺失被诱饵守卫丢弃 → 假红）。"""
    import asyncio

    from eval.cases import load_questions

    qs = load_questions("data/questions_external")
    target = next((q for q in qs if getattr(q, "id", "") ==
                   "ext_gctf2023_primes"), None)
    assert target is not None, "题库里找不到 ext_gctf2023_primes"
    from core import presolve as P

    flag = asyncio.run(P._try_crypto_primes(target))
    assert flag, "presolve 接线路径未解出 flag"
    assert hashlib.sha256(flag.encode()).hexdigest() == REAL_FLAG_SHA256
