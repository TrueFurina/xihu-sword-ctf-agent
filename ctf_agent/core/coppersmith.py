# -*- coding: utf-8 -*-
"""Coppersmith 平滑因子 / 小根求解器（首一化格 + 精确 Hensel 求根，纯 Python + python-flint LLL）。

适用题型
--------
Google CTF 2023「PRIMES」及其同类：给定素数 ``q`` 与

    x = ∏ p_i^{b_i}  (mod q),   M = ∏ p_i   （M 为已知平滑整数，p_i 为已知小素数）

真实整数 ``T = ∏ p_i^{b_i}`` 满足 ``T ≡ x (mod q)`` 且 ``T | M``，故存在未知整数 ``y`` 使
``T = x + y·q``。本模块用 Howgrave-Graham / Coppersmith 格基法找回 ``y``，再用
``T % p_i == 0`` 还原比特 ``b_i``，重组得明文。

🔴 三条踩坑总结（改本文件前必读，都是实测烧出来的）
------------------------------------------------
1. **多项式必须首一**：令 ``c = x·q^{-1} mod M``，取 ``f(y) = y + c``。
   若直接用非首一的 ``x + q·y``，首项系数 ``q`` 会进入格行列式，可达 ``X`` 上限从
   ``M^0.269`` 塌到 ``M^0.073``（本题：2^1419 → 2^391，而真 y=2^1446）→ **永远不可能命中**。
2. **X 必须大于真 y**，且不能"差不多就行"。Howgrave-Graham 的界是
   ``|G(y0)| ≤ √w·‖v‖·(|y0|/X)^{deg}``；当 ``y0 > X`` 时 ``(|y0|/X)^{deg}`` 会把界撑爆，
   表现为"格范数明明低于阈值、所有基多项式都被 T^m 整除，但就是没有整数根"。
   真 y 事先未知 → :func:`solve_primes` 默认扫 X 阶梯（与官方 wp 扫到 b=1450 同思路）。
3. **求根必须走精确 Hensel**：``sympy.Poly.ground_roots`` 在 4 万 bit 系数上要分解整数
   （实测挂死 17 分钟）；``nroots`` 在 400+ 位精度下不收敛。:func:`roots_hensel`
   用"模小素数枚举 + 逐次平方提升 + 整数硬校验"，毫秒级且零误差。

依赖：``python-flint``（缺则抛 :class:`LatticeBackendMissing`，与 ``core/lattice`` 一致）+
``sympy``（素数表 / nextprime）。
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from core.lattice import LatticeBackendMissing, lll, require_backend  # noqa: F401

__all__ = [
    "CoppersmithError", "roots_hensel", "small_roots_monic_linear",
    "find_small_divisor", "divisor_to_bits", "solve_primes", "gen_q_x",
]

# 默认 (m, t) 阶梯：按维数升序，先便宜后贵
_MT_LADDER: Tuple[Tuple[int, int], ...] = (
    (4, 4), (4, 6), (6, 6), (6, 9), (8, 8), (8, 12),
    (10, 10), (10, 15), (12, 18), (14, 21),
)


class CoppersmithError(RuntimeError):
    """Coppersmith 链路上的可预期失败（无解 / 依赖缺失 / 参数非法）。"""


# --------------------------------------------------------------------------
# 精确整数求根（Hensel 提升）
# --------------------------------------------------------------------------
def _eval_mod(coeffs: Sequence[int], y: int, m: int) -> int:
    acc = 0
    for co in reversed(coeffs):
        acc = (acc * y + co) % m
    return acc


def _eval_int(coeffs: Sequence[int], y: int) -> int:
    acc = 0
    for co in reversed(coeffs):
        acc = acc * y + co
    return acc


def _deriv(coeffs: Sequence[int]) -> List[int]:
    return [j * coeffs[j] for j in range(1, len(coeffs))]


def roots_hensel(coeffs: Sequence[int], X: int,
                 ps: Sequence[int] = (10007, 10009, 65537)) -> List[int]:
    """返回多项式在 ``[0, X)`` 内的**全部精确整数根**（Hensel 提升 + 整数硬校验）。

    步骤：模小素数 p 枚举根 → 对单根做逐次平方的 Hensel 提升至 p^k > X → 精确求值确认。
    不做大整数分解、不做高精数值迭代，因此不受系数量级影响。
    """
    c = list(coeffs)
    while len(c) > 1 and c[-1] == 0:
        c.pop()
    if len(c) <= 1:
        return []
    dc = _deriv(c)
    out: List[int] = []
    for p in ps:
        cp = [co % p for co in c]
        cands = [r for r in range(p) if _eval_mod(cp, r, p) == 0]
        if not cands:
            continue
        mod = p
        while mod <= X:                 # 需要 p^k > X
            mod *= p
        for r in cands:
            if _eval_mod(dc, r, p) == 0:
                continue                # 重根：无法提升，换素数
            y, m, ok = r, p, True
            while m < mod:
                m2 = m * m
                gy = _eval_mod(c, y, m2)
                dgy = _eval_mod(dc, y, m2)
                if dgy % p == 0:
                    ok = False
                    break
                t = (-(gy // m) * pow(dgy % m, -1, m)) % m
                y = (y + t * m) % m2
                m = m2
            if not ok or _eval_mod(c, y, m) != 0:
                continue
            for cand in (y, y - m if y >= m else y, y + m):
                if 0 <= cand < X and _eval_int(c, cand) == 0:
                    out.append(cand)
        if out:
            break
    return sorted(set(out))


# --------------------------------------------------------------------------
# 首一化格构造 + LLL
# --------------------------------------------------------------------------
def _poly_mul(a: Sequence[int], b: Sequence[int]) -> List[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            out[i + j] += ai * bj
    return out


def _build_lattice(N: int, c: int, X: int, m: int, t: int) -> List[List[int]]:
    """首一 Howgrave-Graham 格，行 j 列按 ``X^j`` 缩放。

    多项式族（``f(y) = y + c`` 首一）::

        g_i(y) = N^{m-i}·f(y)^i      i = 0..m-1   （次数 i）
        h_i(y) = y^i·f(y)^m         i = 0..t-1   （次数 m+i）

    在真根 y0 处均被未知因子 T 的 m 次幂整除（因 T | N 且 T | f(y0)）。
    """
    w = m + t
    f = [c % N, 1]
    fpow: List[List[int]] = [[1]]
    for _ in range(m):
        fpow.append(_poly_mul(fpow[-1], f))
    rows: List[List[int]] = []
    for i in range(m):
        poly = [co * (N ** (m - i)) for co in fpow[i]]
        rows.append(poly + [0] * (w - len(poly)))
    for i in range(t):
        poly = [0] * i + fpow[m]
        rows.append(poly + [0] * (w - len(poly)))
    return [[row[j] * (X ** j) for j in range(w)] for row in rows]


def small_roots_monic_linear(N: int, c: int, X: int, m: int, t: int,
                             max_rows: int = 5,
                             verbose: bool = False) -> List[int]:
    """求首一线性式 ``f(y) = y + c`` 模 N 的未知因子意义下的小根。

    Returns:
        ``[0, X)`` 内使对应多项式恰为零的候选根列表（已按短行顺序去重排序）。
    """
    require_backend()
    if X <= 0:
        raise CoppersmithError("X 必须为正整数（y 的上界估计）")
    if N <= 0:
        raise CoppersmithError("N 必须为正整数")
    rows = _build_lattice(N, c, X, m, t)
    reduced = lll(rows)
    w = m + t
    reduced.sort(key=lambda v: sum(z * z for z in v))
    out: List[int] = []
    tried = 0
    for row in reduced:
        if all(z == 0 for z in row):
            continue
        coeffs = [row[j] // (X ** j) for j in range(w)]
        for y0 in roots_hensel(coeffs, X):
            if y0 not in out:
                out.append(y0)
        tried += 1
        if tried >= max_rows:
            break
    if verbose and out:
        print(f"  [coppersmith] m={m} t={t} X=2^{X.bit_length() - 1} -> "
              f"{len(out)} 个候选根 {[r.bit_length() for r in out]} bits")
    return out


# --------------------------------------------------------------------------
# 对外：找回 y 使 (x + y·q) | M
# --------------------------------------------------------------------------
def find_small_divisor(x: int, q: int, M: int, X: int,
                       m: int = 6, t: int = 9,
                       verbose: bool = False) -> Optional[int]:
    """找回 ``y ∈ [0, X)`` 使 ``(x + y·q)`` 整除 ``M``（首一化路径）。

    先化首一 ``c = x·q^{-1} mod M``，再跑格；命中后用 ``M % (x + y·q) == 0`` 硬校验。
    """
    require_backend()
    if x <= 0 or q <= 0 or M <= 0:
        raise CoppersmithError("x/q/M 必须为正整数")
    c = (x * pow(q, -1, M)) % M
    for y0 in small_roots_monic_linear(M, c, X, m, t, verbose=verbose):
        T = x + y0 * q
        if T != 0 and M % T == 0:
            if verbose:
                print(f"  [coppersmith] 命中 y={y0.bit_length()} bits, "
                      f"T={T.bit_length()} bits")
            return y0
    return None


# --------------------------------------------------------------------------
# 由因子还原比特 / 明文
# --------------------------------------------------------------------------
def divisor_to_bits(T: int, primes: Sequence[int]) -> List[int]:
    """给定 ``T = x + y·q``（M 的因子），按 primes 顺序给出比特 b_i = 1 iff p_i | T。"""
    return [1 if (T % p == 0) else 0 for p in primes]


def _bits_to_flag(bits: Sequence[int]) -> str:
    """7-bit LSB-first 每字节重组为 ASCII（与 chal.sage 的 to_bits 互逆）。"""
    out = bytearray()
    for k in range(0, len(bits) - (len(bits) % 7), 7):
        chunk = bits[k:k + 7]
        if all(b == 0 for b in chunk):
            break
        val = 0
        for j, b in enumerate(chunk):
            val |= (b << j)
        out.append(val)
    try:
        return out.decode("ascii")
    except UnicodeDecodeError:
        return out.decode("latin-1")


# --------------------------------------------------------------------------
# 端到端：PRIMES
# --------------------------------------------------------------------------
def _first_primes(n: int) -> List[int]:
    """返回前 n 个素数（与 Sage ``Primes()[:n]`` 一致）。"""
    if getattr(_first_primes, "_cache_n", 0) >= n:
        return _first_primes._cache[:n]          # type: ignore[attr-defined]
    import sympy
    limit = 20
    while True:
        cand = list(sympy.primerange(2, limit))
        if len(cand) >= n:
            _first_primes._cache = cand          # type: ignore[attr-defined]
            _first_primes._cache_n = len(cand)   # type: ignore[attr-defined]
            return cand[:n]
        limit *= 2


def _x_ladder(logM: int, logq: int) -> List[int]:
    """X = 2^b 的扫描阶梯（b 升序）。

    真 y 的位长 = β·logM − logq，β 取决于明文比特密度（通常 0.5 上下）且事先未知，
    故按 β ∈ [0.50, 0.62] 铺 12 档；X 越小格越容易，因此升序先试小的。
    """
    lo = max(64, int(0.50 * logM) - logq)
    hi = max(lo + 1, int(0.62 * logM) - logq)
    step = max(1, (hi - lo) // 11)
    bs = list(range(lo, hi + 1, step))
    if bs[-1] != hi:
        bs.append(hi)
    return bs


def solve_primes(q: int, x: int, n: int, r: int = 131,
                 X: Optional[int] = None,
                 mt_ladder: Sequence[Tuple[int, int]] = _MT_LADDER,
                 max_attempts: int = 24,
                 verbose: bool = False) -> str:
    """端到端：由公钥 ``(q, x)`` 与参数 ``(n, r)`` 恢复明文。

    Args:
        q, x: 题面公开值（注意：chal.sage 注释里的 q/x 才是真输入，源码里的 m 是诱饵）。
        n: 明文比特数 = 7 × 字节数（= 素数个数）。
        r: 构造 q 时取末尾 r 个素数（默认 131，与 Google CTF 2023 一致）。
        X: 显式指定 y 上界；为 None 时按 :func:`_x_ladder` 扫阶梯。
        mt_ladder: (m, t) 阶梯，按维数升序。
        max_attempts: 最多尝试多少次 (X, m, t) 组合。
    Returns:
        恢复出的明文字符串（ASCII）。
    Raises:
        CoppersmithError: 全部组合未命中（X 范围不对 / 参数不匹配）。
    """
    require_backend()
    primes = _first_primes(n)
    M = 1
    for p in primes:
        M *= p
    logM, logq = M.bit_length(), q.bit_length()
    c = (x * pow(q, -1, M)) % M

    if X is not None:
        xbs = [X.bit_length() - 1]
    else:
        xbs = _x_ladder(logM, logq)

    # 循环顺序：(m,t) 在外、X 在内 —— 小维格又便宜又常够用；
    # 反过来（X 在外）会在错误量级的 X 上把整条 (m,t) 阶梯白跑一遍，实测慢一个数量级。
    attempts = 0
    for (m, t) in mt_ladder:
        for b in xbs:
            attempts += 1
            if attempts > max_attempts:
                raise CoppersmithError(
                    f"达到 max_attempts={max_attempts} 仍未命中（最后尝试 "
                    f"m={m}, t={t}, X=2^{b}）")
            for y0 in small_roots_monic_linear(M, c, 1 << b, m, t, verbose=verbose):
                T = x + y0 * q
                if T != 0 and M % T == 0:
                    if verbose:
                        print(f"  [primes] 命中 X=2^{b} m={m} t={t}: "
                              f"T={T.bit_length()} bits")
                    return _bits_to_flag(divisor_to_bits(T, primes))
    raise CoppersmithError("Coppersmith 未命中（X 阶梯未覆盖真 y，或体制参数不匹配）")


# --------------------------------------------------------------------------
# 自造实例（已知答案，供测试用）
# --------------------------------------------------------------------------
def sympy_nextprime(n: int) -> int:
    import sympy
    return int(sympy.nextprime(n))


def gen_q_x(flag: bytes, r: int = 131) -> Tuple[int, int, int]:
    """自造实例：由明文 flag 生成 (q, x, n)，供测试 / 已知答案验证用。

    ⚠️ ``r`` 必须与真实题同比例（真实 r/n = 131/518 ≈ 0.253）。r/n 过小会让 q 偏小、
    y 偏大，Coppersmith 界不再成立 —— 这不是算法问题，是参数比例问题。
    """
    n = 7 * len(flag)
    primes = _first_primes(n)
    P = 1
    for pi in primes[n - r:]:
        P *= pi
    q = sympy_nextprime(P)
    b = [(byte >> j) & 1 for byte in flag for j in range(7)]
    T = 1
    for pi, bi in zip(primes, b):
        if bi:
            T *= pi
    return q, T % q, n
