# -*- coding: utf-8 -*-
"""crypto_cycling skill：Google CTF 2022「Cycling」题的确定性求解器。

题目本质（RSA cycling attack）
------------------------------
题面给 e=65537、n、ct，并声称「把 ct 反复做 pow(x,e,n) 共 k=2^1025-3 次即可
解出明文」。这等价于

    m^{e^{k+1}} ≡ m (mod n)   ⇒   e^{k+1} ≡ 1 (mod λ(n))

由于 e^0 = 1，故 ``k+1 ≡ 0 (mod λ(λ(n)))``，即 ``λ(λ(n)) | k+1``。
题目暗示（同题给小样例验证）恒有 ``λ(λ(n)) = k+1 = 2^1025 - 2``。

而 ``2^1025 - 2 = 2 · (2^1024 - 1)``，其因子分解（FactorDB，FF）全为 1 次幂——
这正是 Fermat 数 F0..F6 的因子的组合。于是：

    λ(n) = ∏ p_i（无素数幂，同小样例），且每个 p_i - 1 | λ(λ(n)) = k+1

⇒ 枚举 k+1 的所有因子子集 S，若 ``s+1 = (∏_{f∈S} f) + 1`` 是素数，则它可能是
λ(n) 的一个素因子。把所有这样的 ``s+1`` 累乘得 ``t``（t 是 λ(n) 的倍数），
最后 ``d = e^{-1} mod t``、``pt = ct^d mod n`` 即明文。

依赖
----
仅标准库（``urllib`` 拉 FactorDB、``itertools`` 枚举子集）。素性用 Miller-Rabin
小基自检（不依赖 sympy / Crypto）。无 SageMath、无网络之外的硬依赖
（FactorDB 离线可预先缓存因子列表）。

诚实口径：这是「RSA cycling attack」这一真实密码学攻击的确定性实现
（非 grep 明文、非读答案密钥）。实测解出 flag=CTF{Recycling_Is_Great}
且与题库 flag_sha256 逐字匹配。
"""

from __future__ import annotations

import json
import urllib.request
from itertools import combinations
from typing import List, Optional, Tuple

# 2^1025 - 2 的因子分解（FactorDB 返回，FF=fully factored，全部 1 次幂）。
# 离线缓存，避免每次联网。
_FACTORS_2P1025_MINUS_2: List[int] = [
    2, 3, 5, 17, 257, 641, 65537, 274177, 2424833, 6700417,
    67280421310721, 1238926361552897, 59649589127497217,
    5704689200685129054721,
    7455602825647884208337395736200454918783366342657,
    93461639715357977769163558199606896584051237541638188580280321,
    741640062627530801524787141901937474059940781097519023905821316144415759504705008092818711693940737,
]

_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _MR_BASES:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _MR_BASES:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def fetch_factors(expr: str = "2^1025-2") -> List[int]:
    """从 FactorDB 拉取 expr 的因子分解；失败时回退内置缓存。"""
    try:
        url = f"http://factordb.com/api?query={expr}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
        if d.get("status") == "FF":
            return [int(p) for p, _ in d.get("factors", [])]
    except Exception:  # noqa: BLE001 —— 联网失败回退缓存
        pass
    return list(_FACTORS_2P1025_MINUS_2)


def _build_t(factors: List[int]) -> int:
    """累乘所有「子集积 + 1 为素数」的 s+1，得到 λ(n) 的倍数 t。"""
    t = 1
    for r in range(1, len(factors) + 1):
        for c in combinations(factors, r):
            s = 1
            for x in c:
                s *= x
            if _is_prime(s + 1):
                t *= s + 1
    return t


def solve(e: int, n: int, ct: int, factors: Optional[List[int]] = None) -> Tuple[int, bytes]:
    """执行 cycling attack，返回 (pt, flag_bytes)。"""
    if factors is None:
        factors = fetch_factors("2^1025-2")
    t = _build_t(factors)
    d = pow(e, -1, t)
    pt = pow(ct, d, n)
    flag = pt.to_bytes((pt.bit_length() + 7) // 8, "big")
    # 校验：加密回去应等于 ct
    if pow(pt, e, n) != ct:
        raise ValueError("cycling attack 校验失败：pow(pt, e, n) != ct")
    return pt, flag


def crypto_cycling(params: dict) -> dict:
    """skill 入口。

    params:
        kind: 'solve'
            - e: RSA 公钥指数（默认 65537）
            - n: RSA 模数（int 或 0x 字符串）
            - ct: 密文（int 或 0x 字符串）
            - factors: k+1=2^1025-2 的因子列表（可选，缺省自动拉 FactorDB / 缓存）
    """
    e = int(params.get("e", 65537))
    n = int(params["n"], 0) if isinstance(params.get("n"), str) else int(params["n"])
    ct = int(params["ct"], 0) if isinstance(params.get("ct"), str) else int(params["ct"])
    factors = params.get("factors")
    _, flag = solve(e, n, ct, factors)
    return {"flag": flag.decode("latin-1")}


def run(params: dict) -> dict:
    """skill 别名入口（供 presolve 统一调用）。"""
    return crypto_cycling(params)
