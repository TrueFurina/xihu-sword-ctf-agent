# -*- coding: utf-8 -*-
"""crypto_primes_subset skill：Google CTF 2023「PRIMES」题的确定性求解器。

题面（chal.sage 简化）
--------------------
把 flag 按 7-bit（LSB-first）展开成 n = 7·len(flag) 个比特 b_i，取前 n 个素数 p_i，
再取 ``q = next_prime(∏_{i=n-r}^{n-1} p_i)``（r=131）。密文是

    x = (∏ p_i^{b_i})  mod q

目标：由 (q, x) 恢复 flag。

为什么这道是「工具链题」而非「纯数论」
--------------------------------------
看似只要做「模 q 下子集积」——但 q-1 不平滑，离散对数 / 乘法背包的 LLL 法失效。
真解法是 **Coppersmith 平滑因子法**：真正的整数 ``T = ∏ p_i^{b_i}`` 满足

    T ≡ x (mod q)   且   T | M，其中 M = ∏_{i} p_i 是已知平滑整数

于是存在未知整数 y 使 ``T = x + y·q`` 且 ``(x + y·q) | M``。取**首一**多项式
``f(Y) = Y + c``（``c = x·q^{-1} mod M``）做 Howgrave-Graham / Coppersmith 格基约减找回 y，
再用 ``T % p_i == 0`` 判断哪些 p_i 参与了乘积（即比特 b_i），重组即得 flag。

🔴 三条实测踩坑（详见 :mod:`core.coppersmith` 模块头）
1. **必须首一**：直接用 ``x + q·Y`` 会让首项系数 q 进入格行列式，可达 X 上限从 M^0.269
   塌到 M^0.073（本题 2^1419 → 2^391），而真 y = 2^1446 → **永远命中不了**。
2. **X 必须大于真 y**：给小了不报错，只会「格范数低于阈值、基多项式全被 T^m 整除，
   但一个整数根都没有」。真 y 未知，故默认扫 X 阶梯（与官方 wp 扫到 b=1450 同思路）。
3. **求根走精确 Hensel**：``ground_roots`` 在巨系数上要分解整数（实测挂死 17 分钟），
   ``nroots`` 在 400+ 位精度不收敛。

后端：**python-flint 的 C 实现 LLL**（与 core/lattice 同一套），**无需 SageMath**。
核心算法在 :mod:`core.coppersmith`。

依赖：``python-flint``（格运算）+ ``sympy``（素数 / 素性 / 精确整数根 ``ground_roots``）。
"""

from __future__ import annotations

from typing import Dict

from core.coppersmith import solve_primes, gen_q_x, CoppersmithError


def crypto_primes_subset(params: dict) -> dict:
    """skill 入口。

    params:
        kind: 'solve'（由 (q,x) 恢复 flag）
            - q: 题面模数（int 或十六进制字符串）
            - x: 题面密文（int 或十六进制字符串）
            - n: 比特数 = 7 × 字节数（即素数个数）
            - r: 构造 q 时取最后 r 个素数，默认 131
            - X: y 上界估计（可选，默认按 M/q 体量与保守系数给）
        kind: 'gen'（自造已知答案实例，供测试 / 校验）
            - flag: 明文（str 或 bytes）
            - r: 默认 131
    """
    kind = params.get("kind", "solve")
    verbose = bool(params.get("verbose", False))
    try:
        if kind == "solve":
            q = _coerce_int(params.get("q"))
            x = _coerce_int(params.get("x"))
            n = int(params.get("n"))
            r = int(params.get("r", 131))
            if q is None or x is None or not n:
                return {"ok": False, "error": "solve 需要 q / x / n"}
            X = params.get("X")
            kw = {}
            if X is not None:
                kw["X"] = _coerce_int(X)
            flag = solve_primes(q, x, n, r=r, verbose=verbose, **kw)
            return {"ok": True, "flag": flag}
        if kind == "gen":
            flag = params.get("flag")
            if isinstance(flag, str):
                flag = flag.encode("utf-8", "latin-1")
            if not isinstance(flag, (bytes, bytearray)):
                return {"ok": False, "error": "gen 需要 flag(bytes/str)"}
            r = int(params.get("r", 131))
            q, x, n = gen_q_x(bytes(flag), r=r)
            return {"ok": True, "q": q, "x": x, "n": n}
        return {"ok": False, "error": f"unknown kind: {kind}"}
    except CoppersmithError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 —— 后端缺失等一律如实回报
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _coerce_int(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def run(params):
    """SkillManager 统一入口。"""
    return crypto_primes_subset(params)


def main() -> None:
    import argparse
    import ast
    import json

    ap = argparse.ArgumentParser(description="Google CTF 2023 PRIMES 求解器")
    ap.add_argument("--kind", required=True, choices=["solve", "gen"])
    ap.add_argument("--q")
    ap.add_argument("--x")
    ap.add_argument("--n", type=int)
    ap.add_argument("--r", type=int, default=131)
    ap.add_argument("--flag")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    if a.kind == "solve":
        print(crypto_primes_subset({"kind": "solve", "q": a.q, "x": a.x,
                                     "n": a.n, "r": a.r, "verbose": a.verbose}))
    else:
        print(crypto_primes_subset({"kind": "gen", "flag": a.flag, "r": a.r}))


if __name__ == "__main__":
    main()
