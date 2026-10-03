# -*- coding: utf-8 -*-
"""crypto_knapsack_mhk skill：MHK / MHK2 背包公钥加密的**等价密钥恢复**攻击。

适用题型
--------
Google CTF 2023「MHK2」及其同类（Murakami 背包体制，MHK1 是单密钥版）。
题面特征：公钥 ``a = [a_1..a_n]``（n 通常 256），``a_j = e·s_j mod p``，
其中 ``s_j ∈ [0, 2^128)``、``p = sum(s) + 2`` 为素数、``e ∈ [(p-1)/2, p-1]``。
密文是逐比特加密：两个独立公钥各加密同一比特，解密 ``bit = (M1 + M2) % 2``。

为什么常规做法解不动
--------------------
背包问题本身 NP 难，但**这里的模数 p 由私钥自己决定**（``p = sum(s)+2``），
带来一个致命结构：正交格 ``L(a) = {t : <t,a> = 0}`` 的 LLL 短向量里，
绝大多数满足 ``<t,s> = 0``，恰有 1 个满足 ``<t,s> = ±p``。
先用 254 个前者把 s 关进一个 **rank-2 格**，再用后者与 ``p = sum(s)+2`` 联立，
就得到一个右端极小的二元丢番图方程，可精确解出私钥。
全程只需 LLL + HNF，不需要解背包。

攻击链路
--------
1. 正交格 ``L(a)``（rank n-1）→ **饱和**整数基 → LLL → n-1 个短向量；
2. 逐个假设第 i 个是"特殊向量" t0（其余 n-2 个满足 <t,s>=0），
   取其余的饱和核 → rank-2 格 ∋ s → LLL 得 g1, g2；
3. 令 ``s = α·g1 + β·g2``，联立 ``<t0,s> = σ·p`` 与 ``p = sum(s)+2``：
       ``α·(<t0,g1> - σ·sum g1) + β·(<t0,g2> - σ·sum g2) = 2σ``
   右端只有 ±2 → 扩展 gcd 解出 (α,β) 的一维整数族；
4. 用 ``0 ≤ s_j < 2^128`` 的区间约束求 k 的交集 → 逐候选校验
   ``e·s_j ≡ a_j (mod p)`` 且 p 为素数 → 命中即私钥；
5. ``p = sum(s)+2``，``e = -sum(a)/2 mod p``。

工程坑（本机实测，改代码前务必读）
----------------------------------
* **flint 的 ``nullspace()`` 非饱和** → 格指数暴涨、LLL 完全失效
  （255 维格 LLL 后范数 2^134，而非理论 2^4）。必须用 :func:`saturated_kernel`
  的「转置 + HNF(transform=True)」写法。见 ``core/lattice.py``。
* **特殊向量不能靠"范数最大"挑**：实测 255 个向量范数全落在 8~10 bit，
  无法区分。做法是逐个 drop 尝试 + 校验（失败就换下一个）。
* **(α,β) 量级 ~2^66，盲枚举无解** → 必须走丢番图 + 区间约束。
* **n 太小攻击不成立**：n=16/24/32 时正交格短向量范数相对 p 过大，
  "恰 1 个特殊向量"的假设失效（实测 ❌）；n≥48 稳定成立。
  MHK2 的 n=256 实测两把公钥都在 drop=254 命中，单把约 150s。

依赖：``python-flint``（格运算后端，缺则明确报错，不做浮点兜底）+ ``sympy``（素性）。
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from core.lattice import lll, norm2_bits, saturated_kernel

try:  # sympy 仅用于素性测试，缺失时降级到 Miller-Rabin
    from sympy import isprime as _isprime
except Exception:  # pragma: no cover
    _isprime = None

MAX_K_SPAN = 1_000_000  # k 区间超过这个宽度就放弃该 drop（真解区间远小于此）


class MHKAttackError(RuntimeError):
    """攻击链路上的可预期失败（未命中 / 依赖缺失 / 参数不合法）。"""


# --------------------------------------------------------------------------
# 数论小工具
# --------------------------------------------------------------------------
def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展欧几里得：返回 (g, u, v) 使 a·u + b·v = g = gcd(a,b)。"""
    if b == 0:
        if a == 0:
            return 0, 0, 0
        return (abs(a), 1 if a > 0 else -1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _is_prime(n: int) -> bool:
    if _isprime is not None:
        return bool(_isprime(n))
    # Miller-Rabin 兜底（确定性基组，n < 3.3e24 足够）
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _validate(a: Sequence[int], a_sum: int, s: Sequence[int],
              s_bits: int, check_range: bool = True) -> Optional[Tuple[int, int]]:
    """校验候选私钥 s：区间合法 + p 为素数 + e·s_j ≡ a_j (mod p)。

    返回 (p, e) 或 None。``a_sum`` = sum(a)（调用方传入以免重复求和）。
    """
    lim = 1 << s_bits
    if min(s) < 0 or max(s) >= lim:
        return None
    p = sum(s) + 2
    if not _is_prime(p):
        return None
    e = (-a_sum) * pow(2, -1, p) % p
    if check_range and not ((p - 1) // 2 <= e <= p - 1):
        return None
    if all((e * sj - aj) % p == 0 for aj, sj in zip(a, s)):
        return p, e
    return None


# --------------------------------------------------------------------------
# 第 3 步：丢番图解 (α, β)
# --------------------------------------------------------------------------
def _recover_from_pair(a: Sequence[int], a_sum: int, t0: Sequence[int],
                       g1: Sequence[int], g2: Sequence[int],
                       s_bits: int) -> Optional[Tuple[int, int, List[int]]]:
    """已知 s ∈ span(g1,g2) 且 <t0,s> = ±p，解出 s。

    联立 ``<t0,s> = σ·p`` 与 ``p = sum(s)+2``（σ=±1）：
        α·(T1 - σ·S1) + β·(T2 - σ·S2) = 2σ
    其中 T_i = <t0,g_i>、S_i = sum(g_i)。右端只有 ±2，故可用扩展 gcd 精确求解。
    """
    lim = 1 << s_bits
    t1 = sum(x * y for x, y in zip(t0, g1))
    t2 = sum(x * y for x, y in zip(t0, g2))
    s1, s2 = sum(g1), sum(g2)

    for sigma in (1, -1):
        ca, cb, cc = t1 - sigma * s1, t2 - sigma * s2, 2 * sigma
        g, u, v = _egcd(ca, cb)
        if g == 0 or cc % g:
            continue
        a0, b0 = u * (cc // g), v * (cc // g)     # 一个特解
        da, db = cb // g, -ca // g                # 齐次解方向
        # s(k) = (a0 + k·da)·g1 + (b0 + k·db)·g2 = u_j + k·v_j（逐坐标）
        us = [a0 * x + b0 * y for x, y in zip(g1, g2)]
        vs = [da * x + db * y for x, y in zip(g1, g2)]

        klo, khi = None, None
        ok = True
        for u0, v0 in zip(us, vs):
            # 约束 0 ≤ u0 + k·v0 ≤ lim-1 → k ∈ [lo, hi]（Python // 向下取整）
            if v0 == 0:
                if not (0 <= u0 < lim):
                    ok = False
                    break
                continue
            if v0 > 0:
                lo = -(u0 // v0)              # ceil(-u0/v0) = -floor(u0/v0)
                hi = (lim - 1 - u0) // v0
            else:
                w = -v0
                lo = -((lim - 1 - u0) // w)   # ceil((u0-(lim-1))/w)
                hi = u0 // w
            klo = lo if klo is None else max(klo, lo)
            khi = hi if khi is None else min(khi, hi)
            if klo > khi:
                ok = False
                break
        if not ok or klo is None:
            continue
        if khi - klo > MAX_K_SPAN:
            continue

        k = klo
        while k <= khi:
            s = [u0 + k * v0 for u0, v0 in zip(us, vs)]
            r = _validate(a, a_sum, s, s_bits)
            if r:
                return r[0], r[1], s
            k += 1
    return None


# --------------------------------------------------------------------------
# 主攻击
# --------------------------------------------------------------------------
def recover_secret_key(a: Sequence[int], s_bits: int = 128,
                       verbose: bool = False) -> Optional[Dict]:
    """从公钥 a 恢复 MHK 私钥。

    Args:
        a: 公钥序列（长度 n，建议 n ≥ 48）。
        s_bits: 私钥元素位宽（MHK2 为 128）。
        verbose: 打印诊断（正交格范数分布、命中 drop 序号）。
    Returns:
        ``{'p': int, 'e': int, 's': list[int], 'drop': int}`` 或 None（未命中）。
    """
    a = [int(x) for x in a]
    if len(a) < 8:
        raise MHKAttackError(f"公钥长度 {len(a)} 过短（攻击需 n ≥ 48，至少 ≥8 才有意义）")
    a_sum = sum(a)

    orth = lll(saturated_kernel([a]))
    if verbose:
        nrms = sorted(norm2_bits(v) for v in orth)
        print(f"  正交格 LLL：{len(orth)} 个向量，‖·‖² 位长 min={nrms[0]} max={nrms[-1]}")

    for drop in range(len(orth)):
        t0 = orth[drop]
        good = [v for i, v in enumerate(orth) if i != drop]
        rank2 = lll(saturated_kernel(good))
        if len(rank2) != 2:
            continue
        r = _recover_from_pair(a, a_sum, t0, rank2[0], rank2[1], s_bits)
        if r:
            if verbose:
                print(f"  ✅ drop={drop} 命中（共 {len(orth)} 个候选）")
            return {"p": r[0], "e": r[1], "s": r[2], "drop": drop}
    return None


def decrypt_mhk2(pk: Dict, ct: Sequence[Sequence[int]],
                 s_bits: int = 128, verbose: bool = False) -> str:
    """MHK2 端到端解密：pk={'a1': [...], 'a2': [...]}，ct=[(c1, c2), ...]。

    明文编码是 **7-bit ASCII 塞进 8 bit**（最高位补 0），故按 8 位一组取低 7 位。
    """
    keys = {}
    for name in ("a1", "a2"):
        if name not in pk:
            raise MHKAttackError(f"公钥缺少 '{name}'")
        if verbose:
            print(f"[{name}] 恢复密钥中...")
        r = recover_secret_key(pk[name], s_bits=s_bits, verbose=verbose)
        if not r:
            raise MHKAttackError(f"[{name}] 等价密钥恢复失败")
        keys[name] = (r["p"], r["e"])
        if verbose:
            print(f"[{name}] ✅ p={r['p']}")

    (p1, e1), (p2, e2) = keys["a1"], keys["a2"]
    bits = []
    for c1, c2 in ct:
        m1 = pow(e1, -1, p1) * int(c1) % p1
        m2 = pow(e2, -1, p2) * int(c2) % p2
        bits.append(str((m1 + m2) % 2))
    bits = "".join(bits)
    return "".join(chr(int(bits[i:i + 7], 2))
                   for i in range(0, len(bits), 8) if len(bits[i:i + 7]) == 7)


# --------------------------------------------------------------------------
# skill 入口
# --------------------------------------------------------------------------
def crypto_knapsack_mhk(params: dict) -> dict:
    """skill 入口。

    params:
        kind: 'recover_key'（恢复单把公钥的 p/e）
            - a: 公钥序列（必填）
            - s_bits: 私钥位宽，默认 128
        kind: 'mhk2_decrypt'（端到端解密 MHK2）
            - pk: {'a1': [...], 'a2': [...]}（必填）
            - ct: [(c1, c2), ...]（必填）
    """
    kind = params.get("kind", "")
    s_bits = int(params.get("s_bits", 128))
    verbose = bool(params.get("verbose", False))
    try:
        if kind == "recover_key":
            a = params.get("a")
            if not a:
                return {"ok": False, "error": "缺少公钥 a"}
            r = recover_secret_key(a, s_bits=s_bits, verbose=verbose)
            if not r:
                return {"ok": False, "error": "未命中（可能 n 过小或体制不匹配）"}
            return {"ok": True, "p": r["p"], "e": r["e"], "drop": r["drop"]}
        if kind == "mhk2_decrypt":
            pk, ct = params.get("pk"), params.get("ct")
            if not pk or not ct:
                return {"ok": False, "error": "缺少 pk 或 ct"}
            text = decrypt_mhk2(pk, ct, s_bits=s_bits, verbose=verbose)
            return {"ok": True, "plaintext": text}
        return {"ok": False, "error": f"unknown kind: {kind}"}
    except MHKAttackError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 —— 后端缺失等一律如实回报
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def run(params):
    """SkillManager 统一入口。"""
    return crypto_knapsack_mhk(params)


def main() -> None:
    import argparse
    import ast
    import json

    parser = argparse.ArgumentParser(description="MHK/MHK2 背包等价密钥恢复")
    parser.add_argument("--kind", required=True, choices=["recover_key", "mhk2_decrypt"])
    parser.add_argument("--pk", help="公钥 JSON 文件（两行：pk 字典、ct 列表）")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.kind == "recover_key":
        data = json.loads(Path(args.pk).read_text(encoding="utf-8"))
        print(crypto_knapsack_mhk({"kind": "recover_key", "a": data, "verbose": args.verbose}))
        return
    lines = [l for l in Path(args.pk).read_text(encoding="utf-8").splitlines() if l.strip()]
    pk, ct = ast.literal_eval(lines[0]), ast.literal_eval(lines[1])
    print(crypto_knapsack_mhk({"kind": "mhk2_decrypt", "pk": pk, "ct": ct, "verbose": args.verbose}))


if __name__ == "__main__":
    from pathlib import Path  # noqa: E402  （仅供 CLI 使用）

    main()
