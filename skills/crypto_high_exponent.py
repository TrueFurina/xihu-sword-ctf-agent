"""crypto_high_exponent skill：高偶指数 RSA 攻击模板（e=65536=2^16 真题场景）。

真题（西湖论剑 2026-08-21 正式赛 CRYPTO-02 / 10733 "How many rot are there"）：
- e=65536, c=pow(m, e, n)，n=p*q；task.py 的 print(p)/print(q) 语句存在但附件注释块刻意只留 hint/c/n
- hint = pow(e*p+e**2, q, n) **可分解 n**（2026-08-21 实测验证，非干扰项）：
  二项式展开 + p^q≡p (mod n) => hint ≡ e^q·p + e^{2q} (mod n)
  mod p: hint ≡ e^{2q} = (e^q)²；令 W = e^n mod n，由 p≡1 (mod p-1) 得 pq≡q (mod p-1)
  => W ≡ e^q (mod p) => p | W²-hint => gcd(W²-hint, n) = p   ← factor_from_hint()
- 解密捷径（p,q 均 3 mod 4，v2(λ)=1）：在奇数阶子群 s=(p-1)/2 求 inv 使 2^15·inv≡1 (mod s)
  则 c^inv ≡ m² (mod p)，CRT 得 m² mod n，一轮 Rabin（4 根）即出 m
- ⚠️ 真题 flag 明文是 ROT13 编码的（QNFPGS{...}）：前缀过滤会 miss！
  printable 但无 DASCTF 前缀的候选要做 rot13/rot18 解码检查（题名 "How many rot" 即提示）

kind：
- gcd1:    gcd(e, phi)=1 → 常规 RSA 解密（d = e^{-1} mod phi，m = c^d mod n）
- e2k:     e=2^k → 逐轮 Tonelli-Shanks 平方根 → 前缀过滤；无命中则 CRT 组合
- factor:  已知 hint=pow(e*p+e**2, q, n) → W=e^n mod n, gcd(W²-hint, n) 分解 n
- nth_root: 通用模素数 e 次根（gcd(e,p-1)=1 用指数逆；否则提示 sage nth_root all=True）
- auto:    自动选择（有 hint 先 factor；e 与 phi 互素走 gcd1；e 为 2 的幂走 e2k）

纯 Python 实现（无需 sage）。注意：根数量可达 2^k（e=65536 → 65536 个/素数），
内存 O(2^k) 可承受；CRT 组合用「前缀范围定 k + q 根集合判重」避免 O(2^(2k)) 枚举。
"""

import math


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _ts_sqrt(a: int, p: int):
    """Tonelli-Shanks：求 sqrt(a) mod p 的任一平方根；a 非二次剩余返回 None。

    注意 p 须为奇素数。Legendre 符号预检避免无解时白跑。
    """
    a %= p
    if a == 0:
        return 0
    if p == 2:
        return a
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    # p-1 = q * 2^s（q 奇数）
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    # 找非二次剩余 z
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 1, t * t % p
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        b2 = b * b % p
        # 标准 TS：new_t = t * b²（用 b²，不是旧 c！旧实现误用 c 导致不变式破裂）
        m, c, t, r = i, b2, t * b2 % p, r * b % p
    return r


def all_2k_roots(c: int, p: int, k: int) -> list:
    """c 的所有 2^k 次方根 mod p（c 须为 2^k 次幂，即 c=m^(2^k)）。

    逐轮平方：第 i 轮把上一轮每个根的平方根（两个）加入集合。
    返回最多 2^k 个根（去重后）。c 在某轮非 QR 时提前终止（理论不应发生）。
    """
    roots = [c % p]
    for _ in range(k):
        nxt = []
        seen = set()
        for r in roots:
            s = _ts_sqrt(r, p)
            if s is None:
                continue
            if s not in seen:
                seen.add(s)
                nxt.append(s)
            s2 = (p - s) % p
            if s2 != s and s2 not in seen:
                seen.add(s2)
                nxt.append(s2)
        if not nxt:
            break
        roots = nxt
    return roots


def _int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, "big") if x else b"\x00"


def _match_prefix(x: int, prefixes: list) -> bool:
    b = _int_to_bytes(x)
    return any(b.startswith(p.encode("utf-8")) if isinstance(p, str) else b.startswith(p)
               for p in prefixes)


def _is_printable(x: int, min_ratio: float = 0.9) -> bool:
    """ASCII 可打印比例检查（辅助过滤非 flag 根）。"""
    b = _int_to_bytes(x)
    if not b:
        return False
    printable = sum(1 for ch in b if 32 <= ch < 127)
    return printable / len(b) >= min_ratio


def factor_from_hint(hint: int, e: int, n: int) -> dict:
    """hint = pow(e*p + e², q, n) 型泄露分解 n（10733 真题验证通过）。

    推导：hint ≡ e^q·p + e^{2q} (mod n)（二项式 + p^q≡p mod n + 中间项含 pq）
      mod p: hint ≡ (e^q)²
      W = e^n mod n；n=pq ≡ q (mod p-1)（因 p≡1 mod p-1）=> W ≡ e^q (mod p)
      => W² ≡ hint (mod p) => p | W²-hint
    返回 {"ok": True, "p": p, "q": q}；失败时顺带尝试 hint-e² 与 hint 本身的 gcd。
    """
    if not hint or not e or not n:
        return {"ok": False, "error": "缺少 hint/e/n"}
    W = pow(e, n, n)
    g = _gcd((W * W - hint) % n, n)
    tried = ["gcd(W^2-hint, n)"]
    if 1 < g < n:
        p, q = g, n // g
        return {"ok": True, "p": p, "q": q, "via": "W=e^n; gcd(W^2-hint, n)",
                "hint_note": "hint ≡ e^q*p + e^{2q} (mod n); mod p 即 (e^q)^2"}
    for cand, tag in ((hint, "hint"), ((hint - e * e) % n, "hint-e^2")):
        g = _gcd(cand, n)
        tried.append(f"gcd({tag}, n)")
        if 1 < g < n:
            return {"ok": True, "p": g, "q": n // g, "via": f"gcd({tag}, n)"}
    return {"ok": False, "error": f"hint 分解未命中（tried={tried}）",
            "suggest": "尝试 Fermat/Pollard rho 或 lattice（hint 可能是其它结构）"}


def _crt(a1: int, m1: int, a2: int, m2: int) -> int:
    return (a1 + m1 * ((a2 - a1) * pow(m1, -1, m2) % m2)) % (m1 * m2)


def recover_via_odd_subgroup(c: int, e: int, p: int, q: int, prefixes: list) -> dict:
    """e=2^k 且 v2(λ)=1（p,q 均 3 mod 4）时的快速路径（10733 验证）。

    mod p：c ≡ m^{2^k} = (m²)^{2^{k-1}}；在奇数阶子群 s=(p-1)/2 求 inv 使
    2^{k-1}·inv ≡ 1 (mod s) => c^inv ≡ m² (mod p)。CRT 得 m² mod n 后一轮 Rabin。
    候选若无 flag 前缀但可打印，自动做 rot13/rot18 解码检查（真题坑点）。
    """
    k = e.bit_length() - 1

    def square_mod(y: int, pr: int) -> int:
        s = (pr - 1) // 2
        inv = pow(pow(2, k - 1, s), -1, s)
        return pow(y % pr, inv, pr)

    m2 = _crt(square_mod(c, p), p, square_mod(c, q), q)
    if pow(m2, 1 << (k - 1), p * q) != c:
        return {"ok": False, "error": "m² 验证失败（v2(λ) 可能 >1，请走 e2k 逐轮开方）"}
    # 一轮 Rabin：m² 的 4 个平方根
    roots = []
    for pr, mod in ((p, "p"), (q, "q")):
        r = _ts_sqrt(m2 % pr, pr)
        if r is None:
            return {"ok": False, "error": "m² 开方失败"}
        roots.append([r, pr - r])
    out = []
    for a in roots[0]:
        for b in roots[1]:
            out.append(_crt(a, p, b, q))
    # 前缀检查 + rot 解码检查
    for m in out:
        b = _int_to_bytes(m)
        if _match_prefix(m, prefixes):
            flag = b.decode("utf-8", "replace")
            res = {"ok": True, "m": m, "flag": flag,
                   "via": "odd-subgroup+rabin", "method": "odd-subgroup-rabin"}
            # 明文本身是 rot 编码 flag（真题 10733：QNFPGS{...} = rot13(DASCTF{...})）
            if flag.startswith("QNFPGS{") or flag.startswith("SYNT{"):
                res["rot13"] = codecs_rot(flag, 13)
                res["rot18"] = codecs_rot(flag, 13, True)
                res["note"] = "明文为 ROT 编码 flag，提交前用 rot13/rot18 版本（题名含 rot 即提示）"
            return res
        if _is_printable(m):
            for name, dec in (("rot13", lambda s: codecs_rot(s, 13)),
                              ("rot18", lambda s: codecs_rot(s, 13, True))):
                t = dec(b.decode("utf-8", "replace"))
                if any(t.startswith(x) for x in prefixes):
                    return {"ok": True, "m": m, "flag": t,
                            "plaintext": b.decode("utf-8", "replace"),
                            "via": f"odd-subgroup+rabin+{name}", "method": "odd-subgroup-rabin"}
    return {"ok": False, "candidates": [_int_to_bytes(m).decode("latin-1") for m in out],
            "note": "4 根均无前缀且不可打印组合——人工检查 candidates",
            "method": "odd-subgroup-rabin"}


def codecs_rot(s: str, k: int, digits: bool = False) -> str:
    """字母 rot-k；digits=True 时数字 rot5（rot18）。"""
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        elif digits and ch.isdigit():
            out.append(chr((ord(ch) - 48 + 5) % 10 + 48))
        else:
            out.append(ch)
    return "".join(out)


def e2k_attack(c: int, e: int, p: int, q: int, prefixes: list,
               max_flag_len: int = 128) -> dict:
    """e=2^k 攻击：逐轮开方 + 前缀过滤 + CRT 组合。

    关键观察：flag 直接作为消息 m（无填充），通常 m < p，此时 m 就是
    roots_p 中唯一带 flag 前缀的元素——直接过滤即得，无需 q。
    若 m >= p，走 CRT：对每个 roots_p 元素，m = mp + k*p，
    前缀范围把 k 约束到极小区间（flag 短时 k 只有 0~1 个值），
    再用 (m mod q) ∈ roots_q 集合去重验证。
    """
    if e <= 0 or (e & (e - 1)) != 0:
        return {"ok": False, "error": "e 不是 2 的幂，请用 gcd1/nth_root"}
    k = e.bit_length() - 1
    res = {"method": "e2k-tonelli-shanks", "k": k}

    roots_p = all_2k_roots(c, p, k)
    res["roots_p_count"] = len(roots_p)
    if not roots_p:
        return {"ok": False, "error": "c 在模 p 下某轮开方失败（c 非 2^k 次幂？）", **res}

    # 路径 A：m < p，直接按前缀 + 可打印过滤
    for r in roots_p:
        if _match_prefix(r, prefixes) and _is_printable(r):
            return {
                "ok": True, "m": r, "flag_bytes": _int_to_bytes(r),
                "flag": _int_to_bytes(r).decode("utf-8", errors="replace"),
                "via": "roots_p-prefix", **res,
            }

    # 路径 B：m >= p，CRT 组合
    if q:
        roots_q = all_2k_roots(c, q, k)
        res["roots_q_count"] = len(roots_q)
        q_set = set(roots_q)
        inv_pq = pow(p, -1, q)
        hi = 1 << (max_flag_len * 8)
        scanned = 0
        for mp in roots_p:
            # m = mp + k*p；0 <= m < hi → k ∈ [0, (hi-1-mp)//p]
            k_max = (hi - 1 - mp) // p
            if k_max > (1 << 20):
                # 前缀范围过大（flag 很长或 p 很小）——放弃该元素，防爆炸
                continue
            for kk in range(k_max + 1):
                m = mp + kk * p
                scanned += 1
                if (m % q) in q_set and _match_prefix(m, prefixes):
                    return {
                        "ok": True, "m": m, "flag_bytes": _int_to_bytes(m),
                        "flag": _int_to_bytes(m).decode("utf-8", errors="replace"),
                        "via": "crt-prefix", "crt_scanned": scanned, **res,
                    }
        res["note"] = f"CRT 前缀过滤未命中（scanned={scanned}）；flag 可能超 {max_flag_len} 字节或前缀不符"
    return {"ok": False, **res}


def gcd1_attack(c: int, e: int, p: int, q: int, prefixes: list) -> dict:
    """gcd(e, phi)=1：常规 RSA 解密。"""
    phi = (p - 1) * (q - 1)
    if _gcd(e, phi) != 1:
        return {"ok": False, "error": f"gcd(e, phi)={_gcd(e, phi)} != 1，需 e2k/nth_root"}
    d = pow(e, -1, phi)
    m = pow(c, d, p * q)
    b = _int_to_bytes(m)
    return {
        "ok": True, "m": m, "flag_bytes": b,
        "flag": b.decode("utf-8", errors="replace"),
        "method": "gcd1-normal-rsa", "d": d,
    }


def nth_root_prime(c: int, e: int, p: int, prefixes: list) -> dict:
    """通用模素数 e 次根：gcd(e, p-1)=1 → 指数逆直接开根；否则引导 sage。"""
    if _gcd(e, p - 1) == 1:
        r = pow(c, pow(e, -1, p - 1), p)
        b = _int_to_bytes(r)
        return {"ok": True, "root": r, "flag": b.decode("utf-8", errors="replace"),
                "method": "inverse-exponent", "matches_prefix": _match_prefix(r, prefixes)}
    return {
        "ok": False,
        "note": "gcd(e, p-1) > 1：请把 e 分解为素数幂后用逐轮开方（e2k 为 2 幂特例），"
                "或 sage: Zmod(p)(c).nth_root(e, all=True) 一次到位",
    }


def crypto_high_exponent(params: dict) -> dict:
    """skill 入口。"""
    kind = params.get("kind", "auto")
    c = int(params.get("c", 0))
    e = int(params.get("e", 65536))
    p = int(params.get("p", 0))
    q = int(params.get("q", 0))
    n = int(params.get("n", 0))
    hint = int(params.get("hint", 0))
    prefixes = params.get("prefixes", ["DASCTF{", "flag{", "ctf{", "QNFPGS{"])
    max_flag_len = int(params.get("max_flag_len", 128))
    if kind == "factor":
        return factor_from_hint(hint, e, n)
    if not c or not e:
        return {"ok": False, "error": "缺少 c/e"}
    if not p and n and hint:
        # 先用 hint 分解 n（10733 真题路径）
        fr = factor_from_hint(hint, e, n)
        if fr.get("ok"):
            p, q = fr["p"], fr["q"]
    if not p and n:
        # 尝试从 n 分解（本 skill 不内置其它分解；若有 p 请直接传入）
        return {"ok": False, "error": "需要 p/q（或传 hint 走 factor 分解；否则先用 rsa 分解 skill）"}

    if kind == "gcd1":
        return gcd1_attack(c, e, p, q, prefixes)
    if kind == "e2k":
        return e2k_attack(c, e, p, q, prefixes, max_flag_len)
    if kind == "nth_root":
        return nth_root_prime(c, e, p, prefixes)
    if kind == "auto":
        if p and q and _gcd(e, (p - 1) * (q - 1)) == 1:
            return gcd1_attack(c, e, p, q, prefixes)
        if e > 0 and (e & (e - 1)) == 0 and p:
            # p,q 均 3 mod 4 且 e=2^k：先试快速路径（一轮 Rabin + rot 检查）
            if q and p % 4 == 3 and q % 4 == 3:
                fast = recover_via_odd_subgroup(c, e, p, q, prefixes)
                if fast.get("ok"):
                    return fast
            return e2k_attack(c, e, p, q, prefixes, max_flag_len)
        if p:
            return nth_root_prime(c, e, p, prefixes)
        return {"ok": False, "error": "auto 无法确定路径：请指定 kind 或补全 p/q"}
    return {"ok": False, "error": f"unknown kind: {kind}"}


def run(params):
    """SkillManager 统一入口。"""
    return crypto_high_exponent(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="高偶指数 RSA 攻击（e=65536 等）")
    parser.add_argument("--kind", default="auto",
                        choices=["gcd1", "e2k", "factor", "nth_root", "auto"])
    parser.add_argument("--c", type=int, default=0)
    parser.add_argument("--e", type=int, default=65536)
    parser.add_argument("--p", type=int, default=0)
    parser.add_argument("--q", type=int, default=0)
    parser.add_argument("--n", type=int, default=0)
    parser.add_argument("--hint", type=int, default=0)
    parser.add_argument("--prefix", default="DASCTF{,flag{,ctf{")
    args = parser.parse_args()
    import json

    params = {
        "kind": args.kind, "c": args.c, "e": args.e,
        "p": args.p, "q": args.q, "n": args.n, "hint": args.hint,
        "prefixes": [x for x in args.prefix.split(",") if x],
    }
    print(json.dumps(crypto_high_exponent(params), ensure_ascii=False, indent=1,
                     default=lambda o: o.decode("latin-1") if isinstance(o, bytes) else str(o)))


if __name__ == "__main__":
    main()
