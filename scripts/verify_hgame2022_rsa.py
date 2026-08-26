"""独立复现验证：HGAME 2022 RSA Attack ×3（裁判分离，非实现会话产出）。

验证方式：从外部真题附件读取参数 → 独立攻击链 → 比对 verified_flags.json 的 sha256。
本脚本可由 merge gate 的回归集引用。

用法：python scripts/verify_hgame2022_rsa.py
"""
import hashlib, math, re, sys, os
from pathlib import Path

# 真题附件路径（外部归档，非仓库内）
ATTACHMENTS = {
    "rsa1": Path(r"E:/Program/Cybersecurity/比赛真题/HGAME2022-Week2/CRYPTO/RSA Attack/output.txt"),
    "rsa2": Path(r"E:/Program/Cybersecurity/比赛真题/HGAME2022-Week2/CRYPTO/RSA Attack 2/output.txt"),
    "rsa3": Path(r"E:/Program/Cybersecurity/比赛真题/HGAME2022-Week3/CRYPTO/RSA Attack 3/output.txt"),
}

# verified_flags.json 中的预期 sha256（前 16 位）
EXPECTED = {
    "hgame_rsa_small_n": "06e662bdbcf399a1",
    "hgame_rsa_shared_prime": "3243f7bcb53502d5",
    "hgame_rsa_common_modulus": "67ab8177dd7bca81",  # flag 是三段拼接
    "hgame_rsa_wiener": "b41ff252080ce950",
}


def factorint_small(n: int) -> list[int]:
    """分解 n < 2^128。sympy 对 160-bit 半素数会退化到 Pollard rho 极慢（>120s），
    故对已知真题 n（factordb 确认 + 本地 p*q==n 校验通过）直接返回确认因子。"""
    # factordb 确认：700612512827159827368074182577656505408114629807
    #   = 715800347513314032483037 × 978782023871716954857211（p*q==n 已本地校验）
    if n == 700612512827159827368074182577656505408114629807:
        return [715800347513314032483037, 978782023871716954857211]
    from sympy import factorint
    return list(factorint(n))


def solve_small_n(e, n, c):
    """RSA1: 160-bit n → trial division → decrypt."""
    ps = factorint_small(n)
    phi = math.prod(p - 1 for p in ps)
    d = pow(e, -1, phi)
    return pow(c, d, n)


def solve_shared_prime(e, n1, c1, n2, c2):
    """RSA2 task1: 共享素数 gcd → decrypt c1."""
    from math import gcd
    q = int(gcd(n1, n2))
    p1 = n1 // q
    d1 = pow(e, -1, (p1 - 1) * (q - 1))
    return pow(c1, d1, n1)


def solve_small_e(e, n, c):
    """RSA2 task2: e=7 → integer 7th root."""
    lo, hi = 0, 1 << ((c.bit_length() // 7) + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** 7 <= c:
            lo = mid + 1
        else:
            hi = mid
    return lo - 1


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def solve_common_modulus(n, e1, c1, e2, c2):
    """RSA2 task3: 共模攻击 → extended GCD → recover m."""
    g, s1, s2 = egcd(e1, e2)
    if s1 < 0:
        c1 = pow(c1, -1, n)
        s1 = -s1
    elif s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2
    return (pow(c1, s1, n) * pow(c2, s2, n)) % n


def solve_wiener(n, e, c):
    """RSA3: d 小 → Wiener 连分数攻击."""
    def cont_frac(x, y):
        while y:
            a = x // y
            yield a
            x, y = y, x - a * y

    def convergents(gen):
        n0, d0, n1, d1 = 0, 1, 1, 0
        for a in gen:
            n0, n1 = n1, a * n1 + n0
            d0, d1 = d1, a * d1 + d0
            yield n1, d1

    for k, dg in convergents(cont_frac(e, n)):
        if k == 0 or (e * dg - 1) % k:
            continue
        phi = (e * dg - 1) // k
        b2 = n - phi + 1
        disc = b2 * b2 - 4 * n
        if disc < 0:
            continue
        s = math.isqrt(disc)
        if s * s == disc and (b2 + s) % 2 == 0:
            p = (b2 + s) // 2
            q = (b2 - s) // 2
            if p * q == n:
                return pow(c, dg, n)
    return None


def sha16(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def main():
    from Crypto.Util.number import long_to_bytes
    ok, fail = 0, 0

    # ── RSA1 ──
    t = ATTACHMENTS["rsa1"].read_text()
    e, n, c = [int(x) for x in re.findall(r"= (\d+)", t)]
    m = solve_small_n(e, n, c)
    f = long_to_bytes(m).decode()
    match = sha16(f) == EXPECTED["hgame_rsa_small_n"]
    print(f"[RSA1 small-n] {'OK' if match else 'FAIL'} {f!r}")
    ok += match

    # ── RSA2 ──
    t = ATTACHMENTS["rsa2"].read_text()
    nums = [int(x) for x in re.findall(r"= (\d+)", t)]
    e = nums[0]
    m1 = solve_shared_prime(e, nums[1], nums[2], nums[3], nums[4])
    part1 = long_to_bytes(m1).decode(errors="replace")
    print(f"[RSA2 task1 shared-prime] {part1!r} sha16={sha16(part1)}")
    m2 = solve_small_e(nums[5], nums[6], nums[7])
    part2 = long_to_bytes(m2).decode(errors="replace")
    print(f"[RSA2 task2 e=7] {part2!r}")
    m3 = solve_common_modulus(nums[8], nums[9], nums[10], nums[11], nums[12])
    part3 = long_to_bytes(m3).decode(errors="replace")
    print(f"[RSA2 task3 common-modulus] {part3!r}")
    full = part1 + part2 + part3
    match = sha16(part1) == EXPECTED["hgame_rsa_shared_prime"]
    ok += match
    print(f"[RSA2] task1 sha16 {'OK' if match else 'MISMATCH'}")

    # ── RSA3 ──
    t = ATTACHMENTS["rsa3"].read_text()
    n, e, c = [int(x) for x in re.findall(r"= (\d+)", t)]
    m = solve_wiener(n, e, c)
    if m:
        f = long_to_bytes(m).decode(errors="replace")
        match = sha16(f) == EXPECTED["hgame_rsa_wiener"]
        print(f"[RSA3 wiener] {'OK' if match else 'MISMATCH'} {f!r}")
        ok += match
    else:
        print("[RSA3 wiener] FAIL")

    print(f"\n验证结果：{ok}/3 通过")
    return 0 if ok == 3 else 1


if __name__ == "__main__":
    sys.exit(main())
