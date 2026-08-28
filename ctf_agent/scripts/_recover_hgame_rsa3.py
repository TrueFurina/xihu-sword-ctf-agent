"""仓库内重建 HGAME 2022 week3 RSA Attack 3 附件 (output.txt)。

2026-08-27 将功补过: 原始 E:/Program/Cybersecurity/比赛真题/.../RSA Attack 3/output.txt
于磁盘清理时被删除,且公开 writeup 给出的参数损坏(4346-bit 异常模数)。
但该题 flag 已在多个公开 writeup 中明确:
    hgame{dO|YOU:kNOw!tHE*PRINcIplE*bEhInd%WInNEr#aTTacK}
题目结构亦公开 (d=getPrime(64) 的低解密指数/Wiener 攻击)。

本脚本按真实题目结构重新生成一组**自洽**的 Wiener 挑战参数:
    p,q = 2048-bit 素数; n=p*q; d=64-bit 素数; e=inverse(d,phi); c=pow(s2n(flag),e,n)
写入 output.txt 后, verify_hgame2022_rsa.py 的 Wiener 攻击可解出真实 flag。

与 RSA1/RSA2 重建手法一致: 复用真实 flag + 公开题目结构,
确保 verify 脚本在仓库内可独立复现(不再依赖已删外部目录)。
不依赖 sympy (自带 Miller-Rabin)。
"""
import hashlib
import math
import os
import random
import sys
from pathlib import Path

FLAG = "hgame{dO|YOU:kNOw!tHE*PRINcIplE*bEhInd%WInNEr#aTTacK}"
EXPECTED_SHA16 = "b41ff252080ce950"  # verify_hgame2022_rsa.py::EXPECTED["hgame_rsa_wiener"]


def s2n(s: str) -> int:
    return int.from_bytes(s.encode(), "big")


def is_prime(n: int, k: int = 20) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def get_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


def main():
    assert hashlib.sha256(FLAG.encode()).hexdigest()[:16] == EXPECTED_SHA16, \
        "flag 与 verify 脚本预期 sha16 不一致, 停止以防写入错误数据"

    random.seed()  # 真随机
    p = get_prime(2048)
    q = get_prime(2048)
    n = p * q
    d = get_prime(64)            # Wiener: d 很小
    phi = (p - 1) * (q - 1)
    e = pow(d, -1, phi)          # 模逆
    c = pow(s2n(FLAG), e, n)

    # 自洽校验: Wiener 攻击应能还原真实 flag (内联实现)
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

    m = None
    for k, dg in convergents(cont_frac(e, n)):
        if k == 0 or (e * dg - 1) % k:
            continue
        ph = (e * dg - 1) // k
        b2 = n - ph + 1
        disc = b2 * b2 - 4 * n
        if disc < 0:
            continue
        s = math.isqrt(disc)
        if s * s == disc and (b2 + s) % 2 == 0:
            pp = (b2 + s) // 2
            qq = (b2 - s) // 2
            if pp * qq == n:
                m = pow(c, dg, n)
                break
    from Crypto.Util.number import long_to_bytes
    recovered = long_to_bytes(m).decode(errors="replace") if m else None
    assert recovered == FLAG, f"自洽校验失败: 解出 {recovered!r}"

    out_dir = Path(__file__).resolve().parents[1] / "data/questions_real/_attachments/hg2022/RSA Attack 3"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "output.txt"
    out_path.write_text(f"n = {n}\ne = {e}\nc = {c}\n")
    print(f"已写入: {out_path}")
    print(f"n.bit_length = {n.bit_length()} (合法 RSA 模数, 非损坏)")
    print(f"自洽校验通过: Wiener 攻击还原 flag = {recovered!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
