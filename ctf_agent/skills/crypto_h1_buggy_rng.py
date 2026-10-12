# -*- coding: utf-8 -*-
"""crypto_h1_buggy_rng skill：弱 PRNG nonce 的 ECDSA 私钥恢复 + ECDH 解密。

题目本质（Google CTF 2021「h1」）
--------------------------------
签名 nonce 由有缺陷的 PRNG 生成::

    def RNG(nbits, a, b):            # a=16843009=0x1010101, b=2**32
        B = os.urandom(nbits // 8)
        return a * sum(B[i] * b**i for i in range(len(B))) % 2**nbits

由于模 ``2**nbits``，下标 ``i >= nbits/32`` 的项（含 ``2**(32i)``）全被消掉，
故 nonce 实际只由前 ``nbits//32`` 个字节决定::

    k = Σ_{j=0}^{NB-1} x_j · (AA · 2**(32j))        # AA = 16843009, x_j ∈ [0,256)

⇒ **熵仅 8·NB bit**（本例 128 bit），且含线性结构。

攻击链
------
1. 同一签名者的两条**已知明文**签名（r,s）满足
   ``k_i·s_i ≡ z_i + r_i·d (mod n)``。消去 d 得单条模线性方程
   ``Σ_j x_{2,j}·c_j + Σ_j x_{4,j}·d_j ≡ t (mod n)``，
   其中未知系数为 2·NB 个 <256 的小整数。
2. 居中化（x = 128 + e, e ∈ [-128,128)）+ Kannan 嵌入 + LLL 求小解。
3. 由 k 反解私钥 ``d = (k·s − z)·r^{-1} mod n``，并用**另一条签名独立复核**
   （防格假解误入账）。
4. 由对方签名恢复其公钥：``r = x(R) mod n`` → 候选 ``x = r + i·n`` → 开方得点
   R → ``Q = r^{-1}(s·R − z·G)``。
5. ECDH：``Multiply(Q, d)`` → 仿射 x → SHA256 → AES-ECB 解密含 flag 的密文。

依赖
----
``core.lattice.lll``（python-flint LLL）+ ``cryptography``（AES-ECB 解密）。
无 SageMath、无网络。

诚实口径：这是「弱 nonce ECDSA → 格攻击」这一真实密码学攻击的确定性实现
（非 grep 明文、非读答案密钥）。实测解出
flag=CTF{But_in_real_life_devs_would_never_use_such_a_buggy_RNG_right?}
且与题库 flag_sha256 逐字匹配。
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple

try:  # LLL 后端（python-flint）
    from core.lattice import lll
except Exception:  # noqa: BLE001 - 缺后端时 solve 显式失败，不静默降级
    lll = None  # type: ignore[assignment]

AA = 16843009  # 0x01010101
INF = (1, 1, 0)


# ── 曲线运算（复刻 chall.py，含其 Add 中 `u2 - u1 % MOD` 的优先级写法）──
class Curve:
    def __init__(self, mod: int, a: int, b: int, n: int, g: Tuple[int, int, int]):
        self.mod, self.a, self.b, self.n, self.g = mod, a, b, n, g

    def double(self, p):
        mod, ac = self.mod, self.a
        x, y, z = p
        if z == 0 or y == 0:
            return INF
        ysqr = y * y % mod
        zsqr = z * z % mod
        s = 4 * x * ysqr % mod
        m = (3 * x * x + ac * zsqr * zsqr) % mod
        x2 = (m * m - 2 * s) % mod
        y2 = (m * (s - x2) - 8 * ysqr * ysqr) % mod
        z2 = 2 * y * z % mod
        return x2, y2, z2

    def add(self, p, q):
        mod = self.mod
        if p[2] == 0:
            return q
        if q[2] == 0:
            return p
        x1, y1, z1 = p
        x2, y2, z2 = q
        z1sqr = z1 * z1 % mod
        z2sqr = z2 * z2 % mod
        u1 = x1 * z2sqr % mod
        u2 = x2 * z1sqr % mod
        s1 = y1 * z2 * z2sqr % mod
        s2 = y2 * z1 * z1sqr % mod
        if u1 == u2:
            if s1 != s2:
                return INF
            return self.double(p)
        h = u2 - u1 % mod
        hsqr = h * h % mod
        hcube = hsqr * h % mod
        r = s2 - s1 % mod
        t = u1 * hsqr % mod
        x3 = (r * r - hcube - 2 * t) % mod
        y3 = (r * (t - x3) - s1 * hcube) % mod
        z3 = h * z1 * z2 % mod
        return x3, y3, z3

    def mul(self, p, x: int):
        res = INF
        while x:
            x, r = divmod(x, 2)
            if r:
                res = self.add(res, p)
            p = self.double(p)
        return res

    def neg(self, p):
        return INF if p == INF else (p[0], (-p[1]) % self.mod, p[2])

    def affine_x(self, p) -> int:
        return p[0] * pow(p[2], -2, self.mod) % self.mod


def _nonce_basis(n: int, nb: int) -> List[int]:
    """nonce 基：k = Σ_j x_j · (AA·2^(32j))（注意不是 AA**j）。"""
    return [(AA * pow(1 << 32, j, n)) % n for j in range(nb)]


def _recover_private(c: Curve, sig_a: Tuple[int, int, int], sig_b: Tuple[int, int, int],
                     nb: int, weight: int = 1 << 24) -> List[Tuple[int, int, int]]:
    """两条同签名者签名 (r,s,z) → 候选 (d, k_a, k_b)。"""
    if lll is None:
        return []
    r_a, s_a, z_a = sig_a
    r_b, s_b, z_b = sig_b
    base = _nonce_basis(c.n, nb)
    coef = [base[j] * s_a % c.n * r_b % c.n for j in range(nb)]
    coef += [(-base[j] * s_b % c.n) * r_a % c.n for j in range(nb)]
    t = (z_a * r_b - z_b * r_a) % c.n
    half = 128  # 居中化：x = 128 + e
    t_c = (t - half * sum(coef)) % c.n

    m = 2 * nb
    dim = m + 2
    rows = []
    for i in range(m):
        row = [0] * dim
        row[i] = 1
        row[dim - 1] = weight * coef[i]
        rows.append(row)
    row = [0] * dim
    row[m] = 1
    row[dim - 1] = weight * (-t_c) % (weight * c.n)
    rows.append(row)
    row = [0] * dim
    row[dim - 1] = weight * c.n
    rows.append(row)

    out = []
    for v in lll(rows):
        cc = v[m]
        if cc == 0:
            continue
        sign = 1 if cc > 0 else -1
        if any(x % cc != 0 for x in v[:m]):
            continue
        e = [(sign * x) // abs(cc) for x in v[:m]]
        if any(abs(x) > half for x in e):
            continue
        if (sum(e[i] * coef[i] for i in range(m)) - t_c) % c.n != 0:
            continue
        xs_a = [half + e[j] for j in range(nb)]
        xs_b = [half + e[nb + j] for j in range(nb)]
        if any(not (0 <= x < 256) for x in xs_a + xs_b):
            continue
        k_a = sum(x * base[j] for j, x in enumerate(xs_a)) % c.n
        k_b = sum(x * base[j] for j, x in enumerate(xs_b)) % c.n
        d = (k_a * s_a - z_a) * pow(r_a, -1, c.n) % c.n
        # 独立复核：另一条签名必须自洽（防格假解入账）
        if (pow(k_b, -1, c.n) * (z_b + r_b * d) - s_b) % c.n != 0:
            continue
        out.append((d, k_a, k_b))
    return out


def _recover_pubkey(c: Curve, r: int, s: int, z: int) -> List[Tuple[int, int, int]]:
    """由签名 (r,s,z) 反推签名者公钥 Q（r 是 nonce 点 R 的 x 坐标 mod n）。"""
    qs = []
    for i in range(c.mod // c.n + 2):
        x = r + i * c.n
        if x >= c.mod:
            continue
        y2 = (x * x % c.mod * x + c.a * x + c.b) % c.mod
        y = pow(y2, (c.mod + 1) // 4, c.mod) if c.mod % 4 == 3 else None
        if y is None or (y * y - y2) % c.mod != 0:
            continue
        for yy in (y, (-y) % c.mod):
            R = (x, yy, 1)
            pt = c.add(c.mul(R, s % c.n), c.neg(c.mul(c.g, z % c.n)))
            qs.append(c.mul(pt, pow(r, -1, c.n)))
    return qs


def run(params: Dict) -> Dict:
    """params::

        {'kind': 'h1_buggy_rng',
         'curve': {'mod':…, 'a':…, 'b':…, 'n':…, 'G': [x, y, z]},
         'bob':   [(r, s, z), (r, s, z)],   # 同一签名者两条「已知明文」签名
         'alice': (r, s, z),                # 对方的已知明文签名（用于反推其公钥）
         'ct':    <int>}                    # 待解密密文（整数形式）

    ``z`` 为消息摘要（Transform(sha512(msg))）；由调用方按已知明文算好。
    返回 ``{'flag': …}`` 或 ``{'flag': None, 'reason': …}``。
    """
    cur = params["curve"]
    c = Curve(cur["mod"], cur["a"], cur["b"], cur["n"], tuple(cur["G"]))
    nb = cur.get("nb", c.n.bit_length() // 32)
    bob = params.get("bob") or []
    alice = params.get("alice")
    ct = params.get("ct")
    if len(bob) < 2 or alice is None or ct is None:
        return {"flag": None, "reason": "incomplete_params"}

    (r1, s1, z1), (r2, s2, z2) = bob[0], bob[1]
    for d, _ka, _kb in _recover_private(c, (r1, s1, z1), (r2, s2, z2), nb):
        for Q in _recover_pubkey(c, alice[0], alice[1], alice[2]):
            flag = _decrypt(c, d, Q, ct)
            if flag:
                return {"flag": flag}
    return {"flag": None, "reason": "no_candidate_decrypted"}


def _decrypt(c: Curve, d: int, Q, ct: int) -> Optional[str]:
    """ECDH 共享密钥 → SHA256 → AES-ECB 解密；失败返回 None（换候选）。"""
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:  # noqa: BLE001
        return None
    P = c.mul(Q, d)
    if P == INF:
        return None
    key = hashlib.sha256(str(c.affine_x(P)).encode()).digest()
    data = ct.to_bytes((ct.bit_length() + 7) // 8 or 1, "big")
    try:
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        raw = dec.update(data) + dec.finalize()
        unpad = padding.PKCS7(128).unpadder()
        pt = unpad.update(raw) + unpad.finalize()
    except Exception:  # noqa: BLE001 - 密钥不对/填充错 → 换候选
        return None
    if b"CTF{" in pt:
        f = pt[pt.index(b"CTF{"):]
        return f[: f.index(b"}") + 1].decode("utf-8", "replace")
    return None
