"""确定性攻击链补强回归测试（2026-08-21 赛前攻坚）。

覆盖本次新增/扩展的确定性链：
1. rsa_fermat_factor：Hastad 广播任意组数（2/3 组）、共享素数 GCD、
   已知 d 直接解密、小指数跨模爆破（m^e = c + k*n）
2. web_jwt_prototype：JWT alg=none 伪造、HS256 弱密钥爆破
3. web_sqli：布尔盲注逐字符二分提取
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── rsa_fermat_factor 确定性链 ───────────────────────────────────────
def test_rsa_d_known():
    from Crypto.Util.number import getPrime, inverse

    from skills.rsa_fermat_factor import run
    p, q = getPrime(512), getPrime(512)
    n, e = p * q, 65537
    d = inverse(e, (p - 1) * (q - 1))
    m = int.from_bytes(b"flag{d_known_ok}", "big")
    c = pow(m, e, n)
    out = run({"n": n, "e": e, "c": c, "d": d})
    assert out == b"flag{d_known_ok}"


def test_rsa_shared_prime_gcd():
    from Crypto.Util.number import getPrime

    from skills.rsa_fermat_factor import run
    p, q1, q2 = getPrime(512), getPrime(512), getPrime(512)
    n1, n2 = p * q1, p * q2
    m = int.from_bytes(b"flag{gcd_shared_ok}", "big")
    e = 65537
    out = run({"e": e, "n1": n1, "c1": pow(m, e, n1),
               "n2": n2, "c2": pow(m, e, n2), "attack": "common_factor"})
    assert out == b"flag{gcd_shared_ok}"


def test_rsa_hastad_arbitrary_pairs():
    from Crypto.Util.number import getPrime

    from skills.rsa_fermat_factor import run
    m = int.from_bytes(b"flag{hastad_any_pairs}", "big")
    e = 3
    ns, cs = [], []
    for _ in range(2):  # 2 组（旧版只支持恰好 3 组，2 组会 KeyError）
        while True:
            p, q = getPrime(512), getPrime(512)
            n = p * q
            if pow(m, e) < n:
                ns.append(n)
                cs.append(pow(m, e, n))
                break
    out = run({"e": e, "n1": ns[0], "c1": cs[0],
               "n2": ns[1], "c2": cs[1], "attack": "hastad"})
    assert out == b"flag{hastad_any_pairs}"


def test_rsa_small_e_cross_modulus():
    from Crypto.Util.number import getPrime

    from skills.rsa_fermat_factor import _small_e_attack
    # 跨模场景：m 略大于 n^(1/3)（m^e = c + k*n，k 小可爆破）。
    # 真实题型：e=3 且明文填充到 n^(1/3) 数量级；k 随 (m/n^(1/3))^e 增长。
    import gmpy2

    e = 3
    p, q = getPrime(1024), getPrime(1024)
    n = p * q
    root = int(gmpy2.iroot(n, e)[0]) + 1
    m = root + 2026  # m 略高于 n^(1/3)，m^3 只超出 n 一点 → k 很小
    assert pow(m, e) > n, "测试前置：需 m^e > n"
    c = pow(m, e, n)
    out = _small_e_attack(c, e, n)
    assert out == m


# ── web_jwt_prototype 确定性链 ───────────────────────────────────────
def test_jwt_forge_none():
    import json

    from skills.web_jwt_prototype import jwt_forge_none
    tok = jwt_forge_none({"admin": True})
    h, p, sig = tok.split(".")
    import base64

    hdr = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    assert hdr["alg"] == "none"
    assert sig == ""  # 空签名


def test_jwt_hs256_crack():
    import base64
    import hashlib
    import hmac
    import json as _json

    from skills.web_jwt_prototype import web_jwt_prototype

    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")

    h = b64u(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64u(_json.dumps({"user": "admin"}).encode())
    sig = b64u(hmac.new(b"jwt_secret", h + b"." + p, hashlib.sha256).digest())
    tok = (h + b"." + p + b"." + sig).decode()
    r = web_jwt_prototype({"token": tok})
    assert r["attack"]["hs256_secret"] == "jwt_secret"
    assert r["attack"]["forge_hs256"].count(".") == 2


# ── web_sqli 布尔盲注确定性链 ────────────────────────────────────────
def test_sqli_bool_blind_extract():
    import re

    from skills.web_sqli import bool_blind_extract
    secret = "flag{bool_blind_waf_ok}"

    def oracle(cond):
        m = re.search(r"ascii\(substr\(\(select flag\),(\d+),1\)\)>(\d+)", cond)
        if not m:
            return False
        i, x = int(m.group(1)), int(m.group(2))
        if i > len(secret):
            return False
        return ord(secret[i - 1]) > x

    assert bool_blind_extract(oracle, subquery="flag") == secret
