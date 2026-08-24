# -*- coding: utf-8 -*-
"""10733 CRYPTO-02: How many rot are there
n 分解: hint ≡ e^q*p + e^{2q} (mod n)
  mod p:  hint ≡ e^{2q} = (e^q)^2
  W = e^n mod n; 由 p≡1 (mod p-1) => pq≡q (mod p-1) => W ≡ e^q (mod p)
  => p | W^2 - hint  =>  gcd(W^2 - hint, n) = p
之后: e=2^16, gcd(e,phi)=2^k -> d=inv(e/2^k,phi), c^d = m^{2^k} -> BFS 逐层开平方根
"""
import math
from Crypto.Util.number import long_to_bytes, isPrime

hint = 101048855492044571417475830924088947184757234444475406804947498377420789778570832667138477666669908690663759417316798982038542431531087217671616502327573935462498550576600180793553880691247281813287212166428236802504214599757066100450668324529765827891463527861160593648623157792143035729770978865516948880313
c = 62214676810380175097525195047581624344610596576389901532958749194333175927146005969879818861882074690471600028484419966943711467342568120045965690332607166015419112255944582319675084071747302548088333383655637474764450810187215177625206094644430662667402073753343732910706186228919546522301643978766618493433
n = 131232786046474875167899992758388342524496883222860498694293714537118780151392850883679257361099172761516964104115167485944225089583991161038144993589322315250529302275646269196618503385962458635181473103926087951239559460161218447795578503981054097990206859884036249764383918404640987230150854235563692800669
e = 65536

# ---- Step 1: factor n ----
W = pow(e, n, n)
g = math.gcd((W * W - hint) % n, n)
print("gcd =", g)
assert 1 < g < n, "分解失败"
p, q = g, n // g
assert p * q == n and isPrime(p) and isPrime(q)
print("p =", p)
print("q =", q)
print("p%4 =", p % 4, " q%4 =", q % 4)

# ---- helpers (提前定义) ----
def crt(a1, m1, a2, m2):
    return (a1 + m1 * ((a2 - a1) * pow(m1, -1, m2) % m2)) % (m1 * m2)

def sqrt_mod_pp(x, p):
    """素数模平方根, p≡3 mod 4 走捷径, 否则 Tonelli-Shanks (sympy)"""
    if p % 4 == 3:
        r = pow(x, (p + 1) // 4, p)
        return [r, p - r] if r * r % p == x else []
    from sympy.nthroot_mod import nthroot_mod
    try:
        rs = nthroot_mod(x, 2, p, all_roots=True)
        return list(set(int(r) for r in rs))
    except Exception:
        return []

# ---- Step 2: 奇数阶子群求逆 -> m^2, 再一轮 Rabin ----
# mod p: c ≡ m^{2^16} = (m^2)^{2^15}, 在 s=(p-1)/2(奇) 中求 inv 使 2^15*inv ≡ 1 (mod s)
# 则 c^inv ≡ m^{2^16*inv} ≡ m^2 (mod p)  [2^16*inv ≡ 2 (mod 2s)]
def recover_square(y, p):
    s = (p - 1) // 2
    inv = pow(pow(2, 15, s), -1, s)
    return pow(y % p, inv, p)

m2_p = recover_square(c, p)
m2_q = recover_square(c, q)
x = crt(m2_p, p, m2_q, q)   # x = m^2 mod n
assert pow(x, pow(2, 15), n) == c, "m^2 验证失败"
k = 1                       # 只需一轮开平方

cands = [x]
for _ in range(k):
    nxt = []
    for v in cands:
        rp = sqrt_mod_pp(v % p, p)
        if not rp:
            continue
        rq = sqrt_mod_pp(v % q, q)
        if not rq:
            continue
        for a in rp:
            for b in rq:
                nxt.append(crt(a, p, b, q))
    cands = list(set(nxt))
    print("round, candidates =", len(cands))
    if not cands:
        break

for v in cands:
    b = long_to_bytes(v)
    if b"DASCTF" in b or b"flag" in b.lower():
        print("FLAG:", b)
