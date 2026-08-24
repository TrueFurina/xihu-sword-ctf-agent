"""Skill: RSA 攻击全套

覆盖 CTF 高频 RSA 变体：
- 费马分解（p, q 接近）
- 小指数攻击（e=3, m^e < n）
- Wiener 连分数（d < n^0.25）
- 共模攻击（同模数不同公钥）
- Hastad 广播攻击（同明文多模数）
- phi/逆元已知直接解密（玄盾杯 ExcitingInverse 题型，EASY）

输入: params = {'n': int, 'e': int, 'c': int, 'phi': int(可选，已知phi直接解密), ...}
输出: 解出的明文 bytes 或 None
"""

try:
    import gmpy2
    from Crypto.Util.number import long_to_bytes
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False


def _collect_pairs(params: dict) -> tuple:
    """从 params 收集 (n1,c1),(n2,c2)... 序列（支持任意组数≥2）。

    兼容旧 dict 形态 n1/c1/n2/c2/n3/c3 以及 n/c（作第一组），返回 (ns, cs)。
    按模数去重（n/c 与 n1/c1 可能指向同一组，重复模数会使 CRT 求逆失败）。
    """
    ns, cs = [], []
    n = params.get("n")
    c = params.get("c")
    if n and c:
        ns.append(int(n))
        cs.append(int(c))
    for i in range(1, 10):
        nk, ck = "n%d" % i, "c%d" % i
        if nk in params and ck in params:
            ns.append(int(params[nk]))
            cs.append(int(params[ck]))
        else:
            break
    # 按模数去重
    seen = set()
    out_n, out_c = [], []
    for a, b in zip(ns, cs):
        if a in seen:
            continue
        seen.add(a)
        out_n.append(a)
        out_c.append(b)
    return out_n, out_c


def run(params):
    """RSA 攻击：自动检测攻击类型并尝试。

    Args:
        params: {'n': int, 'e': int, 'c': int, 'phi': int, 'd': int, 'attack': str(可选),
                 'n1'/'c1'/'n2'/'c2'...: 多模数广播/共享素数组（任意组数≥2）,
                 'e1'/'c1'/'e2'/'c2': 共模}

    Returns:
        解出的明文 bytes 或 None
    """
    if not HAS_DEPS:
        return None

    n = int(params.get("n", 0))
    e = int(params.get("e", 0))
    c = int(params.get("c", 0))
    attack = str(params.get("attack", "")).lower()
    ns, cs = _collect_pairs(params)
    es = [int(params.get("e", 0))] * len(cs) if not params.get("e1") else None

    # 自动检测攻击类型（按优先级：d已知 > phi已知 > 多模数 > 共模 > 小指数 > Wiener > 费马）
    if not attack:
        if params.get("d") and n and c:
            attack = "d_known"
        elif params.get("phi") and e and c:
            attack = "phi_known"
        elif len(ns) >= 2:
            # 多组 (n,c)：先试共享素数 GCD，失败再试 Hastad 广播
            attack = "multi_n"
        elif params.get("e2") and params.get("c2") and params.get("e1"):
            attack = "common_modulus"
        elif e <= 5 and n > 0 and c > 0:
            attack = "small_e"
        else:
            # 大 e（接近 n 量级）通常是 Wiener（小 d）场景，优先试 Wiener；否则费马
            if e > 0 and n > 0 and e.bit_length() >= n.bit_length() // 2:
                attack = "wiener"
            else:
                attack = "fermat"

    # 尝试各种攻击
    if attack == "d_known":
        result = _d_known_attack(int(params["d"]), c, n)
    elif attack == "phi_known":
        result = _phi_known_attack(
            int(params["phi"]), e, c, n if n else 0)
    elif attack == "small_e":
        result = _small_e_attack(c, e, n)
    elif attack == "wiener":
        result = _wiener_attack(n, e, c)
    elif attack == "common_modulus":
        result = _common_modulus(
            int(params["c1"]), int(params["c2"]),
            int(params["e1"]), int(params["e2"]),
            int(params["n"])
        )
    elif attack == "multi_n":
        # 共享素数 GCD 优先（n 两两 gcd），失败再 Hastad 广播（任意组数）
        result = _common_factor_attack(ns, cs, e) or _hastad_attack(ns, e, cs)
    elif attack == "hastad":
        result = _hastad_attack(ns, e, cs)
    elif attack == "common_factor":
        result = _common_factor_attack(ns, cs, e)
    elif attack == "phi_factor":
        result = _phi_factor_attack(
            int(params.get("n", 0)), int(params["phi"]),
            int(params.get("e", 0)), int(params.get("c", 0)))
    elif attack == "phi_known_inv":
        result = _phi_known_inv_attack(
            int(params["phi"]), int(params["e"]), int(params["c"]),
            int(params.get("pinv", 0)), int(params.get("qinv", 0)),
        )
    else:
        # 默认费马分解
        result = _fermat_factor(n, e, c)

    if result is not None:
        try:
            return long_to_bytes(result)
        except Exception:
            return None
    return None


def _phi_known_attack(phi: int, e: int, c: int, n: int = 0) -> int:
    """已知 phi（欧拉函数）直接解密：d = invert(e, phi)，m = c^d mod n。

    玄盾杯 ExcitingInverse 题型（EASY）：题目直接给出 phi 或 d，只需
    pow(c, d, n) 即可出明文。n 缺失时也可先用 phi 求 d 再尝试。
    """
    if not phi or not e or not c:
        return None
    try:
        d = int(gmpy2.invert(e, phi))
        if n:
            return int(gmpy2.powmod(c, d, n))
        # n 缺失：无法算模幂，返回 None（由调用方补 n）
        return None
    except Exception:
        return None


def _phi_factor_attack(n: int, phi: int, e: int = 0, c: int = 0) -> int:
    """已知 n + phi 分解 p/q（二次方程），再用 e/c 解密（如有）。

    数学：p+q = n − phi + 1 = s；p−q = √(s² − 4n)；
    p=(s+d)/2, q=(s−d)/2（无 e/c 时此函数也返回 p 供调用方拿素因子）。

    适用：题目同时给出 n 与 phi（phi 直接解密因 gcd(e,phi)!=1 失败时，
    先分解出 p/q 再走降幂/Rabin 等后续攻击；或需验证 n 由 phi 恢复的 p/q 组成）。
    """
    if not (n and phi):
        return None
    try:
        s = n - phi + 1
        D = s * s - 4 * n
        if D < 0:
            return None
        d = int(gmpy2.isqrt(D))
        if d * d != D:
            return None
        if (s + d) % 2 or (s - d) % 2:
            return None
        p, q = (s + d) // 2, (s - d) // 2
        if p <= 1 or q <= 1 or p * q != n or (p - 1) * (q - 1) != phi:
            return None
        if not (e and c):
            return p  # 无密文：返回素因子 p（调用方取 n//p 得 q）
        d_ = int(gmpy2.invert(e, phi))
        return int(gmpy2.powmod(c, d_, n))
    except Exception:
        return None


def _phi_known_inv_attack(phi: int, e: int, c: int, pinv: int, qinv: int) -> int:
    """玄盾杯 ExcitingInverse：已知 phi + pinv/qinv（无 n）恢复 n 后解密。

    数学（2026-08-21 人工推导验证）：
    - pinv·p ≡ 1 (mod q) → pinv·p − 1 = k·q，且 k ≡ −qinv (mod p)、0<k<p → k = p − qinv
    - 代入得 p·pinv − 1 = (p−qinv)·q → pq = p·pinv + qinv·q − 1
    - 由 phi = pq − p − q + 1 与 pq = p·pinv + qinv·q − 1 联立：
      p·(pinv−1) + q·(qinv−1) = phi，令 A=pinv−1、B=qinv−1 → pA + qB = phi
    - p = (phi − qB)/A 代入 pq − p − q + 1 = phi → 关于 q 的二次方程：
      B·q² − (phi+B−A)·q + (phi·(1+A) − A) = 0，判别式开方得 q，回代得 p。
    """
    if not (phi and e and c and pinv and qinv):
        return None
    try:
        A = pinv - 1
        B = qinv - 1
        if A == 0 or B == 0:
            return None
        Cq = B
        Cb = -(phi + B - A)
        Cc = phi * (1 + A) - A
        D = Cb * Cb - 4 * Cq * Cc
        if D < 0:
            return None
        d = int(gmpy2.isqrt(D))
        if d * d != D:
            return None
        for q in (( -Cb + d) // (2 * Cq), (-Cb - d) // (2 * Cq)):
            if q <= 1:
                continue
            num = phi - q * B
            if num % A != 0:
                continue
            p = num // A
            if p <= 1:
                continue
            if (p - 1) * (q - 1) != phi:
                continue
            n = p * q
            if n != p * pinv + qinv * q - 1:
                continue
            d_ = int(gmpy2.invert(e, phi))
            return int(gmpy2.powmod(c, d_, n))
    except Exception:
        return None
    return None


def _d_known_attack(d: int, c: int, n: int) -> int:
    """已知私钥 d 直接解密：m = c^d mod n（题目直接给出 d 时命中即秒解）。"""
    if not (d and c and n):
        return None
    try:
        return int(gmpy2.powmod(c, d, n))
    except Exception:
        return None


def _small_e_attack(c: int, e: int, n: int = 0) -> int:
    """小指数攻击：直接开 e 次方；c > n（m^e 跨模）时爆破 k 使 m^e = c + k*n。

    覆盖两类真题：m^e < n 直接开方；m^e > n 但 m 较小（e=3 高频）需
    对 k∈[0,K) 尝试 iroot(c + k*n, e) 精确匹配。
    """
    if e > 100:
        return None
    root = int(gmpy2.iroot(c, e)[0])
    if root ** e == c:
        return root
    # 跨模爆破：m^e = c + k*n（n 已知且 e 较小；e=3 时 K 取 2**20 足够常见 m）
    if n > 0:
        limit = 1 << 20 if e <= 5 else 1 << 14
        for k in range(1, limit):
            val = c + k * n
            r = int(gmpy2.iroot(val, e)[0])
            if r ** e == val:
                return r
            if r ** e > (k + 1) * n:  # 上界剪枝：超出下一区间即可停止
                break
    return None


def _wiener_attack(n: int, e: int, c: int) -> int:
    """Wiener 连分数攻击。"""
    cf = _continued_fraction(e, n)
    for k, d in cf:
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        m = int(gmpy2.powmod(c, d, n))
        if pow(m, e, n) == c:
            return m
    return None


def _continued_fraction(e: int, n: int):
    """连分数展开，返回 (k, d) 对。"""
    cf = []
    a, b = e, n
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a - q * b
    # 收敛
    convs = []
    num, den = 0, 1
    num_prev, den_prev = 1, 0
    for q in cf:
        num, num_prev = q * num + num_prev, num
        den, den_prev = q * den + den_prev, den
        convs.append((num, den))
    return convs


def _common_modulus(c1: int, c2: int, e1: int, e2: int, n: int) -> int:
    """RSA 共模攻击。"""
    g, s, t = gmpy2.gcdext(e1, e2)
    if g != 1:
        return None
    m = (int(gmpy2.powmod(c1, s, n)) * int(gmpy2.powmod(c2, t, n))) % n
    return m


def _hastad_attack(ns: list, e: int, cs: list) -> int:
    """Hastad 广播攻击（CRT + 开 e 次方）。支持任意组数（>=2）。

    前提：同明文 m 被 e 个及以上不同模数加密，且 m^e < ∏n（Hastad 定理）。
    组数少于 e 时 CRT 恢复出的 x 不保证等于 m^e，直接开方校验兜底。
    """
    if not ns or len(ns) != len(cs) or len(ns) < 2:
        return None
    ns = [int(x) for x in ns]
    cs = [int(x) for x in cs]
    # 2026-08-21 修复：原 `e >= len(ns)*4` 快速失败是错误启发式——
    # 3 组密文 + e=17 时 flag(≈240bit) 的 m^e(≈4080bit) 仍 < ∏n(≈6144bit)，
    # Hastad 完全可行（实测 ezrsa e=17 CRT+iroot 精确解出）。
    # 正确性由下方 `root**e == x` 精确校验兜底，无需前置拒杀。
    # CRT 合并
    N = 1
    for n in ns:
        N *= n
    x = 0
    for i, (n, c) in enumerate(zip(ns, cs)):
        Ni = N // n
        # 求 Ni 对 n 的逆
        gi = int(gmpy2.invert(Ni, n))
        x += c * Ni * gi
    x %= N
    root = int(gmpy2.iroot(x, e)[0])
    if root ** e == x:
        return root
    return None


def _common_factor_attack(ns: list, cs: list, e: int = 0) -> int:
    """共享素数 GCD 攻击：多组 n 两两 gcd，gcd>1 即分解出公共素数 p。

    场景：RSA 多密钥生成时素数复用（不同 n 共享 p），或 n1/n2 有公因子。
    命中即恢复所有私钥解密，无需 Coppersmith/格攻击。
    """
    if not ns or len(ns) != len(cs) or len(ns) < 2:
        return None
    ns = [int(x) for x in ns]
    cs = [int(x) for x in cs]
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            g = int(gmpy2.gcd(ns[i], ns[j]))
            if g <= 1 or g >= ns[i]:
                continue
            for idx in range(len(ns)):
                if ns[idx] % g != 0:
                    continue
                p, q = g, ns[idx] // g
                if p <= 1 or q <= 1:
                    continue
                phi = (p - 1) * (q - 1)
                try:
                    d = int(gmpy2.invert(e or 65537, phi))
                except Exception:
                    continue
                m = int(gmpy2.powmod(cs[idx], d, ns[idx]))
                if pow(m, e or 65537, ns[idx]) == cs[idx]:
                    return m
    return None


def _fermat_factor(n: int, e: int, c: int) -> int:
    """费马分解（p, q 接近）。"""
    a = gmpy2.isqrt(n) + 1
    b2 = a * a - n
    for _ in range(100000):
        if gmpy2.is_square(b2):
            b = gmpy2.isqrt(b2)
            p = int(a + b)
            q = int(a - b)
            if p * q == n:
                phi = (p - 1) * (q - 1)
                d = int(gmpy2.invert(e, phi))
                m = int(gmpy2.powmod(c, d, n))
                return m
        a += 1
        b2 = a * a - n
    return None


def suggest_steps(description=None, attachments=None):
    """给出解题步骤建议。"""
    return [
        "提取 RSA 参数 n/e/c/phi/d（从附件或题目描述；题目给出 phi 或 d 时直接解密）",
        "判断攻击类型：已知d→直接解密；已知phi→直接解密；多组(n,c)→先试共享素数gcd再试Hastad广播；同n两组(e,c)→共模；e小→小指数（跨模爆破k）；d小→Wiener；p≈q→费马",
        "执行对应攻击脚本恢复明文 m",
        "long_to_bytes(m) 转 flag",
        "脚本执行失败/输出为空时：检查参数是否从附件正确提取（文件可能有多行数据），修正参数后重试，不要原样重跑",
    ]
