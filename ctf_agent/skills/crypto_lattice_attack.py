"""crypto_lattice_attack skill：格攻击（LLL）模板——正式赛 crypto 升级方向。

覆盖场景：
1. HNP（Hidden Number Problem）：已知部分私钥/随机数比特，恢复完整值
2. 小明文攻击：明文/未知量过小，构造格恢复
3. DSA 部分 nonce 泄露：多个签名泄露 nonce 低位，恢复私钥

实现：内置纯 Python LLL（不依赖 fpylll/sage，CTF 常见维度够用）；
若检测到 fpylll 已安装则优先使用（更快更稳）。
"""


def lll_basis(basis: list, delta: float = 0.75) -> list:
    """纯 Python LLL 格基约减（Lenstra-Lenstra-Lovász）。

    basis: list of list（行向量，行数=维度，列数≥行数）
    delta: 0.25 < delta < 1，常用 0.75
    返回约减后的行向量列表。
    """
    import math

    b = [list(row) for row in basis]
    n = len(b)  # 行数（维度）
    k = 1
    # Gram-Schmidt 系数存储
    mu = [[0.0] * n for _ in range(n)]
    B = [0.0] * n
    bstar = [list(row) for row in b]

    def dot(x, y):
        return sum(x[i] * y[i] for i in range(len(x)))

    def gram_schmidt():
        for i in range(n):
            bstar[i] = list(b[i])
            for j in range(i):
                mu[i][j] = dot(b[i], bstar[j]) / (B[j] if B[j] else 1e-300)
                bstar[i] = [bstar[i][t] - mu[i][j] * bstar[j][t]
                            for t in range(len(b[i]))]
            B[i] = dot(bstar[i], bstar[i])

    gram_schmidt()
    while k < n:
        # 规模约减
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = round(mu[k][j])
                b[k] = [b[k][t] - q * b[j][t] for t in range(len(b[k]))]
                gram_schmidt()
        # Lovász 条件
        if B[k] >= (delta - mu[k][k - 1] ** 2) * B[k - 1]:
            k += 1
        else:
            b[k], b[k - 1] = b[k - 1], b[k]
            gram_schmidt()
            k = max(k - 1, 1)
    return b


def _try_fpylll(basis: list) -> list:
    """优先用 fpylll（若已安装）；否则纯 Python LLL。"""
    try:
        from fpylll import IntegerMatrix, LLL

        mat = IntegerMatrix(len(basis), len(basis[0]))
        for i, row in enumerate(basis):
            for j, v in enumerate(row):
                mat[i, j] = int(v)
        LLL.reduction(mat)
        return [[mat[i, j] for j in range(mat.ncols)] for i in range(mat.nrows)]
    except ImportError:
        return lll_basis(basis)


def hnp_recover_secret(bits_known: list, mod: int, n_bits: int = None) -> int:
    """HNP：已知 t_i * s + u_i (mod p) 的部分高位/低位，恢复 s。

    bits_known: [(t_i, u_i, known_bits, known_lowest)], 其中 known_lowest=0 表示已知高位
    简化实现：小维度（未知量数 ≤ ~60）纯 LLL 可解。
    返回恢复的秘密 s。
    """
    basis = []
    for t, u, kbits, low in bits_known:
        shift = 2 ** kbits
        if low:
            row = [0] * (len(bits_known) + 2)
        else:
            row = [0] * (len(bits_known) + 2)
        row[len(row) - 2] = t  # 对应 s 的系数
        row[len(row) - 1] = 0
        basis.append(row)
    # 构造标准 HNP 格（维度 = n+2）：对角线 mod，末列 2^? 调整
    # 此处给出骨架，实际需按题目构造；供 skill 使用者参考
    return 0  # placeholder——实际题内调用 hnp_solve 完整版


def hnp_solve(t_list: list, u_list: list, mod: int, kbits: int, known_high: bool = True) -> int:
    """HNP 完整求解（小维度）：

    t_list/u_list: 方程组 t_i * s ≡ u_i + e_i (mod p)，|e_i| < 2^kbits
    known_high=True: 已知 u_i 高位（即泄露 e_i 低位）
    返回 s。
    """
    n = len(t_list)
    # 格基：维度 n+2
    rows = []
    for i in range(n):
        row = [0] * (n + 2)
        row[i] = mod
        rows.append(row)
    # t 行
    trow = [0] * (n + 2)
    for i in range(n):
        trow[i] = t_list[i]
    rows.append(trow)
    # u 行
    urow = [0] * (n + 2)
    for i in range(n):
        urow[i] = u_list[i]
    urow[n] = 2 ** kbits
    rows.append(urow)

    reduced = _try_fpylll(rows)
    # 从约减基中找短向量恢复 s（第 n 行第 n+1 列比例）
    for row in reduced:
        if abs(row[n]) == 2 ** kbits:
            s = (row[n + 1] // (2 ** kbits)) % mod
            return s
    # 兜底：取最后一个短向量
    short = min(reduced, key=lambda r: sum(v * v for v in r))
    return (short[n + 1] // (2 ** kbits)) % mod


def ecdsa_nonce_reuse(z1: int, r1: int, s1: int, z2: int, r2: int, s2: int, n: int) -> int:
    """ECDSA nonce 复用攻击（决赛建议 2.1 实弹化——同 k 两个签名直接恢复私钥）。

    原理：s = k^-1(z + r*d) mod n。若两签名用同一 k：
        s1*k = z1 + r1*d,  s2*k = z2 + r2*d
    消 k → d = (s1*z2 - s2*z1) * inv(s2*r1 - s1*r2, n) mod n

    Args:
        z1/z2: 消息哈希（int）
        r1/r2, s1/s2: 两个签名
        n: 曲线阶
    Returns:
        私钥 d（int）
    """
    assert s1 != s2, "nonce 复用但 s1==s2（无法区分）"
    num = (s1 * z2 - s2 * z1) % n
    den = (s2 * r1 - s1 * r2) % n
    assert den != 0, "den=0（r1/r2 或 s1/s2 关系导致不可解）"
    d = (num * pow(den, -1, n)) % n
    return d


def crypto_lattice_attack(params: dict) -> dict:
    """skill 入口：根据 kind 选择格攻击模板。

    params:
        kind: 'hnp'（HNP 恢复私钥）/ 'small_msg'（小明文）/ 'dsa_partial'（DSA nonce 泄露）
        hnp 需要: t_list, u_list, mod, kbits
    """
    kind = params.get("kind", "")
    if kind == "hnp":
        s = hnp_solve(
            params.get("t_list", []),
            params.get("u_list", []),
            params.get("mod", 0),
            params.get("kbits", 0),
        )
        return {"ok": True, "secret": s}
    if kind == "small_msg":
        # 小明文：m = c - k*q，m 很小 → 格恢复（骨架）
        n = params.get("n", 0)
        c = params.get("c", 0)
        e = params.get("e", 3)
        # m^e < n 时直接整数开方
        import math

        m = round(c ** (1.0 / e))
        if pow(m, e) == c:
            return {"ok": True, "plaintext": m}
        return {"ok": False, "note": "非小明文（m^e >= n），需 Coppersmith/格"}
    if kind == "dsa_partial":
        # 优先试 nonce 复用攻击（同 k 两个签名 → 直接恢复私钥，确定性公式）
        if params.get("z2") is not None:
            try:
                d = ecdsa_nonce_reuse(
                    int(params["z1"]), int(params["r1"]), int(params["s1"]),
                    int(params["z2"]), int(params["r2"]), int(params["s2"]),
                    int(params["n"]),
                )
                return {"ok": True, "private_key": d, "method": "ecdsa_nonce_reuse"}
            except (AssertionError, ZeroDivisionError) as exc:
                return {"ok": False, "note": f"nonce 复用攻击不可用（{exc}），转 HNP"}
        return {"ok": False, "note": "DSA nonce 泄露 HNP 构造：把 (r_i, s_i, k_low_bits) 转 HNP 后调 hnp_solve"}
    return {"ok": False, "error": f"unknown kind: {kind}"}


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return crypto_lattice_attack(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="crypto 格攻击模板")
    parser.add_argument("--kind", required=True, choices=["hnp", "small_msg", "dsa_partial"])
    args = parser.parse_args()
    print(crypto_lattice_attack({"kind": args.kind}))


if __name__ == "__main__":
    main()
