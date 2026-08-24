"""crypto_coppersmith skill：Coppersmith 攻击模板（决赛 crypto 难度升级）。

覆盖场景：
1. partial_p：RSA 已知 p 的高位/低位部分比特（p_high | p_low）→ 恢复完整 p
2. related_message：同一 m 用不同 e/不同 padding 加密的多密文 → 求根
3. small_roots：多项式模 N 小根（m^e - c ≡ 0 mod N，m 小）→ 整数开方兜底 + 格

实现：纯 Python（无需 fpylll/sage）；partial_p 用小根求解（整数开方逼近 + 逐位爆破），
相关消息用 GCD/小根；完整 Coppersmith（Hensel/Howgrave-Graham）依赖 sage——本 skill
提供流程 + 常见情形的 Python 解法，复杂情形引导用 sage/fpylll。

用法（skill 调用）：
    params = {'kind': 'partial_p|related_message|small_roots', ...}
"""

import math


def partial_p_factor(n: int, p_high: int = 0, known_bits: int = 0, low: bool = False) -> dict:
    """已知 p 的部分比特，恢复完整 p 并分解 n。

    p_high: 已知的 p 高位（十进制整数）；known_bits: 已知比特数
    low=True: 已知的是低位（p_low）
    方法：p ≈ n^0.5，从已知部分 + 未知部分（2^(bits-unknown) 范围）逼近。
    完整 Coppersmith 需 sage；本实现做逐位逼近（未知比特 ≤ 64 时可行）。
    """
    n_bits = n.bit_length()
    p_bits = n_bits // 2
    unknown_bits = p_bits - known_bits
    # 纯 Python 爆破上限：unknown_bits > 30 时遍历不可行，直接引导 sage
    if unknown_bits > 30:
        return {"ok": False,
                "note": f"未知比特 {unknown_bits} 过大（>30），需 sage/fpylll 完整 Coppersmith（small_roots）"}

    # 低位已知：p = p_low + x * 2^known_bits，x ∈ [0, 2^unknown_bits)
    if low:
        base = p_high  # 传入的是 p_low
        step = 1 << known_bits
        # 全范围遍历 x（unknown_bits ≤ 64 时；用 start 优化起点易算错漏 x）
        for x in range(0, 1 << unknown_bits):
            p = base + x * step
            if n % p == 0:
                return {"ok": True, "p": p, "q": n // p, "method": "low-bits-bruteforce"}
        return {"ok": False, "note": "低位爆破未命中（未知比特可能超范围）"}

    # 高位已知：p = p_high * 2^unknown_bits + x，x ∈ [0, 2^unknown_bits)
    base = p_high << unknown_bits
    step = 1
    for x in range(0, 1 << unknown_bits):
        p = base + x
        if n % p == 0:
            return {"ok": True, "p": p, "q": n // p, "method": "high-bits-bruteforce"}
        if x % (1 << 20) == 0 and x > 0:
            pass  # 进度（无打印避免污染）
    return {"ok": False, "note": f"高位爆破 {1 << unknown_bits} 次未命中（需 sage）"}


def related_message_attack(c1: int, c2: int, e: int, n: int,
                           diff: int = 0) -> dict:
    """相关消息攻击：m 与 m+diff 分别加密（同 e 同 n）。

    经典 Franklin-Reiter：m2 = m + diff（或 padding 差异已知）
    gcd((x)^e - c1, (x+diff)^e - c2) 的根 = m（需多项式 GCD，纯 Python 用
    近似：小 e 时枚举或牛顿逼近）。
    本实现：e=3 时用 GCD 思路 + 数值逼近；其他 e 引导 sage。
    """
    if e == 3:
        # (m)^3 - c1 = 0, (m+diff)^3 - c2 = 0 → 消元求 m（数值近似）
        # m = (c2 - c1 - 3*diff*m^2 ... ) 复杂；用简单情形：diff 已知且小
        # 实际用二分/牛顿求解 m^3 ≡ c1 (mod n) 的整数根（若 m^3 < n）
        m = round(c1 ** (1.0 / 3))
        if pow(m, 3) == c1:
            return {"ok": True, "m": m, "method": "cube-root"}
        # 尝试 m+diff
        m2 = round(c2 ** (1.0 / 3))
        if pow(m2, 3) == c2:
            return {"ok": True, "m": m2 - diff, "method": "cube-root-2"}
        return {"ok": False, "note": "e=3 但 m^3>=n（取模），需 Franklin-Reiter 完整版（sage）"}
    return {"ok": False, "note": f"e={e} 需 Franklin-Reiter 多项式 GCD（sage）"}


def small_roots_low_e(n: int, c: int, e: int) -> dict:
    """低指数小根：m^e < n 时直接整数开方；否则引导格/Coppersmith。"""
    m = round(c ** (1.0 / e))
    if pow(m, e) == c:
        return {"ok": True, "m": m, "method": "integer-root"}
    # m^e >= n：若 e 小且 m 相对 n 小（如 m < n^(1/e) * 阈值），可 Coppersmith
    # 简化：检查是否 m 位数 << n 位数（小明文场景）
    if c.bit_length() < n.bit_length():
        return {"ok": False, "note": "m^e 取模后小于 n，可能是 padding 相关攻击（引导 related_message）"}
    return {"ok": False, "note": "需 Coppersmith 小根（sage: small_roots）或格攻击 LLL"}


def crypto_coppersmith(params: dict) -> dict:
    """skill 入口。"""
    kind = params.get("kind", "")
    n = params.get("n", 0)
    if kind == "partial_p":
        return partial_p_factor(
            n, p_high=params.get("p_high", 0),
            known_bits=params.get("known_bits", 0),
            low=params.get("low", False),
        )
    if kind == "related_message":
        return related_message_attack(
            params.get("c1", 0), params.get("c2", 0),
            params.get("e", 3), n, diff=params.get("diff", 0),
        )
    if kind == "small_roots":
        return small_roots_low_e(n, params.get("c", 0), params.get("e", 3))
    return {"ok": False, "error": f"unknown kind: {kind}"}


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return crypto_coppersmith(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Coppersmith 攻击模板")
    parser.add_argument("--kind", required=True,
                        choices=["partial_p", "related_message", "small_roots"])
    args = parser.parse_args()
    import json

    print(json.dumps(crypto_coppersmith({"kind": args.kind}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
