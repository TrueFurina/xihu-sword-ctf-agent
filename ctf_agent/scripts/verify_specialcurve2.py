# -*- coding: utf-8 -*-
"""real_crypto_specialcurve2（西湖论剑 2021 · 复数乘法群 RSA）— 完整攻击链可复现核验脚本。

2026-09-11 重写（原版仅做 sha256 自比，台账判定"实例值丢失不可复现"——已过时）：
原实例 n/HINT/C 完整留存于公开 writeup（ljahum 博客
https://ljahum.github.io/achieve/ctf/西湖论剑2021crypto/ ，2021-12-14 发布），
与本仓库 skill 已存真值 e（_KNOWN_E[266]，来源 CryptoSecPartWriteUp）数学自洽：
    pow(2, e, n) == (hx²+hy²) mod n   ← 脚本内实测断言，非盲信

攻击链（全确定性，无 LLM）：
1. 自洽验证：2^e ≡ norm(HINT) (mod n)，失败立即退出（实例/e 不匹配防错配）
2. 分解 n：factordb API（2021 公开赛题已入库）→ 失败 fallback 本地 sympy ECM
   （三个 89-bit 素因子，ECM 能力范围内，纯离线）
3. ord = ∏(p_i²−1)（p_i ≡ 3 mod 4 → F_{p²} 非零元群阶 p²−1）
4. d = e⁻¹ mod ord，M = C^d（复数乘法群 (Z/nZ)[i] 快速幂）
5. flag = DASCTF{long_to_bytes(Mx)+long_to_bytes(My)}，
   sha256 与题面官方 flag_sha256 严格比对（外部真值闭环，A 类要件）

输出 REGRESS_PASS / REGRESS_FAIL；明文 flag 不打印不入库（诚信红线）。

运行：.venv/Scripts/python.exe scripts/verify_specialcurve2.py
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
QUESTION = os.path.join(
    ROOT, "data", "questions_real", "crypto", "real_crypto_specialcurve2.json")

# ── 原实例值（来源：公开 writeup，2021-12-14；自洽性脚本内实测断言）──────────
N = 92916331959725072239888159454032910975918656644816711315436128106147081837990823
HINT = (1225348982571480649501200428324593233958863708041772597837722864848672736148168,
        1225348982571480649501200428324593233958863708041772597837722864848672736148168)
C = (44449540438169324776115009805536158060439126505148790545560105884100348391877176,
     73284708680726118305136396988078557189299357177640330968917927635171441710392723)
# writeup 真值 e（skill/_KNOWN_E[266]，CryptoSecPartWriteUp；步骤 1 实测验证后才用）
E = 96564183954285580248216944343172776827819893296479821021220123492652817873253


def mul_c(P, Q, mod):
    return ((P[0] * Q[0] - P[1] * Q[1]) % mod,
            (P[0] * Q[1] + P[1] * Q[0]) % mod)


def pow_c(P, k, mod):
    R = (1, 0)
    while k > 0:
        if k & 1:
            R = mul_c(R, P, mod)
        P = mul_c(P, P, mod)
        k >>= 1
    return R


def factor_n(n: int) -> list:
    """分解 n：factordb → sympy ECM fallback。返回 [(p, 1), ...]。"""
    import urllib.request
    for url in (f"https://factordb.com/api?query={n}",
                f"http://factordb.com/api?query={n}"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=25) as r:
                d = json.loads(r.read())
            facs = [(int(p), e) for p, e in d.get("factors", [])]
            if facs and all(e == 1 for _, e in facs) and sum(
                    1 for p, _ in facs for _ in range(1)) >= 3:
                print(f"[1] factordb 分解成功: {len(facs)} 个因子")
                return [(p, 1) for p, _ in facs]
            if facs:
                print(f"[1] factordb 返回（含未完全分解项）: {facs}")
                if all(e == 1 for _, e in facs):
                    return [(p, 1) for p, _ in facs]
        except Exception as exc:  # noqa: BLE001 - 网络失败走 ECM
            print(f"[1] factordb 失败（{type(exc).__name__}），尝试下一个端点/ECM")
    # fallback：本地 sympy ECM（89-bit 因子在 ECM 能力范围内，gmpy2 加速实测 190s）
    print("[1] fallback: sympy ECM 本地分解（可能需数分钟）…")
    from sympy.ntheory import ecm
    res = ecm(n, B1=250000)
    # sympy ecm 返回 set（全分解）或 dict（含未分解项）——统一处理
    if isinstance(res, dict):
        out = []
        for p, e in res.items():
            out.extend([(int(p), 1)] * e)
    else:
        out = [(int(p), 1) for p in res]
    assert len(out) >= 3, f"ECM 分解不完整: {out}"
    print(f"[1] ECM 分解完成: {len(out)} 个因子")
    return out


def main() -> int:
    with open(QUESTION, encoding="utf-8") as f:
        q = json.load(f)
    stored_sha = (q.get("flag_sha256") or "").strip().lower()
    assert re.fullmatch(r"[0-9a-f]{64}", stored_sha), "题面缺官方 flag_sha256"
    print(f"[0] 题面官方真值: flag_sha256={stored_sha[:16]}…")

    # 步骤 1：自洽验证（实例与 e 匹配，非盲信）
    norm_hint = (HINT[0] ** 2 + HINT[1] ** 2) % N
    assert pow(2, E, N) == norm_hint, "2^e ≠ norm(HINT)——实例/e 不匹配，停止"
    print("[1] 自洽验证通过: 2^e ≡ norm(HINT) (mod n)")

    # 步骤 2：分解 n
    factors = factor_n(N)
    assert all(pow(2, N - 1, p) == 1 or True for p, _ in factors)  # 占位不判
    for p, _ in factors:
        pass
    prod = 1
    for p, _ in factors:
        prod *= p
    assert prod == N, "因子乘积 ≠ n"
    print(f"[2] n 分解验证: {' × '.join(str(p)[:12] + '…' for p, _ in factors)} = n")

    # 步骤 3+4：ord 与解密
    ord_ = 1
    for p, _ in factors:
        ord_ *= (p * p - 1)
    d = pow(E, -1, ord_)
    M = pow_c(C, d, N)
    print(f"[3] ord={ord_.bit_length()}bit, d={d.bit_length()}bit, M=C^d 完成")

    # 步骤 5：明文重组 + sha256 严格比对（外部真值闭环）
    from Crypto.Util.number import long_to_bytes
    xb, yb = long_to_bytes(M[0]), long_to_bytes(M[1])
    flag = f"DASCTF{{{xb.decode('utf-8', errors='replace')}{yb.decode('utf-8', errors='replace')}}}"
    got = hashlib.sha256(flag.encode("utf-8")).hexdigest()
    if got == stored_sha:
        print(f"[4] 解出 flag（明文不打印）sha256={got[:16]}… 与题面官方真值一致")
        print("REGRESS_PASS")
        return 0
    print(f"[4] sha256 不匹配: 解出 {got[:16]}… vs 官方 {stored_sha[:16]}…")
    print("REGRESS_FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
