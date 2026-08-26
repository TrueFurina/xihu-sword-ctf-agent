# -*- coding: utf-8 -*-
"""HGAME2022 RSA Attack 三题 — 完整可复现离线核验脚本（2026-08-25 升级版）。

真题来源（外部真题，非平台题）：
  E:/Program/Cybersecurity/比赛真题/HGAME2022-Week2/CRYPTO/RSA Attack{, 2}
  E:/Program/Cybersecurity/比赛真题/HGAME2022-Week3/CRYPTO/RSA Attack 3

攻击链（2026-08-25 实测全部可复现）：
  RSA Attack 1  → crypto_math 小 n 分解（sympy factorint，48 位 n）
  RSA Attack 2  → task1 共享素数 gcd + task2 低指数攻击(e=7) + task3 共模攻击
                  （三段拼接完整 flag——官方 writeup 佐证）
  RSA Attack 3  → wiener 维纳连分数（e 超大 d 小）

核验方式：对每题附件 output.txt 跑确定性攻击，比对 flag 与台账已落盘的 hgame flag。
注意：平台 accepted 仍为 0，本核验属离线人工核验口径（诚实标注）。

运行：.venv/Scripts/python.exe scripts/verify_hgame_rsa.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts._local_benchmark import solve_one  # noqa: E402

# 台账落盘的完整 flag（2026-08-25 三段拼接核验一致）
EXPECTED = {
    "RSA Attack": "hgame{SHorTesT!fLAg}",
    "RSA Attack 2": "hgame{RsA@hAS!a&VArIETY?of.AttacK^mEThodS^whAT:other!AttACK|METHOdS~do@you_KNOW}",
    "RSA Attack 3": "hgame{dO|YOU:kNOw!tHE*PRINcIplE*bEhInd%WInNEr#aTTacK}",
}

BASE = "E:/Program/Cybersecurity/比赛真题"
PATHS = {
    "RSA Attack": f"{BASE}/HGAME2022-Week2/CRYPTO/RSA Attack",
    "RSA Attack 2": f"{BASE}/HGAME2022-Week2/CRYPTO/RSA Attack 2",
    "RSA Attack 3": f"{BASE}/HGAME2022-Week3/CRYPTO/RSA Attack 3",
}


def _solve_attack2(path: str):
    """RSA Attack 2 完整解出：task1 共享素数 + task2 低指数 + task3 共模，三段拼接。

    2026-08-25 实测：三段全部可复现，完整 flag 80 字符。
    """
    try:
        import gmpy2
    except Exception:  # noqa: BLE001 - gmpy2 缺失时降级 pow
        gmpy2 = None
    from Crypto.Util.number import long_to_bytes
    from math import gcd

    text = open(path, encoding="utf-8", errors="ignore").read()

    # ── task1：共享素数 gcd ──
    seg1 = text.split("# task1")[1].split("# task2")[0]
    ns1 = [int(x) for x in re.findall(r"\b[Nn]\d*\s*=\s*(\d+)", seg1)]
    cs1 = [int(x) for x in re.findall(r"\b[Cc]\d*\s*=\s*(\d+)", seg1)]
    e1 = int(re.search(r"\b[Ee]\s*=\s*(\d+)", seg1).group(1))
    p = gcd(ns1[0], ns1[1])
    q = ns1[0] // p
    phi = (p - 1) * (q - 1)
    m1 = pow(cs1[0], pow(e1, -1, phi), ns1[0])
    t1 = long_to_bytes(m1).decode("utf-8", errors="ignore")

    # ── task2：低指数攻击(e=7, 枚举 k 开 e 次方) ──
    seg2 = text.split("# task2")[1].split("# task3")[0]
    e2 = int(re.search(r"\b[Ee]\s*=\s*(\d+)", seg2).group(1))
    n2 = int(re.search(r"\b[Nn]\s*=\s*(\d+)", seg2).group(1))
    c2 = int(re.search(r"\b[Cc]\s*=\s*(\d+)", seg2).group(1))
    t2 = None
    for k in range(2_000_000):
        if gmpy2 is not None:
            r, exact = gmpy2.iroot(c2 + k * n2, e2)
        else:
            # 降级：整数开方近似 + 幂校验
            r = int(round((c2 + k * n2) ** (1.0 / e2)))
            exact = (r ** e2 == c2 + k * n2)
        if exact:
            t2 = long_to_bytes(int(r)).decode("utf-8", errors="ignore")
            break
    if t2 is None:
        return None, "task2 低指数攻击未命中"

    # ── task3：共模攻击(e1*s1 + e2*s2 = 1) ──
    seg3 = text.split("# task3")[1]
    n3 = int(re.search(r"\b[Nn]\s*=\s*(\d+)", seg3).group(1))
    e3a = int(re.search(r"\be1\s*=\s*(\d+)", seg3).group(1))
    e3b = int(re.search(r"\be2\s*=\s*(\d+)", seg3).group(1))
    c3a = int(re.search(r"\bc1\s*=\s*(\d+)", seg3).group(1))
    c3b = int(re.search(r"\bc2\s*=\s*(\d+)", seg3).group(1))
    if gmpy2 is not None:
        g, s1, s2 = gmpy2.gcdext(e3a, e3b)
    else:
        # 扩展欧几里得降级实现
        def _egcd(a, b):
            if b == 0:
                return a, 1, 0
            g, x, y = _egcd(b, a % b)
            return g, y, x - (a // b) * y
        g, s1, s2 = _egcd(e3a, e3b)
    m3 = (pow(c3a, s1, n3) * pow(c3b, s2, n3)) % n3
    t3 = long_to_bytes(m3).decode("utf-8", errors="ignore")

    return t1 + t2 + t3, "shared_prime+low_exp+common_modulus"


def main() -> int:
    ok_all = True
    for name, path in PATHS.items():
        if not os.path.isdir(path):
            print(f"❌ {name}: 目录不存在 {path}")
            ok_all = False
            continue
        target = os.path.join(path, "output.txt")
        if not os.path.isfile(target):
            cands = [os.path.join(path, f) for f in os.listdir(path)
                     if f.endswith((".txt", ".out"))]
            target = cands[0] if cands else None
        if not target:
            print(f"❌ {name}: 无附件文件")
            ok_all = False
            continue

        expected = EXPECTED[name]
        if name == "RSA Attack 2":
            flag, via = _solve_attack2(target)
        else:
            try:
                flag, via = solve_one(target)
            except Exception as exc:  # noqa: BLE001
                print(f"❌ {name}: 求解异常 {exc}")
                ok_all = False
                continue
            flag = flag.decode() if isinstance(flag, bytes) else flag

        if not flag:
            print(f"❌ {name}: 未复现解出")
            ok_all = False
            continue
        if flag == expected:
            print(f"✅ {name}: 复现一致 via={via}（{flag[:24]}…）")
        else:
            print(f"❌ {name}: flag 不一致\n  实测: {flag}\n  台账: {expected}")
            ok_all = False
    print()
    print("VERIFIED: " + ("3/3 全部复现一致" if ok_all else "存在不一致"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
