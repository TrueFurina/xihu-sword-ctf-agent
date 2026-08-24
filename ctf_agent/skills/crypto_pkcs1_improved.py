"""crypto_pkcs1_improved skill：PKCS#1 改进型题（正式赛 CRYPTO-01/02 沉淀——2026-08-21）。

场景：task.py 用 hint=(e*p+e²)^q mod n 提示 p + AES_KEY 加密 + 文件 AES-ECB 加密。
解法链（已确认——下次直接解）：
1. hint e=3 小指数攻击（hint^3 < n——整数开三次方根）→ hint 明文
2. AES_KEY 从打印的 pow(AES_KEY_ENC, d, q*r) 末尾 16 字节提取
3. AES-ECB 解密 .enc → 明文文件（PDF 等）→ flag
4. hint 解 p 型（CRYPTO-02——e 为 2 的幂）：W=e^n mod n → p | W²-hint → gcd(W²-hint, n)=p
   → e=2^16 时 c 开 16 次平方根（BFS 逐层——模 p/q + CRT）
"""

import re


def _iroot(n: int, k: int) -> int:
    """整数 k 次方根。"""
    lo, hi = 0, 1
    while hi ** k <= n:
        hi *= 2
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid
    return lo


def _extract_aes_key_from_pow(pow_result: int, qr_bits: int = 2048) -> bytes:
    """从 pow(AES_KEY_ENC, d, q*r) 末尾 16 字节提取 AES_KEY（PKCS#1 改进填充）。"""
    b = pow_result.to_bytes((pow_result.bit_length() + 7) // 8, "big")
    if len(b) < qr_bits // 8:
        b = b"\x00" * (qr_bits // 8 - len(b)) + b  # 补前导 00
    return b[-16:]  # AES_KEY 在末尾 16 字节（改进填充：00 02 [00...] [AES_KEY]）


def _hint_solve_p(hint: int, n: int, e: int) -> tuple:
    """hint=(e*p+e²)^q mod n 解 p：W=e^n mod n → p | W²-hint → gcd(W²-hint, n)=p。

    数学：hint ≡ e^(2q) (mod p)；W=e^n ≡ e^q (mod p)（费马 pq≡q mod p-1）→ W²≡e^(2q)≡hint (mod p)。
    """
    import math

    W = pow(e, n, n)
    g = math.gcd((W * W - hint) % n, n)
    if 1 < g < n:
        return g, n // g  # (p, q)
    return None, None


def run(params: dict) -> dict:
    """skill 统一入口。params: hint/n/c/e/pow_result/enc_path/flag_prefix。"""
    out = {"ok": False, "method": "pkcs1_improved"}
    hint = params.get("hint")
    n = params.get("n")
    e = params.get("e", 3)

    # 1. hint 开根（e=3 小明文）
    if hint and e == 3:
        h = _iroot(int(hint), 3)
        if h ** 3 == int(hint):
            hb = h.to_bytes((h.bit_length() + 7) // 8, "big")
            out["hint_text"] = hb.decode("utf-8", errors="ignore")

    # 2. hint 解 p（CRYPTO-02 型——e 为 2 的幂）
    if hint and n and e in (65536, 65537):
        p, q = _hint_solve_p(int(hint), int(n), int(e))
        if p:
            out["p"] = p
            out["q"] = q
            # e=2^16：c 开根（此处给出方法——完整 BFS 见 _solve_10733.py）
            c = params.get("c")
            if c:
                from math import gcd as _gcd

                phi = (p - 1) * (q - 1)
                ee, ph = int(e), phi
                k = 0
                while ee % 2 == 0 and ph % 2 == 0:
                    ee //= 2
                    ph //= 2
                    k += 1
                d = pow(ee, -1, ph)
                m2k = pow(int(c), d, p * q)  # m^(2^k)
                out["k"] = k
                out["m_pow_2k"] = m2k  # 需 BFS 逐层开平方根（模 p/q + CRT）→ m → flag

    # 3. AES_KEY 提取 + AES-ECB 解密（CRYPTO-01 型）
    pow_res = params.get("pow_result")
    enc_path = params.get("enc_path")
    if pow_res and enc_path:
        aes_key = _extract_aes_key_from_pow(int(pow_res))
        try:
            from Crypto.Cipher import AES

            enc = open(enc_path, "rb").read()
            dec = AES.new(aes_key, AES.MODE_ECB).decrypt(enc)
            out["decrypted_head"] = dec[:8]
            flags = re.findall(rb"(?:DASCTF|flag)\{[^}\s]{3,}\}", dec)
            if flags:
                out["ok"] = True
                out["flag"] = flags[0].decode()
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"AES 解密: {exc}"
    return out


if __name__ == "__main__":
    import json

    print(json.dumps(run({}), ensure_ascii=False, indent=1))
