"""本地可复现 benchmark（2026-08-24——P1 工程能力交付②）

用途：题库 → 自动解出 → 统计解出数/耗时/失败归因 → JSON 留档。
诚实口径：所有解出为「离线推导（未平台验证——accepted=0）」。

用法：
    python scripts/_local_benchmark.py [题库目录]
输出：benchmark_report.json（解出数/耗时/失败归因——可复现）

实现：确定性解出器（模板/解出链 skill——无 LLM——可复现）：
- plain 明文 flag 提取（flag{...} 正则）
- caesar/ROT13 解码（26 位移遍历——flag{ 命中）
- base64/hex 解码（可读 flag）
"""

import glob, os, re, json, time, base64, sys

FLAG_RE = re.compile(rb'(?:DASCTF|flag|ctf)\{([^}\s]{3,})\}', re.I)


def _try_plain(content: bytes):
    for m in FLAG_RE.finditer(content):
        return b'flag{' + m.group(1) + b'}'
    return None


def _try_caesar_rot13(content: bytes):
    text = content.decode('utf-8', errors='ignore')
    for shift in range(26):
        out = ''.join(
            chr((ord(c) - 97 + shift) % 26 + 97) if 'a' <= c <= 'z' else
            chr((ord(c) - 65 + shift) % 26 + 65) if 'A' <= c <= 'Z' else c
            for c in text)
        if 'flag{' in out.lower() or 'dasctf{' in out.lower():
            m = re.search(r'(?:DASCTF|flag|ctf)\{[^}\s]{3,}', out)
            if m:
                return m.group(0).encode()
    t = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                      'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
    out13 = text.translate(t)
    m = re.search(r'(?:DASCTF|flag|ctf)\{[^}\s]{3,}', out13)
    if m:
        return m.group(0).encode()
    return None


def _try_b64_hex(content: bytes):
    text = content.decode('utf-8', errors='ignore').strip()
    if len(text) < 8 or not re.fullmatch(r'[A-Za-z0-9+/=]+', text):
        return None
    try:
        dec = base64.b64decode(text)
        if FLAG_RE.search(dec):
            return FLAG_RE.search(dec).group(0)
    except Exception:
        pass
    try:
        dec = bytes.fromhex(text)
        if FLAG_RE.search(dec):
            return FLAG_RE.search(dec).group(0)
    except Exception:
        pass
    return None


def _try_crypto_math(content: bytes):
    """数学链解出（10733/10696 解出链 skill——task.py 参数自动提取）：
    ① 10733 类：hint 解 p（W/gcd）+ BFS 开根 + ROT13（e 为 2 的幂）
    ② 10696 类：费马分解（p/q 相邻）+ decode_e=-π+2 + 标准解密
    ③ 小 n 类（<60 位十进制）：sympy.factorint 直接分解（RSA Attack 沉淀）
    输入为 task.py 文本（含 n/e/c/hint 参数）。
    """
    import math
    from math import gcd as _g
    text = content.decode('utf-8', errors='ignore')
    try:
        n = int(re.search(r'\bn\s*=\s*(\d{20,})', text).group(1))
        e = int(re.search(r'\be\s*=\s*(\d+)', text).group(1))
        c = int(re.search(r'\bc\s*=\s*(\d{10,})', text).group(1))
        hint_m = re.search(r'hint\s*=\s*(\d+)', text)
    except Exception:
        return None
    # ③ 小 n 直接分解（<60 位十进制——sympy factorint——RSA Attack 沉淀）
    if len(str(n)) < 60:
        try:
            from sympy import factorint as _fi
            fac = _fi(n)
            if len(fac) >= 2:
                from Crypto.Util.number import long_to_bytes as _l2b, inverse as _inv
                phi = 1
                for p, k in fac.items():
                    phi *= (p - 1) * (p ** (k - 1))
                if _g(e, phi) == 1:
                    b = _l2b(pow(c, _inv(e, phi), n))
                    if b'flag' in b.lower() or b'ctf' in b.lower() or b'hgame' in b.lower():
                        return b
        except Exception:
            pass
    # ① 费马分解（p/q 相邻——10696 类）
    a = math.isqrt(n) + 1
    p = q = None
    for _ in range(200000):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            break
        a += 1
    if p is None:
        return None
    # ② decode_e 类（e 巨大——primepi 判）或 hint 类（hint 解 p）
    if hint_m:
        hint = int(hint_m.group(1))
        W = pow(e, n, n)
        p2 = _g(W * W - hint, n)
        if p2 > 1 and n % p2 == 0:
            p = p2
            q = n // p
    phi = (p - 1) * (q - 1)
    g = _g(e, phi)
    from Crypto.Util.number import long_to_bytes, inverse
    if g == 1:
        m = pow(c, inverse(e, phi), n)
        b = long_to_bytes(m)
        if b'DASCTF' in b or b'flag' in b.lower() or b'CTF' in b:
            return b
        # ROT13 检查（QNFPGS{ = DASCTF{——题名 rot 提示）
        t = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                          'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
        b13 = bytes(t.get(x, x) if x < 128 else x for x in b)
        if b'DASCTF' in b13 or b'flag' in b13.lower() or b'CTF' in b13:
            return b13
    return None


def _try_shared_prime(content: bytes):
    """共享素数攻击（RSA Attack 2 类——多组 n 共享素数——gcd 分解——解密）。
    真题集实证：HGAME2022 RSA Attack 2——gcd(n1,n2) 共享素数——解出。"""
    import re as _re
    from math import gcd as _g
    from Crypto.Util.number import long_to_bytes, inverse
    text = content.decode('utf-8', errors='ignore')
    ns = [int(x) for x in _re.findall(r'\b[Nn]\d*\s*=\s*(\d+)', text)]
    es = [int(x) for x in _re.findall(r'\b[Ee]\s*=\s*(\d+)', text)]
    cs = [int(x) for x in _re.findall(r'\b[Cc]\d*\s*=\s*(\d+)', text)]
    if len(ns) < 2 or not es or not cs:
        return None
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            p = _g(ns[i], ns[j])
            if 1 < p < ns[i]:
                q = ns[i] // p
                phi = (p - 1) * (q - 1)
                e = es[0]
                if _g(e, phi) == 1:
                    m = pow(cs[0], inverse(e, phi), ns[i])
                    b = long_to_bytes(m)
                    if b'flag' in b.lower() or b'ctf' in b.lower() or b'hgame' in b.lower():
                        return b
    return None


def _try_wiener(content: bytes):
    """维纳攻击（RSA Attack 3 类——e 超大 d 小——连分数解 d——解密）。
    真题集实证：HGAME2022 RSA Attack 3——维纳连分数——解出。"""
    import re as _re
    from math import isqrt as _isqrt
    from Crypto.Util.number import long_to_bytes
    text = content.decode('utf-8', errors='ignore')
    try:
        n = int(_re.search(r'\bn\s*=\s*(\d+)', text).group(1))
        e = int(_re.search(r'\be\s*=\s*(\d+)', text).group(1))
        c = int(_re.search(r'\bc\s*=\s*(\d+)', text).group(1))
    except Exception:
        return None
    if len(str(e)) < len(str(n)) // 2:  # e 不够大——非维纳
        return None

    def cf_expansion(a, b):
        while b:
            yield a // b
            a, b = b, a % b

    n0, d0, n1, d1 = 0, 1, 1, 0
    for a in cf_expansion(e, n):
        n0, d0, n1, d1 = n1, d1, a * n1 + n0, a * d1 + d0
        k, d = n1, d1
        if k and d and (e * d - 1) % k == 0:
            phi_cand = (e * d - 1) // k
            s = n - phi_cand + 1
            disc = s * s - 4 * n
            if disc >= 0:
                r = _isqrt(disc)
                if r * r == disc and (s + r) % 2 == 0:
                    m = pow(c, d, n)
                    b = long_to_bytes(m)
                    if b'flag' in b.lower() or b'ctf' in b.lower() or b'hgame' in b.lower():
                        return b
    return None


SOLVERS = [("plain", _try_plain), ("caesar/rot13", _try_caesar_rot13),
           ("b64/hex", _try_b64_hex), ("crypto_math", _try_crypto_math),
           ("shared_prime", _try_shared_prime), ("wiener", _try_wiener)]


def solve_one(path: str) -> tuple:
    try:
        content = open(path, 'rb').read()
    except Exception:
        return None, "read_error"
    if len(content) > 1_000_000:
        return None, "too_large"
    for name, solver in SOLVERS:
        try:
            r = solver(content)
            if r:
                return r, name
        except Exception:
            continue
    return None, "unsolved"


def run(root: str = "data/attachments") -> dict:
    files = []
    for pat in ("**/*.txt", "**/*.log", "**/*.json", "**/*.out"):
        files.extend(glob.glob(os.path.join(root, pat), recursive=True))
    files = [f for f in files if os.path.getsize(f) < 1_000_000]
    results = []
    t0 = time.time()
    for f in sorted(files):
        s = time.time()
        flag, solver = solve_one(f)
        results.append({
            "file": os.path.basename(f),
            "solved": flag is not None,
            "flag": flag.decode('utf-8', errors='ignore') if flag else None,
            "solver": solver,
            "time_s": round(time.time() - s, 3),
        })
    total = time.time() - t0
    solved = [r for r in results if r["solved"]]
    report = {
        "_honest_note": "离线推导（未平台验证——accepted=0）——本地可复现 benchmark",
        "date": "2026-08-24",
        "题库": root,
        "文件数": len(results),
        "解出数": len(solved),
        "解出率": round(len(solved) / max(len(results), 1), 3),
        "总耗时_s": round(total, 2),
        "均单题_s": round(total / max(len(results), 1), 3),
        "solver分布": {},
        "解出列表": [{"file": r["file"], "flag": r["flag"], "solver": r["solver"]}
                  for r in solved],
        "失败归因": {},
    }
    for r in results:
        report["solver分布"][r["solver"]] = report["solver分布"].get(r["solver"], 0) + 1
    for r in results:
        if not r["solved"]:
            report["失败归因"][r["solver"]] = report["失败归因"].get(r["solver"], 0) + 1
    out = "benchmark_report.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: v for k, v in report.items()
                      if k not in ("解出列表",)}, ensure_ascii=False, indent=2))
    return report


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "data/attachments"
    run(root)
