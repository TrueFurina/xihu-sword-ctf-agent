"""LCG 参数恢复 → RSA 私钥重建求解器（least-common-genominator / Google CTF 2023）。

B1 工具链补齐第五刀（2026-10-05）。Google CTF 2023 `least-common-genominator`
用一条线性同余发生器（LCG）`state = (state*m + c) % n` 生成 RSA 质数：
前 6 个 LCG 输出被 dump 到 `dump.txt`，其输出流里按序挑出前 8 个
`isPrime 且 512-bit` 的候选作 RSA 模数 N 的因子；flag 用 `public.pem` 的 (N,e)
加密存 `flag.txt`（little-endian 字节）。

从 6 个连续 LCG 输出即可**确定性**恢复 (m, c, n)（纯数论，无需靶机/靶场）：
- 令 y_i = x_{i+1} - x_i，则 y_{i+1} = m·y_i (mod n) ⇒ n | (y_{i+1}² - y_{i+2}·y_i)，
  取多个此类式的 gcd 即得 n；
- m = y_1·y_0⁻¹ (mod n)（取可逆的一对），c = (x_1 - m·x_0) (mod n)；
- 用 (m,c,n) 从 x0 重放 LCG 流，按序收集前 8 个 512-bit 质数 → N；
- 读 `public.pem` 取 e，d = e⁻¹ mod φ(N)，pow(enc_flag, d, N) 解密。

全部离线纯 Python（gmpy2/sympy 已具备），¥0，不需要启 LLM 真跑。

诚实口径：本题属 `questions_external` 外部池口径，**不进 `offline_verified=14` 台账**；
属「工具链补齐」产物（已知数论算法的确定性实现），不代表 LLM 自主推理能力。
"""

import hashlib
import math
import os

try:
    import gmpy2
    _is_prime = gmpy2.is_prime
except Exception:  # noqa: BLE001 - 退化到 sympy
    from sympy import isprime as _is_prime


def _recover_lcg_params(xs):
    """从连续 LCG 输出 x0..x5 恢复 (m, c, n)。

    返回 (m, c, n)。若 y_i 全退化导致无法恢复则抛异常。
    """
    if len(xs) < 4:
        raise ValueError("need >=4 consecutive LCG outputs")
    ys = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
    # n 整除 (y_{i+1}^2 - y_{i+2}*y_i) 对每个 i 成立
    n = 0
    for i in range(len(ys) - 2):
        t = abs(ys[i + 1] * ys[i + 1] - ys[i + 2] * ys[i])
        n = math.gcd(n, t)
    if n <= 1:
        raise ValueError("failed to recover LCG modulus n")
    # 恢复 m：找一对可逆的 y_i
    m = None
    for i in range(len(ys) - 1):
        if math.gcd(ys[i] % n, n) == 1:
            m = (ys[i + 1] * pow(ys[i] % n, -1, n)) % n
            break
    if m is None:
        raise ValueError("no invertible y_i to recover m")
    c = (xs[1] - m * xs[0]) % n
    # 自校验：用 (m,c,n) 重放必须与 dump 完全一致
    for i in range(len(xs) - 1):
        if (xs[i] * m + c) % n != xs[i + 1]:
            raise ValueError("LCG recovery self-check failed at index %d" % i)
    return m, c, n


def _regenerate_primes(x0, m, c, n, n_primes=8, bits=512):
    """从 x0 重放 LCG 流，按序收集前 n_primes 个 512-bit 质数。

    与 generate.py 语义一致：候选序列为 x0, x1, x2, ...，逐个判 isPrime+512bit。
    """
    primes = []
    s = x0
    # 安全上限：避免极端情况下死循环
    guard = 0
    while len(primes) < n_primes and guard < 100000:
        guard += 1
        if _is_prime(s) and s.bit_length() == bits:
            primes.append(s)
        s = (s * m + c) % n
    if len(primes) < n_primes:
        raise ValueError("only recovered %d/%d primes" % (len(primes), n_primes))
    return primes


def solve_lcg(dump_lines, pem_str, flag_bytes, expected_sha=None):
    """核心求解。

    dump_lines: iterable of str/int（LCG 输出，每行一个大整数）
    pem_str:    公钥 PEM 文本（含 N, e）
    flag_bytes: flag.txt 原始字节（little-endian 加密体）
    expected_sha: 题库 flag_sha256（可选，用于复核）

    返回 (flag_bytes, info_dict)
    """
    xs = []
    for line in dump_lines:
        line = str(line).strip()
        if not line:
            continue
        try:
            xs.append(int(line))
        except ValueError:
            continue
    if len(xs) < 4:
        raise ValueError("dump.txt has too few LCG outputs")

    from Crypto.PublicKey import RSA
    kpem = RSA.import_key(pem_str)
    e = int(kpem.e)

    m, c, n = _recover_lcg_params(xs)
    primes = _regenerate_primes(xs[0], m, c, n)
    N = math.prod(primes)
    if kpem.n != N:
        raise ValueError("recovered N != PEM N (recovery drift)")

    phi = math.prod(p - 1 for p in primes)
    d = pow(e, -1, phi)
    enc = int.from_bytes(flag_bytes, "little")
    flag_int = pow(enc, d, N)
    flag = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, "big")

    info = {
        "m": m, "c": c, "n": n, "N": N,
        "e": e, "n_primes": len(primes),
        "matched": (hashlib.sha256(flag).hexdigest() == expected_sha)
        if expected_sha else None,
    }
    return flag, info


def crypto_lcg_recover(params):
    """Skill 入口。

    params:
      kind='dir'  -> dir=<附件目录，含 dump.txt/public.pem/flag.txt>, expected_sha=...
      kind='solve'-> dump_lines=[...], pem=<PEM 文本>, flag_bytes=<bytes>, expected_sha=...
    返回 dict {ok, flag, matched, info}
    """
    kind = params.get("kind", "dir")
    expected_sha = params.get("expected_sha")
    try:
        if kind == "dir":
            d = params["dir"]
            with open(os.path.join(d, "dump.txt"), "r", encoding="utf-8") as f:
                dump_lines = f.read().splitlines()
            with open(os.path.join(d, "public.pem"), "r", encoding="utf-8") as f:
                pem_str = f.read()
            with open(os.path.join(d, "flag.txt"), "rb") as f:
                flag_bytes = f.read()
        elif kind == "solve":
            dump_lines = params["dump_lines"]
            pem_str = params["pem"]
            flag_bytes = params["flag_bytes"]
        else:
            return {"ok": False, "error": "unknown kind %r" % kind}
        flag, info = solve_lcg(dump_lines, pem_str, flag_bytes, expected_sha)
        return {
            "ok": True,
            "flag": flag.decode("latin1"),
            "matched": info.get("matched"),
            "info": {k: (str(v) if isinstance(v, int) else v) for k, v in info.items()},
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def run(params):
    """Unified run() 接口（skills 由 run(params)->dict 发现）。"""
    return crypto_lcg_recover(params)


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.join(
        here, "..", "data", "questions_external", "crypto",
        "ext_gctf2023_least-common-genominator", "_attachments")
    if os.path.isdir(cand):
        res = crypto_lcg_recover({"kind": "dir", "dir": cand})
        print("ok:", res.get("ok"), "flag:", res.get("flag"),
              "matched_sha:", res.get("matched"))
    else:
        print("attachment dir not found at", cand)
