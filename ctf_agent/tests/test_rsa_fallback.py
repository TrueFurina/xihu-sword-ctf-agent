"""P0-C 回归测试：crypto fallback 的 RSA 确定性攻击链路。

背景（2026-08-21 整改）：实测 LLM 现场写 RSA 攻击代码 0/2 全错
（real_crypto_exciting_inverse=phi_known、real_crypto_ezrsa=Hastad 都失败）。
整改：fallback 复用 skills.rsa_fermat_factor 全套确定性攻击
（phi_known/small_e/共模/Hastad/Wiener/费马），沙盒 AST 白名单放行 skills 导入。

本测试保护三条关键路径：
1. 费马分解（p/q 接近，auto 分支）
2. phi_known（已知 phi 直接解密，兼容 # 注释前缀附件）
3. Hastad 广播（e=3 多组 n/c，附件无 n/c 只有 n1..n3/c1..c3）
"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.crypto_toolkit import CryptoToolkit  # noqa: E402
from sandbox.subprocess_executor import SubprocessExecutor  # noqa: E402


def _run_fallback(path: str) -> tuple[str, str]:
    script = CryptoToolkit.build_fallback_script(path)
    assert script, "应生成 fallback 脚本"
    ex = SubprocessExecutor()

    async def _run():
        r = await ex.run("python: " + script, timeout=60)
        return r.stdout, r.stderr

    return asyncio.run(_run())


def test_fermat_fallback():
    """费马分解：p/q 相邻 → auto 分支（费马）解出 flag。"""
    from Crypto.Util.number import getPrime
    import gmpy2

    p = getPrime(512)
    q = int(gmpy2.next_prime(p))
    n = p * q
    m = int.from_bytes(b"flag{fermat_fallback_ok}", "big")
    c = pow(m, 65537, n)
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as f:
        f.write(f"n = {n}\ne = 65537\nc = {c}\n")
    try:
        out, err = _run_fallback(path)
        assert "flag{fermat_fallback_ok}" in out, f"费马分解未解出: out={out!r} err={err!r}"
    finally:
        os.unlink(path)


def test_phi_known_fallback():
    """已知 phi 直接解密（ExcitingInverse 类），兼容 # 注释前缀 + 冒号分隔。"""
    from Crypto.Util.number import getPrime
    import gmpy2

    p = getPrime(512)
    q = int(gmpy2.next_prime(p))
    n = p * q
    phi = (p - 1) * (q - 1)
    m = int.from_bytes(b"flag{phi_known_fallback_ok}", "big")
    c = pow(m, 65537, n)
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as f:
        f.write(f"# n: {n}\n# e: 65537\n# c: {c}\n# phi: {phi}\n")
    try:
        out, err = _run_fallback(path)
        assert "flag{phi_known_fallback_ok}" in out, f"phi_known 未解出: out={out!r} err={err!r}"
    finally:
        os.unlink(path)


def test_hastad_fallback():
    """Hastad 广播：e=3 多组 (n,c)，附件只有 n1..n3/c1..c3 无 n/c。"""
    from Crypto.Util.number import getPrime

    m = int.from_bytes(b"flag{hastad_fallback_ok}", "big")
    e = 3
    ns, cs = [], []
    for _ in range(3):
        while True:
            p = getPrime(512)
            q = getPrime(512)
            n = p * q
            if pow(m, e) < n:  # 保证 m^e 未取模（Hastad 前提）
                ns.append(n)
                cs.append(pow(m, e, n))
                break
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as f:
        f.write(f"n1 = {ns[0]}\nc1 = {cs[0]}\n"
                f"n2 = {ns[1]}\nc2 = {cs[1]}\n"
                f"n3 = {ns[2]}\nc3 = {cs[2]}\ne = {e}\n")
    try:
        out, err = _run_fallback(path)
        assert "flag{hastad_fallback_ok}" in out, f"Hastad 未解出: out={out!r} err={err!r}"
    finally:
        os.unlink(path)


def test_common_modulus_fallback():
    """共模攻击：同 n 双公钥 (e1,c1),(e2,c2)。"""
    from Crypto.Util.number import getPrime

    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    m = int.from_bytes(b"flag{common_modulus_ok}", "big")
    e1, e2 = 65537, 65539
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as f:
        f.write(f"n = {n}\ne1 = {e1}\nc1 = {c1}\ne2 = {e2}\nc2 = {c2}\n")
    try:
        out, err = _run_fallback(path)
        assert "flag{common_modulus_ok}" in out, f"共模未解出: out={out!r} err={err!r}"
    finally:
        os.unlink(path)
