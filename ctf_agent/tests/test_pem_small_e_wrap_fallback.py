"""回归测试：PEM 公钥布局下的小指数跨模攻击（CSAW 2018 lowe 类）。

背景（2026-10-07）：A5 held-out 5 题实跑 0/5，卡壳 176 次无进展。根因并非
「缺少攻击能力」——`skills.rsa_fermat_factor._small_e_attack` 早已支持跨模
k 爆破（m^e = c + k*n）；缺的是 triage 层的**附件布局解析**：lowe 的附件是
`pubkey.pem` + 十进制大整数密文 + base64 密文块，triage 既不解析 PEM 取 (N,e)，
也不知道把复原出的密钥与 base64 块 XOR，故该能力在生产中恒不可达。

本测试保护两条路径：
1. 正例：PEM(e=3) + 十进制 c（c ≈ N）+ 等长 base64 blob → 复原 m → blob⊕m = flag。
2. 负例：只有 PEM + 十进制 c、无 base64 blob → 不得误报 flag（防假阳性）。
"""
import asyncio
import base64
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.crypto_toolkit import CryptoToolkit  # noqa: E402
from sandbox.subprocess_executor import SubprocessExecutor  # noqa: E402


def _run_fallback(paths: list) -> tuple:
    script = CryptoToolkit.build_fallback_script(paths[0], extra_paths=paths[1:])
    assert script, "应生成 fallback 脚本"
    ex = SubprocessExecutor()

    async def _run():
        r = await ex.run("python: " + script, timeout=120)
        return r.stdout, r.stderr

    return asyncio.run(_run())


def _iroot(k: int, x: int) -> int:
    hi = 1 << ((x.bit_length() + k - 1) // k + 1)
    lo = 0
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid
    return lo


def _make_fixture(secret: bytes):
    """构造 lowe 类三附件：pubkey.pem(e=3) + c(十进制) + blob(base64)。"""
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import getPrime, long_to_bytes

    p, q = getPrime(768), getPrime(768)
    N = p * q
    e = 3
    # 取 K 落在 (N^(1/3), (2N)^(1/3)) → K^3 ∈ (N, 2N)，使 c = K^3 - N（恰好跨 1 次模）
    lo, hi = _iroot(3, N) + 1, _iroot(3, 2 * N)
    assert lo < hi
    K = (lo + hi) // 2
    c = pow(K, e, N)
    assert c == K ** 3 - N, "fixture 前提：K^3 必须恰好跨 1 次模"
    pem = RSA.construct((N, e)).export_key("PEM").decode()
    kb = long_to_bytes(K)
    # 关键：secret 必须严格等于 len(kb) 字节，否则 zip() 会按较短者截断，
    # 造成 blob 比恢复出的 m 短 1 字节 → 行 692 的 `len(_bd)!=len(_mb)` 守卫
    # 把唯一候选跳过 → 正例偶发失败。K 在 (0.9·2^512,1.13·2^512) 间浮动，
    # len(kb) 可能是 64 或 65，故必须按 len(kb) 对齐而非写死 64。
    secret = secret[:len(kb)].ljust(len(kb), b"_") if len(secret) >= len(kb) \
        else secret.ljust(len(kb), b"_")
    blob = bytes(x ^ y for x, y in zip(secret, kb))  # len == len(kb)
    return pem, str(c), base64.b64encode(blob).decode()


def _write(tmpdir, name, content):
    path = os.path.join(tmpdir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


def test_pem_small_e_wrap_xor_recovers_flag():
    """正例：PEM + 十进制 c + 等长 base64 blob → 复原 flag。"""
    secret = (b"flag{pem_small_e_wrap_ok}").ljust(64, b"_")  # 64B，与 K 等长
    pem, ctext, blob = _make_fixture(secret)
    with tempfile.TemporaryDirectory() as d:
        paths = [
            _write(d, "pubkey.pem", pem),
            _write(d, "key.enc", ctext),
            _write(d, "file.enc", blob),
        ]
        out, err = _run_fallback(paths)
    assert "flag{pem_small_e_wrap_ok}" in out, f"未复原 flag: out={out!r} err={err!r}"


def test_pem_small_e_wrap_no_false_positive():
    """负例：无 base64 伴随块时不得误报 flag（防假阳性）。"""
    secret = (b"flag{should_not_leak}").ljust(64, b"_")
    pem, ctext, _ = _make_fixture(secret)
    with tempfile.TemporaryDirectory() as d:
        paths = [_write(d, "pubkey.pem", pem), _write(d, "key.enc", ctext)]
        out, err = _run_fallback(paths)
    assert "flag{" not in out, f"不应误报 flag: out={out!r} err={err!r}"
