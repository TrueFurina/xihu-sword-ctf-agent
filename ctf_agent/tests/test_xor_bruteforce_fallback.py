"""回归测试：编码块（hex/base64）→ 单字节 / 重复密钥 XOR 爆破（triage 段 2.8）。

背景（2026-10-07）：A5 held-out 5 题离线分诊发现 2 题的确定性攻击「能力缺失」——
triage 段 4 只做 hex/url/base64 多层解码，解不出「解码后仍需 XOR」的格局：
1. CSAW 2018 babycrypto：base64 解码后的字节逐字节取反（单字节 XOR 0xFF）即明文；
2. CSAW 2017 another_xor：plaintext = flag + key + md5(flag+key)、cipher = plaintext
   XOR repeat(key)；存在窗口使 XOR(blob[off:off+L])==0 → 定位 key 长，再由 "flag{"
   前缀与密钥自引用关系传播恢复全 key，末尾 32B hex 的 md5 作仲裁。

本测试保护三条路径（全部防假阳性）：
1. 正例：base64 → 单字节 XOR(0xFF) → 复原 flag（babycrypto 类）。
2. 正例：hex → 内嵌密钥型重复 XOR → 复原 flag（another_xor 类）。
3. 负例：结构相似但不含 flag 的编码块 → 不得误报。
"""
import asyncio
import base64
import hashlib
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


def _write(tmpdir, name, content):
    path = os.path.join(tmpdir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


def _make_embedded_key_xor(flag: bytes, key: bytes) -> str:
    """构造 another_xor 类密文（hex）：plaintext = flag + key + md5(flag+key)。"""
    plaintext = flag + key + hashlib.md5(flag + key).hexdigest().encode()
    ct = bytes(x ^ key[i % len(key)] for i, x in enumerate(plaintext))
    return ct.hex()


def test_single_byte_xor_after_base64_recovers_flag():
    """正例：base64 解码 → 单字节 XOR(0xFF) → 复原 flag（babycrypto 类）。"""
    pt = b"hello, this is a plaintext; the answer is flag{xor_after_b64_ok} bye"
    enc = bytes(x ^ 0xFF for x in pt)          # 逐位取反 = 单字节 XOR 0xFF
    b64 = base64.b64encode(enc).decode()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "ciphertext.txt", b64)
        out, err = _run_fallback([path])
    assert "flag{xor_after_b64_ok}" in out, f"未复原 flag: out={out!r} err={err!r}"


def test_embedded_key_repeating_xor_recovers_flag():
    """正例：hex → 内嵌密钥型重复 XOR → 复原 flag（another_xor 类）。"""
    flag = b"flag{embedded_key_xor_test}"
    key = b"A quart jar of oil mixed with zinc oxide!!"   # len=42, gcd(27,42)=3<=5
    ct_hex = _make_embedded_key_xor(flag, key)
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "encrypted", ct_hex)
        out, err = _run_fallback([path])
    assert "flag{embedded_key_xor_test}" in out, f"未复原 flag: out={out!r} err={err!r}"


def test_negative_no_flag_no_false_positive():
    """负例：结构相似但不含 flag 的编码块 → 不得误报。"""
    pt = b"just some ordinary text with no secret marker at all, move along. "
    enc = bytes(x ^ 0xFF for x in pt)
    b64 = base64.b64encode(enc).decode()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "blob.txt", b64)
        out, err = _run_fallback([path])
    assert "flag{" not in out, f"不应误报 flag: out={out!r} err={err!r}"
