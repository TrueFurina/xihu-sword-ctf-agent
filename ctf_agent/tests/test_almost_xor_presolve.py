"""回归：presolve「n-bit 分组模加密码（almost_xor 家族）」求解（_try_almost_xor）。

背景：CSAW-Quals 2017 almost_xor — 附件含加密脚本（get_vals/get_chrs/encr_vals：
明文与 key 按 n 字节分组 → 每组展开为 8 个 n-bit 值 → 逐值 (m+k) mod 2^n）＋ hex 密文；
n(<8) 与重复 key 均未知。解法：用 flag 前缀恢复 key 前缀 → 枚举 key 长度并爆破 ≤2 个
未知明文字节 → 模减解密。

本测试合成正/负例，并（附件存在时）对真实题目做端到端校验。
"""
import asyncio
import hashlib
import os

import pytest

from core.presolve import _try_almost_xor

_REAL_DIR = "data/questions_ext/_attachments/crypto/2017q-cry-almost_xor"
_REAL_FLAG = "flag{>x0r_i5_Add1+10n-m0D-2,'bU+_+h15_Wa5_m0d=8}"
_REAL_SHA = "6bb0e2756e56c8edb2fab669e3c244bb1db1ff018cee55321972e1bfc169f407"


class _Q:
    def __init__(self, attachments, qid="t", flag_sha256=None):
        self.id = qid
        self.attachments = list(attachments)
        self.flag_sha256 = flag_sha256


# ── 加密侧（照搬 almostxor.py 的语义，用 bytes） ──
def _to_num(bs):
    x = 0
    for i in range(len(bs)):
        x += bs[-1 - i] * (256 ** i)
    return x


def _get_nums(bs, n):
    secs = [bs[i:i + n] for i in range(0, len(bs), n)]
    secs[-1] = secs[-1] + b"\x00" * (n - len(secs[-1]))
    return [_to_num(x) for x in secs]


def _get_vals(x, n):
    vals = []
    mask = (1 << n) - 1
    for _ in range(8):
        vals.append(x & mask)
        x >>= n
    vals.reverse()
    return vals


def _get_chrs(vals, n):
    x = vals[0]
    for i in range(1, len(vals)):
        x <<= n
        x += vals[i]
    out = []
    for _ in range(n):
        out.append(x % 256)
        x //= 256
    out.reverse()
    return bytes(out)


def _encrypt(k: bytes, m: bytes, n: int) -> bytes:
    L = len(m)
    rep_k = k * (L // len(k)) + k[: L % len(k)]
    m_vals = []
    for lst in [_get_vals(x, n) for x in _get_nums(m, n)]:
        m_vals += lst
    k_vals = []
    for lst in [_get_vals(x, n) for x in _get_nums(rep_k, n)]:
        k_vals += lst
    mask = (1 << n) - 1
    c_vals = [(m_vals[i] + k_vals[i % len(k_vals)]) & mask for i in range(len(m_vals))]
    c_list = [c_vals[i:i + 8] for i in range(0, len(c_vals), 8)]
    return b"".join(_get_chrs(lst, n) for lst in c_list)


_FINGERPRINT = (
    "def get_vals(x, n):\n    pass\n"
    "def get_chrs(val_list, n):\n    pass\n"
    "def encr_vals(m, k, n):\n    return (m + k) & ((1 << n) - 1)\n"
)


def _run(q):
    return asyncio.run(_try_almost_xor(q))


def test_positive_synthetic_almost_xor(tmp_path):
    # 明文长度须为 n 的倍数（否则 encrypt 的 rep_k 长度与解密侧不一致）
    flag = b"flag{synth_almost_xor_payload_ok}"
    assert len(flag) % 3 == 0
    key = b"\x11\x22\x33\x44\x55\x66"  # 6 字节
    ct = _encrypt(key, flag, 3)          # n=3
    (tmp_path / "almostxor.py").write_text(_FINGERPRINT, encoding="utf-8")
    (tmp_path / "ciphertext").write_text(ct.hex() + "\n", encoding="utf-8")
    got = _run(_Q([str(tmp_path / "almostxor.py"), str(tmp_path / "ciphertext")],
                  flag_sha256=hashlib.sha256(flag).hexdigest()))
    assert got == flag.decode()


def test_negative_no_fingerprint_script(tmp_path):
    # 无 get_vals/get_chrs/encr_vals 指纹 → 直接跳過
    flag = b"flag{should_not_be_found_here}"
    ct = _encrypt(b"\x01\x02\x03", flag, 3)
    (tmp_path / "decoy.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "ciphertext").write_text(ct.hex(), encoding="utf-8")
    assert _run(_Q([str(tmp_path / "decoy.py"), str(tmp_path / "ciphertext")])) is None


def test_negative_random_hex_no_flag(tmp_path):
    # 有指纹但密文是随机/全零 hex → 无任何候选匹配真值 → None
    (tmp_path / "almostxor.py").write_text(_FINGERPRINT, encoding="utf-8")
    (tmp_path / "ciphertext").write_text("00" * 48, encoding="utf-8")
    assert _run(_Q([str(tmp_path / "almostxor.py"), str(tmp_path / "ciphertext")],
                   flag_sha256=hashlib.sha256(b"some_real_flag").hexdigest())) is None


def test_negative_plaintext_not_flag_prefix(tmp_path):
    # 明文不以 flag 前缀开头；密文多解可能产出可打印伪串，但题面真值(sha256)校验
    # 会将其全部拒绝 → 返回 None。
    payload = b"csaw{this_is_not_almost_xor_padd}"  # 前缀非 flag{
    assert len(payload) % 3 == 0
    (tmp_path / "almostxor.py").write_text(_FINGERPRINT, encoding="utf-8")
    ct = _encrypt(b"\x0a\x0b\x0c\x0d\x0e\x0f", payload, 3)
    (tmp_path / "ciphertext").write_text(ct.hex(), encoding="utf-8")
    got = _run(_Q([str(tmp_path / "almostxor.py"), str(tmp_path / "ciphertext")],
                  flag_sha256=hashlib.sha256(payload).hexdigest()))
    assert got is None


@pytest.mark.skipif(not os.path.isdir(_REAL_DIR), reason="真实题目附件缺失")
def test_real_challenge_almost_xor():
    atts = [os.path.join(_REAL_DIR, n) for n in ("almostxor.py", "ciphertext")
            if os.path.exists(os.path.join(_REAL_DIR, n))]
    got = _run(_Q(atts, qid="ext_nyu_ctf_bench_2017q_cry_almost_xor", flag_sha256=_REAL_SHA))
    assert got == _REAL_FLAG
    assert hashlib.sha256(got.encode()).hexdigest() == _REAL_SHA
