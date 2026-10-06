"""回归：presolve「曲线25519 ECXOR」求解（_try_ecxor）。

背景：CSAW-Finals 2017 ECXOR — 密文是 `;` 分隔的一串 base64，每段解出恰 32 字节
（Curve25519 压缩点）；加密语义 `ct[i] = (key[i mod L] + ord(pt[i])) * G`，key 为
L 个随机字节。解法：逐 residue 用 `ct[i]-ct[锚]` 差分得相对字符偏移（与绝对 key
无关）→ 对 256 个锚字符基值做英文对数似然搜索 → 重建明文搜 flag。

本测试合成正/负例，并（附件存在时）对真实题目做端到端校验。
"""
import asyncio
import base64
import hashlib
import os

import pytest

from core.presolve import _try_ecxor

_REAL_DIR = "data/questions_ext/_attachments/crypto/2017f-cry-ecxor"
_REAL_FLAG = "flag{generalizing_vignere_to_arbitrary_groups_is_not_good}"
_REAL_SHA = "0e063f15a4c24ca6e9d9277225fdf5f8ff7b9ea61d66e0a111eae4919d6a489f"


# ── 自足 Curve25519（RFC8032）算术：仅供测试构造密文 ──
_P = 2 ** 255 - 19


def _inv(x):
    return pow(x % _P, _P - 2, _P)


_D = (-121665 * _inv(121666)) % _P


def _padd(Pp, Q):
    A = (Pp[1] - Pp[0]) * (Q[1] - Q[0]) % _P
    B = (Pp[1] + Pp[0]) * (Q[1] + Q[0]) % _P
    C = 2 * Pp[3] * Q[3] * _D % _P
    Dd = 2 * Pp[2] * Q[2] % _P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pmul(s, Pp):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _padd(Q, Pp)
        Pp = _padd(Pp, Pp)
        s >>= 1
    return Q


def _compress(Pp):
    zi = _inv(Pp[2])
    x = Pp[0] * zi % _P
    y = Pp[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


_sqrt_m1 = pow(2, (_P - 1) // 4, _P)


def _recx(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return 0 if not sign else None
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _sqrt_m1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_gy = 4 * _inv(5) % _P
_gx = _recx(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _P)


def _encrypt(key: bytes, pt: bytes) -> bytes:
    L = len(key)
    points = [_padd(_pmul(key[i % L], _G), _pmul(pt[i], _G)) for i in range(len(pt))]
    return b";".join(base64.b64encode(_compress(p)) for p in points)


_FINGERPRINT = "def point_add(P, Q):\n    pass\ndef point_mul(s, P):\n    pass\n"


class _Q:
    def __init__(self, attachments, qid="t", flag_sha256=None, description=""):
        self.id = qid
        self.attachments = list(attachments)
        self.flag_sha256 = flag_sha256
        self.description = description


def _run(q):
    return asyncio.run(_try_ecxor(q))


def test_positive_synthetic_ecxor(tmp_path):
    flag = b"flag{synth_ecxor_recover_ok}"
    # 明文足够长且含自然空格/字母，保证英文似然能定住各 residue 的基值
    tail = b" the quick brown fox jumps over the lazy dog, and then it runs away\n"
    pt = flag + tail
    key = b"\x11\x22\x33\x44\x55"  # L=5
    ct = _encrypt(key, pt)
    (tmp_path / "rfc8032.py").write_text(_FINGERPRINT, encoding="utf-8")
    (tmp_path / "ciphertext").write_bytes(ct)
    got = _run(_Q([str(tmp_path / "rfc8032.py"), str(tmp_path / "ciphertext")],
                  flag_sha256=hashlib.sha256(flag).hexdigest()))
    assert got == flag.decode()


def test_negative_no_curve_fingerprint(tmp_path):
    # 无曲线指纹（无 point_add/point_mul，描述也不含 25519）→ 直接跳过
    pt = b"flag{should_not_be_found_here}" + b" the quick brown fox jumps over\n"
    ct = _encrypt(b"\x01\x02\x03", pt)
    (tmp_path / "decoy.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "ciphertext").write_bytes(ct)
    assert _run(_Q([str(tmp_path / "decoy.py"), str(tmp_path / "ciphertext")])) is None


def test_negative_random_points_no_flag(tmp_path):
    # 结构合法（32 字节压缩点 + 曲线指纹）但明文无 flag → None
    import random
    rnd = random.Random(1234)
    blobs = [_compress(_pmul(rnd.randrange(1, 2 ** 200), _G)) for _ in range(24)]
    ct = b";".join(base64.b64encode(b) for b in blobs)
    (tmp_path / "rfc8032.py").write_text(_FINGERPRINT, encoding="utf-8")
    (tmp_path / "ciphertext").write_bytes(ct)
    assert _run(_Q([str(tmp_path / "rfc8032.py"), str(tmp_path / "ciphertext")],
                   flag_sha256=hashlib.sha256(b"some_real_flag").hexdigest())) is None


def test_negative_sha_mismatch(tmp_path):
    # 明文含合法 flag 模式，但题面真值 sha256 不符 → 拒绝
    flag = b"flag{this_is_a_decoy_not_real}"
    pt = flag + b" the quick brown fox jumps over the lazy dog again\n"
    ct = _encrypt(b"\x07\x08\x09\x0a", pt)
    (tmp_path / "rfc8032.py").write_text(_FINGERPRINT, encoding="utf-8")
    (tmp_path / "ciphertext").write_bytes(ct)
    got = _run(_Q([str(tmp_path / "rfc8032.py"), str(tmp_path / "ciphertext")],
                  flag_sha256=hashlib.sha256(b"flag{different_real_flag}").hexdigest()))
    assert got is None


@pytest.mark.skipif(not os.path.isdir(_REAL_DIR), reason="真实题目附件缺失")
def test_real_challenge_ecxor():
    names = ("ecxor_handout_100.py", "rfc8032.py", "ciphertext")
    atts = [os.path.join(_REAL_DIR, n) for n in names
            if os.path.exists(os.path.join(_REAL_DIR, n))]
    got = _run(_Q(atts, qid="ext_nyu_ctf_bench_2017f_cry_ecxor",
                  flag_sha256=_REAL_SHA,
                  description="Can you break this curve25519-encrypted message?"))
    assert got == _REAL_FLAG
    assert hashlib.sha256(got.encode()).hexdigest() == _REAL_SHA
