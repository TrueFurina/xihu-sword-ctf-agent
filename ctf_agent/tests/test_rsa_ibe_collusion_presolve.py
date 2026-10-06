"""回归：presolve「RSA-IBE collusion（串谋攻击）」求解（_try_rsa_ibe_collusion）。

背景：CSAW-Quals 2018 collusion — 身份基加密（IBE），给两名解密者 B、C 的私钥
（`d_id=(x+n)^{-1} mod φ(N)`）与一份对目标 A 的密文（`V=3^{(x+n_A)r}`、AES-GCM）。
串谋攻击：`k=d_B·d_C·(n_B−n_C)+d_B−d_C ≡ 0 (mod φ(N))` → 分解 N → 得 φ、x →
对目标求 `d_A` 解 K → 解密。身份 id 经确定性 PRNG（Go `crypto/rand.Int` over
`AES-256-CTR(sha256(id), iv=0)`）映射为 <N 的奇数。

本测试合成正/负例，并（附件存在时）对真实题目做端到端校验。
"""
import asyncio
import base64
import hashlib
import json
import math
import os

import pytest

from core.presolve import _try_rsa_ibe_collusion

_REAL_DIR = "data/questions_ext/_attachments/crypto/2018q-cry-collusion"
_REAL_FLAG = "flag{flag_created_in_validation_mission_payload}"
_REAL_SHA = "f2f037fd6d9e354ca4a6d28312fccb2335f83e42399ff77c8e8cd0834cf9edec"

# 两个确定的素数（M61 与 2^64-59），仅供测试构造 N=pq
_P = 2305843009213693951          # 2^61 - 1
_Q = 18446744073709551557         # 最大 < 2^64 的素数


def _did(name: str, N: int) -> int:
    """复刻 Go 的 DecrypterId（AES-256-CTR(sha256(id), iv=0) 零流 → rand.Int）。"""
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    bitlen = (N - 1).bit_length()
    k = (bitlen + 7) // 8
    b = bitlen % 8 or 8
    mask = (1 << b) - 1
    c = AES.new(hashlib.sha256(name.encode()).digest(), AES.MODE_CTR,
                counter=Counter.new(128, initial_value=0))
    while True:
        raw = bytearray(c.encrypt(b"\x00" * k))
        raw[0] &= mask
        n = int.from_bytes(bytes(raw), "big")
        if n < N:
            return n | 1


def _build(dirpath, message: bytes, target="Alice", nm_b="bob", nm_c="carol",
           p=_P, q=_Q, x0=12345678, name_b="bobs-key.json", name_c="carols-key.json",
           N_override=None):
    """在 dirpath 下生成一份 IBE 挑战（bobs/carols key + message）。"""
    from Crypto.Cipher import AES

    N = (p * q) if N_override is None else N_override
    phi = (p - 1) * (q - 1)
    x = x0 - (x0 % 2)                        # x 必须为偶数
    ids = {nm: _did(nm, N) for nm in (nm_b, nm_c, target)}
    while any(math.gcd((x + ids[nm]) % phi, phi) != 1 for nm in ids):
        x += 2
    dB = pow((x + ids[nm_b]) % phi, -1, phi)
    dC = pow((x + ids[nm_c]) % phi, -1, phi)
    r = 987654321 % (N - 1) or 3
    V = pow(3, (x + ids[target]) * r, N)
    K = pow(3, r, N)
    kb = K.to_bytes((K.bit_length() + 7) // 8, "big")
    aes_key = hashlib.sha256(kb).digest()
    nonce = bytes(range(12))
    # Go 的 cipher.Seal 返回「密文 ‖ 16字节 tag」，须用 encrypt_and_digest 对齐
    ct, tag = AES.new(aes_key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(message)
    body = ct + tag
    (dirpath / name_b).write_text(json.dumps({"N": N, "D": dB}), encoding="utf-8")
    (dirpath / name_c).write_text(json.dumps({"N": N, "D": dC}), encoding="utf-8")
    (dirpath / "message.json").write_text(json.dumps({
        "V": V,
        "Nonce": base64.b64encode(nonce).decode(),
        "Body": base64.b64encode(body).decode(),
    }), encoding="utf-8")
    return N


class _Q:
    def __init__(self, attachments, qid="t", flag_sha256=None, flag_pattern=None,
                 description=""):
        self.id = qid
        self.attachments = list(attachments)
        self.flag_sha256 = flag_sha256
        self.flag_pattern = flag_pattern
        self.description = description


def _atts(tmp_path):
    return [str(tmp_path / n) for n in
            ("bobs-key.json", "carols-key.json", "message.json")]


def _run(q):
    return asyncio.run(_try_rsa_ibe_collusion(q))


def test_positive_synthetic_collusion(tmp_path):
    msg = b"flag{synthetic_collusion_ok}"
    _build(tmp_path, msg)
    got = _run(_Q(_atts(tmp_path), flag_sha256=hashlib.sha256(msg).hexdigest()))
    assert got == msg.decode()


def test_positive_validation_prefix_convention(tmp_path):
    # 明文非 flag 形态，真值是 benchmark 的「重生成 flag」前缀包装 → 由 sha 选定
    _build(tmp_path, b"mission payload")
    sha = hashlib.sha256(b"flag{flag_created_in_validation_mission_payload}").hexdigest()
    got = _run(_Q(_atts(tmp_path), flag_sha256=sha))
    assert got == "flag{flag_created_in_validation_mission_payload}"


def test_positive_no_sha_extract_literal_flag(tmp_path):
    # 无真值：明文本身含 flag 子串 → 直接提取（不臆造包装）
    _build(tmp_path, b"here is flag{literal_in_message} bye")
    got = _run(_Q(_atts(tmp_path)))
    assert got == "flag{literal_in_message}"


def test_negative_no_sha_no_literal_flag(tmp_path):
    # 无真值且明文不含 flag 子串 → 不得臆造 "flag{...}" → None
    _build(tmp_path, b"mission payload")
    assert _run(_Q(_atts(tmp_path))) is None


def test_negative_sha_mismatch(tmp_path):
    # 真值与明文任何候选都不符 → None（宁缺勿滥）
    _build(tmp_path, b"mission payload")
    got = _run(_Q(_atts(tmp_path), flag_sha256=hashlib.sha256(b"other").hexdigest()))
    assert got is None


def test_negative_missing_shape(tmp_path):
    # 只有一把私钥 → 结构指纹不成立 → 跳过
    _build(tmp_path, b"flag{x}")
    (tmp_path / "carols-key.json").unlink()
    assert _run(_Q(_atts(tmp_path))) is None


def test_negative_different_modulus(tmp_path):
    # 两把私钥 N 不同 → 不是同一 IBE 系统 → 跳过
    _build(tmp_path, b"flag{x}")
    other = json.loads((tmp_path / "carols-key.json").read_text(encoding="utf-8"))
    other["N"] = other["N"] + 4
    (tmp_path / "carols-key.json").write_text(json.dumps(other), encoding="utf-8")
    assert _run(_Q(_atts(tmp_path))) is None


@pytest.mark.skipif(not os.path.isdir(_REAL_DIR), reason="真实题目附件缺失")
def test_real_challenge_collusion():
    names = ("bobs-key.json", "carols-key.json", "message.json", "common.go")
    atts = [os.path.join(_REAL_DIR, n) for n in names
            if os.path.exists(os.path.join(_REAL_DIR, n))]
    got = _run(_Q(atts, qid="ext_nyu_ctf_bench_2018q_cry_collusion",
                  flag_sha256=_REAL_SHA,
                  flag_pattern=r"[A-Za-z0-9_]{1,12}\{[^}\s]{3,120}\}",
                  description="decrypt the message to A"))
    assert got == _REAL_FLAG
    assert hashlib.sha256(got.encode()).hexdigest() == _REAL_SHA
