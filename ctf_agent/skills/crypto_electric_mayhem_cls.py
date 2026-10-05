"""Electric Mayhem CLS — AES-128 power-analysis (CPA) side-channel solver.

B1 工具链补齐第四道（2026-10-05）。Google CTF 2022 `crypto-electric-mayhem-cls`
是一道 **功耗分析（CPA）** 题：题目直接给出模拟功耗轨迹（ELMO 模型），
无需真实示波器/靶机即可离线求解。

机理：AES-128 第一轮 SubBytes 输入为 `u = Sbox[pt[i] ^ key[i]]`，该字节的
汉明重量（Hamming weight）会与功耗轨迹相关。对每个密钥字节做 256 候选的
相关功耗分析（Pearson 相关），峰值对应的候选即为真密钥字节。

诚实定位：本题属 `questions_external` 外部池口径，**不进 `offline_verified=14` 台账**；
属「工具链补齐」产物，不代表 LLM 自主推理能力。
"""

import hashlib
import json
import gzip
import os
import numpy as np

# Standard AES S-box
_SBOX = np.array([
 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
], dtype=np.uint8)


def _popcount8(x):
    x = x.astype(np.uint32)
    c = (x & 0x55) + ((x >> 1) & 0x55)
    c = (c & 0x33) + ((c >> 2) & 0x33)
    c = (c & 0x0f) + ((c >> 4) & 0x0f)
    return c.astype(np.float64)


def solve_aes_cpa(pt_list, pm_list, n_bytes=16):
    """CPA on AES-128 first-round S-box.

    pt_list: iterable of 16-byte plaintexts (list[int] or bytes)
    pm_list: iterable of power traces (list[float], length L per trace)
    returns: 16-byte key (np.uint8 array)
    """
    pt = np.asarray([list(p) for p in pt_list], dtype=np.uint8)   # (N,16)
    R = np.asarray(pm_list, dtype=np.float64)                    # (N,L)
    N, L = R.shape
    Rc = R - R.mean(axis=0, keepdims=True)

    key = np.zeros(n_bytes, dtype=np.uint8)
    for i in range(n_bytes):
        xor = pt[:, i:i + 1] ^ np.arange(256, dtype=np.uint8).reshape(1, 256)  # (N,256)
        H = _popcount8(_SBOX[xor])                                      # (N,256) HW of Sbox out
        Hc = H - H.mean(axis=0, keepdims=True)
        cov = (Hc.T @ Rc) / N                                           # (256,L)
        denom = (np.sqrt((Hc ** 2).sum(axis=0))[:, None]
                 * np.sqrt((Rc ** 2).sum(axis=0))[None, :])
        denom[denom == 0] = 1.0
        corr = np.abs(cov / denom)                                      # (256,L)
        kbest = int(np.argmax(corr) // L)
        key[i] = kbest
    return key


def _load_challenge_json(path):
    """Load an Electric-Mayhem-style trace json: list of {pt, ct, pm}."""
    if path.endswith(".gz"):
        with gzip.open(path, "rt") as f:
            data = json.load(f)
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    pt = [bytes(e["pt"]) for e in data]
    pm = [e["pm"] for e in data]
    return pt, pm


def _format_flag(key_bytes, expected_sha=None):
    """Try common encodings; return (flag_bytes, matched_bool)."""
    raw = bytes(key_bytes)
    candidates = [
        b"CTF{" + raw + b"}",
        b"CTF{" + raw.hex().encode() + b"}",
        b"CTF{" + raw.decode("latin1").encode() + b"}",
    ]
    if expected_sha is None:
        return candidates[0], None
    for c in candidates:
        if hashlib.sha256(c).hexdigest() == expected_sha:
            return c, True
    return candidates[0], False


def crypto_electric_mayhem_cls(params):
    """Skill entry.

    params:
      kind='file'  -> path=... (trace json), expected_sha=... (optional)
      kind='solve' -> pt=[...], pm=[...], expected_sha=... (optional)
    returns dict {flag, key_hex, matched, ok}
    """
    kind = params.get("kind", "file")
    expected_sha = params.get("expected_sha")
    if kind == "file":
        pt, pm = _load_challenge_json(params["path"])
    elif kind == "solve":
        pt = [bytes(p) for p in params["pt"]]
        pm = params["pm"]
    else:
        return {"ok": False, "error": "unknown kind %r" % kind}

    key = solve_aes_cpa(pt, pm)
    flag, matched = _format_flag(key, expected_sha)
    return {
        "ok": True,
        "flag": flag.decode("latin1"),
        "key_hex": key.tobytes().hex(),
        "matched": matched,
    }


def run(params):
    """Unified run() interface (skills are discovered by run(params)->dict)."""
    return crypto_electric_mayhem_cls(params)


if __name__ == "__main__":
    # smoke: locate the local challenge attachment and solve
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.join(
        here, "..", "data", "questions_external", "crypto",
        "ext_gctf2022_electric-mayhem-cls", "_attachments", "stm32f0_aes.json.gz")
    if os.path.isfile(cand):
        pt, pm = _load_challenge_json(cand)
        k = solve_aes_cpa(pt, pm)
        flag, ok = _format_flag(k)
        print("key_hex:", k.tobytes().hex())
        print("flag:", flag.decode("latin1"), "matched_sha:", ok)
    else:
        print("attachment not found at", cand)
