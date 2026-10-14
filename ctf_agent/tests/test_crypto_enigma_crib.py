# -*- coding: utf-8 -*-
"""crypto_enigma_crib 求解器测试（B1 第八道 enigma，2026-10-14）。

覆盖：
1. 真钥机制校验：攻击恢复的配置全量解密 == crib（2641/2641，快）；
2. Fernet 纯标准库实现 == cryptography 库（含 NIST AES-128 向量）；
3. flag 解析器：德语指令文本 → CTF{...}（题库 sha256 校验）；
4. 负例：错长度密文 / 缺文件 / 无 numpy → 一律 None 不崩；
5. 反捷径：skill 源码不含 flag 明文 / 题库 sha256；
6. 真题全链（@slow）：crib 海选 → 环扫 → 插板爬山 → fernet → flag。
"""

from __future__ import annotations

import ast  # noqa: E402
import hashlib  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import crypto_enigma_crib as M  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_QDIR = _ROOT / "data" / "questions_external" / "crypto" / "ext_gctf2022_enigma"
_CT = _QDIR / "_attachments" / "messages" / "may_12_2022" / "flag.ciphertext.txt"
_FERNET = _QDIR / "_attachments" / "messages" / "may_12_2022" / "flag.fernet.txt"
_QJSON = _QDIR.parent / "ext_gctf2022_enigma.json"

# 攻击恢复并经官方 settings 对拍的配置（VII IV I / ATN / 10 插板 / CLR）
_TRUE_STATE = (
    M.TIDX["VII"], M.TIDX["IV"], M.TIDX["I"],   # 左中右转子
    13, 19,                                      # 右环 N、中环 T（左环规范为 A）
    17, 11, 2,                                   # 右位置 R、中位置 L、左位置 C
    None,                                        # 插板占位（下方构造）
)
_TRUE_PLUGS = [(0, 7), (1, 14), (2, 11), (3, 20), (5, 22),
               (6, 12), (9, 24), (10, 25), (15, 21), (16, 23)]

_TRUTH_SHA = ""
if _QJSON.is_file():
    import json
    try:
        _TRUTH_SHA = str(json.loads(_QJSON.read_text(encoding="utf-8")).get("flag_sha256") or "")
    except Exception:
        _TRUTH_SHA = ""

needs_question = pytest.mark.skipif(not _CT.is_file(), reason="enigma 题目附件未落地")


def _true_state():
    plug = list(range(26))
    for a, b in _TRUE_PLUGS:
        plug[a], plug[b] = b, a
    return _TRUE_STATE[:8] + (plug,)


def _ct_letters():
    return [c - 65 for c in _CT.read_bytes() if 65 <= c <= 90]


def _crib_letters():
    return M._letters(M._CRIB.encode("ascii"))


# ─────────────────────────── 1. 机制校验（快） ───────────────────────────

@needs_question
def test_recovered_key_decrypts_crib_exactly():
    """攻击恢复的配置必须把密文逐字母解成 crib（2641/2641）。"""
    import numpy as np
    ct = np.array(_ct_letters(), dtype=np.int8)
    pt = np.array(_crib_letters(), dtype=np.int8)
    st = _true_state()
    d = M._decrypt_batch(ct, *st[:8], plug=np.array(st[8], dtype=np.int8), n=len(ct))
    assert bool((d == pt).all()), f"only {int((d == pt).sum())}/{len(ct)} match"


@needs_question
def test_settings_string_matches_official_format():
    """还原的设置串形态 = machine.cc 语义（左中右环序、插板对排序）。"""
    s = M._settings_string(_true_state())
    parts = s.split()
    assert parts[:3] == ["VII", "IV", "I"]
    assert len(parts[4:14]) == 10 and parts[14] and len(parts[14]) == 3
    assert parts[4:14] == sorted(parts[4:14])


# ─────────────────────────── 2. Fernet / AES ───────────────────────────

def test_aes128_nist_vector():
    """纯 Python AES-128 解密对拍 FIPS-197 算例。"""
    rks = M._aes128_expand(bytes(range(16)))
    out = M._aes128_decrypt_block(
        bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"), rks)
    assert out.hex() == "00112233445566778899aabbccddeeff"


@needs_question
def test_fernet_matches_cryptography_library():
    """纯标准库 Fernet 解密 == cryptography 库输出（PBKDF2+HMAC+AES-CBC）。"""
    cryptography = pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet
    blob = _FERNET.read_bytes()
    key_material = M._settings_string(_true_state()).encode("utf-8")
    ref = Fernet(M._fernet_key(key_material, blob[:16])).decrypt(blob[16:])
    assert M._fernet_decrypt(blob, key_material) == ref


@needs_question
def test_parse_flag_from_original():
    """德语指令文本 → flag；题库 sha256 校验（缺真值则只验形态）。"""
    key_material = M._settings_string(_true_state()).encode("utf-8")
    original = M._fernet_decrypt(_FERNET.read_bytes(), key_material)
    assert original is not None
    flag = M._parse_flag(original.decode("utf-8"))
    assert flag and flag.startswith("CTF{") and flag.endswith("}")
    if _TRUTH_SHA:
        assert hashlib.sha256(flag.encode()).hexdigest() == _TRUTH_SHA


# ─────────────────────────── 3. 负例 ───────────────────────────

@needs_question
def test_negative_wrong_length_ciphertext(tmp_path):
    """字母数 ≠ crib 长度 → None（不对无关文本开火）。"""
    p = tmp_path / "short.txt"
    p.write_text("ABCDEFGHIJ" * 60, encoding="utf-8")   # 600 letters
    assert M.run({"path": str(p)}).get("flag") is None


def test_negative_missing_file():
    assert M.run({"path": "/nonexistent/xyz.txt"}).get("flag") is None
    assert M.run({}).get("flag") is None


def test_negative_no_numpy(monkeypatch):
    """无 numpy 时优雅降级 None（不崩、不谎报）。"""
    monkeypatch.setattr(M, "np", None)
    assert M.run({"path": str(_CT)}).get("flag") is None


# ─────────────────────────── 4. 反捷径 ───────────────────────────

def test_no_flag_plaintext_or_sha_in_source():
    """skill 源码不得含 flag 明文 / 题库 sha256（crib 是编码字母流，不含标志）。"""
    src = (_ROOT / "skills" / "crypto_enigma_crib.py").read_text(encoding="utf-8")
    assert "DU HAST GETAN" not in src
    assert "TURING NICHT KONNTE" not in src
    assert "VII IV I ATN" not in src          # 设置串也不许内嵌（必须搜索恢复）
    if _TRUTH_SHA:
        assert _TRUTH_SHA not in src and _TRUTH_SHA[:16] not in src


def test_numpy_import_is_guarded():
    """numpy import 必须 try/except 包裹（无 numpy 环境可导入）。"""
    src = (_ROOT / "skills" / "crypto_enigma_crib.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    has_guard = any(
        isinstance(n, ast.Try) and any(
            isinstance(s2, ast.Import) and any(a.name == "numpy" for a in s2.names)
            for s2 in n.body)
        for n in ast.walk(tree))
    assert has_guard, "numpy import 未在 try/except 内"


# ─────────────────────────── 5. 真题全链（slow） ───────────────────────────

@pytest.mark.slow
@needs_question
def test_real_question_full_attack():
    """真题全链：crib 海选 → 环扫 → 插板爬山 → fernet → flag（sha256 校验）。"""
    res = M.run({"path": str(_CT)})
    flag = res.get("flag")
    assert flag, res
    if _TRUTH_SHA:
        assert hashlib.sha256(flag.encode()).hexdigest() == _TRUTH_SHA
