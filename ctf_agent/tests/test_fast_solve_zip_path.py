# -*- coding: utf-8 -*-
"""fast_solve('zip') 参数契约与 zip 链真 flag 盯守（2026-10-15）。

为什么单列一个文件
------------------
`zip` 一直被列在 `_PROVEN_FAST_SOLVE_KINDS`（「真题实证解出过」清单）里，
但实测发现**三处断裂**（都不是"没写"，而是"写了但从不工作 / 拿错"）：

1. **关键词表从未收录 zip**：`_FAST_SOLVE_KEYWORDS` 里没有 `("zip", ...)`
   ⇒ presolve `_try_fast_solve` **从不调用** fast_solve('zip')；
2. **参数契约不齐**：zip 分支两根都要**文件路径**（zip_fake_encryption 要 `path`、
   zip_filename_chain_decode 要 `zip_path`），而 `_try_fast_solve` 只传 `s`（正文
   文本）⇒ 即便调了也恒 `{'ok': False, 'error': 'zip_path not found'}`；
3. **诱饵遮蔽**：原顺序「伪加密优先」先扫 zip 内文本，实测返回 `flag='ni_cai?'`
   （文件名链里的真 flag 就此错过）——与 misc_decode 遮蔽 misc_zip 同型。

结果：crypto 类套娃 zip 题 **0 覆盖**（misc 类靠 math_engine.misc_zip 兜住）。
修复后实测：crypto / misc 均出链中真 flag。

同时给链解码加 `no_brute`：**遇加密层立即放弃**，绝不触发 110 万候选的同步爆破
（爆破交给有墙钟保护的 zip_crypto_bruteforce / bkcrack）——这是把 zip 分支接进
presolve 的**前提**，否则等于给主链路埋一个分钟级挂死点。

变异验证
--------
* 从 `_FAST_SOLVE_KEYWORDS` 摘掉 zip 条目 → crypto 端到端用例必须 FAIL；
* `_try_fast_solve` 不传 path/zip_path → crypto 端到端用例必须 FAIL；
* fast_solve zip 分支去掉 `no_brute=True` → 真加密 fixture 用例必须 FAIL（超时）。
"""

from __future__ import annotations

import base64
import os
import sys
import time
import types
import uuid
import zipfile

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from core import presolve as P  # noqa: E402

_REAL_FLAG = "flag{zipchain_ok_10663}"
_DECOY_FLAG = "DASCTF{ni_cai?}"
# 仓库自带 fixture：真 ZipCrypto 加密（密码 66688）
_ENC_FIXTURE = os.path.join(_ROOT, "tests", "fixtures", "zipcrypto_66688.zip")


# ── 样本构造 ────────────────────────────────────────────────────────────────
def _chain_zip(dirpath: str, real: str = _REAL_FLAG, decoy: str = _DECOY_FLAG) -> str:
    """3 层套娃：真 flag 编码在文件名链，最内层 flag.txt 是诱饵。"""
    x = base64.b32encode(real.encode()).decode().rstrip("=")
    half = len(x) // 2
    first, second = x[half:], x[:half]

    def _mk(path: str, inner: str, data: bytes) -> bytes:
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(inner, data)
        with open(path, "rb") as f:
            blob = f.read()
        os.remove(path)
        return blob

    d = str(dirpath)
    inner = _mk(os.path.join(d, "second.zip"), "flag.txt", decoy.encode())
    mid = _mk(os.path.join(d, "first.zip"), second + ".zip", inner)
    outer = os.path.join(d, "outer_chain.zip")
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr(first + ".zip", mid)
    return outer


def _fake_encrypted_zip(path: str, inner: str, data: bytes) -> str:
    """造**伪加密** zip：内容未加密，仅把 bit0 置位（local + central 都要改）。"""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(inner, data)
    b = bytearray(open(path, "rb").read())
    i = 0
    while True:                       # local file header: flag 在签名后偏移 6
        i = b.find(b"PK\x03\x04", i)
        if i < 0:
            break
        b[i + 6] |= 1
        i += 4
    i = 0
    while True:                       # central directory: flag 在签名后偏移 8
        i = b.find(b"PK\x01\x02", i)
        if i < 0:
            break
        b[i + 8] |= 1
        i += 4
    with open(path, "wb") as f:
        f.write(bytes(b))
    return path


def _q(attachments, category: str = "crypto") -> types.SimpleNamespace:
    return types.SimpleNamespace(
        id=f"t_zip_{uuid.uuid4().hex[:8]}", category=category,
        description="flag 藏在这个 zip 压缩包里，解压看看。",
        attachments=list(attachments), extra={},
    )


# ── 1. 接线 ─────────────────────────────────────────────────────────────────
def test_zip_kind_is_routed_by_keyword_table():
    kinds = {k for k, _ in P._FAST_SOLVE_KEYWORDS}
    assert "zip" in kinds, (
        "zip 不在 _FAST_SOLVE_KEYWORDS ⇒ presolve 从不调 fast_solve('zip')，"
        "却仍被列在 _PROVEN_FAST_SOLVE_KINDS「已实证」清单（声明与实际断裂）"
    )


# ── 2. 端到端：crypto 类套娃 zip（修复前 0 覆盖）────────────────────────────
def test_crypto_nested_zip_yields_chain_flag(tmp_path):
    import asyncio

    outer = _chain_zip(str(tmp_path))
    q = _q([outer], category="crypto")
    flag = asyncio.run(P.presolve(q, registry=None, answers=None, force=True))
    assert flag == _REAL_FLAG, (
        f"crypto 类套娃 zip 未出真 flag：期望 {_REAL_FLAG!r}，实际 {flag!r}"
    )


def test_misc_nested_zip_still_yields_chain_flag(tmp_path):
    """misc 类不受影响（math_engine.misc_zip 兜底 + 本路径均可命中）。"""
    import asyncio

    outer = _chain_zip(str(tmp_path))
    q = _q([outer], category="misc")
    flag = asyncio.run(P.presolve(q, registry=None, answers=None, force=True))
    assert flag == _REAL_FLAG


# ── 3. fast_solve 直调：参数契约 ────────────────────────────────────────────
def test_fast_solve_zip_needs_path_not_only_text(tmp_path):
    """只给正文文本 ⇒ 必须明确失败（不得冒充成功），给了路径 ⇒ 出链中真 flag。"""
    from agents.crypto_toolkit import fast_solve

    outer = _chain_zip(str(tmp_path))
    no_path = fast_solve("zip", s="这是附件正文文本")
    assert not no_path.get("ok"), f"无路径却返回 ok=True（虚报）: {no_path}"

    with_path = fast_solve("zip", s="", path=outer, zip_path=outer)
    assert with_path.get("flag") == _REAL_FLAG, f"有路径却未出真 flag: {with_path}"


def test_fast_solve_zip_prefers_chain_flag_over_inner_decoy(tmp_path):
    """链中真 flag 优先于 zip 内文本（诱饵）返回。"""
    from agents.crypto_toolkit import fast_solve

    outer = _chain_zip(str(tmp_path))
    r = fast_solve("zip", s="", path=outer)
    assert r.get("flag") == _REAL_FLAG
    assert _DECOY_FLAG not in str(r.get("flag")), "返回了 zip 内诱饵 flag"


# ── 4. 护栏：绝不触发同步爆破 ───────────────────────────────────────────────
def test_encrypted_zip_does_not_brute_force():
    """真加密 zip：必须快速放弃（no_brute），不得跑 110 万候选挂住主链路。"""
    from agents.crypto_toolkit import fast_solve

    if not os.path.isfile(_ENC_FIXTURE):
        pytest.skip(f"缺 fixture: {_ENC_FIXTURE}")
    t = time.monotonic()
    r = fast_solve("zip", s="", path=_ENC_FIXTURE)
    dt = time.monotonic() - t
    assert not r.get("ok"), f"真加密 zip（密码 66688）不该被链解码解开: {r}"
    assert dt < 10.0, (
        f"真加密 zip 耗时 {dt:.1f}s：no_brute 失效，正在同步爆破（会挂死主链路）"
    )


def test_nested_zip_with_encrypted_inner_layer_aborts_fast(tmp_path):
    """套娃里含真加密层：必须在毫秒级放弃，不得进入爆破。"""
    from agents.crypto_toolkit import fast_solve

    if not os.path.isfile(_ENC_FIXTURE):
        pytest.skip(f"缺 fixture: {_ENC_FIXTURE}")
    outer = os.path.join(str(tmp_path), "outer_with_enc.zip")
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("inner.zip", open(_ENC_FIXTURE, "rb").read())

    t = time.monotonic()
    r = fast_solve("zip", s="", path=outer)
    dt = time.monotonic() - t
    assert dt < 10.0, f"内层加密时耗时 {dt:.1f}s（no_brute 未生效）"
    assert not r.get("ok")


# ── 5. 回归：伪加密仍可解 ───────────────────────────────────────────────────
def test_fake_encrypted_zip_still_solved(tmp_path):
    from agents.crypto_toolkit import fast_solve

    p = _fake_encrypted_zip(os.path.join(str(tmp_path), "fake.zip"),
                            "flag.txt", b"flag{fake_enc_ok}\n")
    with zipfile.ZipFile(p) as z:
        assert any(i.flag_bits & 0x1 for i in z.infolist()), "样本未置位（构造失效）"
    r = fast_solve("zip", s="", path=p)
    assert r.get("ok"), f"伪加密 zip 回归：本应解出，实际 {r}"
    assert "fake_enc_ok" in str(r.get("flag", "")), f"伪加密 flag 不对: {r}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
