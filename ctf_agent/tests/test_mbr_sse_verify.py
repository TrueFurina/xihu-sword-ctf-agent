"""skills/mbr_sse_verify（MBR 内 SSE andps+psadbw 校验链反推）行为 + 变异测试。

真实性：真实 CSAW-Quals 2017 rev/realism 的 sha256 锁——附件缺失时跳过；
       断言返回值的 sha256 与题面 flag_sha256 逐字一致（测试里不落明文 flag）。
合成：自建 (init16, body, pshufd_imm) 三元组，按程序语义正推 8 项期望表，
       断言求解器还原出**能重建期望表**的 flag（证明是算法在解，不是硬编码）。
变异验证：破坏 pshufd 逆置换 / 目标表顺序 / 掩码表结构后，真题或合成必须解不出。
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import mbr_sse_verify as M  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_POOL_DIR = _ROOT / "data" / "questions_ext"
_REAL_BIN = (_POOL_DIR / "_attachments" / "rev" / "2017q-rev-realism" / "main.bin")
_REAL_QID = "ext_nyu_ctf_bench_2017q_rev_realism"
_j = _POOL_DIR / "rev" / f"{_REAL_QID}.json"
_REAL_SHA = None
if _j.exists():
    _REAL_SHA = json.loads(_j.read_text(encoding="utf-8")).get("flag_sha256")

_need_real = pytest.mark.skipif(
    not (_REAL_BIN.exists() and _REAL_SHA), reason=f"真题附件/题面缺失: {_REAL_BIN}")

_MASK_ADDR = 0x7D90
_EXP_ADDR = 0x7DA8


def _shuf_forward(body: bytes, imm: int) -> bytes:
    dw = [body[0:4], body[4:8], body[8:12], body[12:16]]
    perm = [(imm >> (2 * i)) & 3 for i in range(4)]
    return b"".join(dw[perm[i]] for i in range(4))


def _exp_from(init16, body, imm):
    shuf = list(_shuf_forward(body, imm))
    xmm5 = list(init16)
    it = []
    for k in range(1, 9):
        Mm = list(shuf)
        Mm[k - 1] = 0
        Mm[k + 7] = 0
        lo = sum(abs(xmm5[j] - Mm[j]) for j in range(0, 8))
        hi = sum(abs(xmm5[j] - Mm[j]) for j in range(8, 16))
        xmm5 = [(lo & 0xFF), (lo >> 8) & 0xFF, 0, 0, 0, 0, 0, 0,
                (hi & 0xFF), (hi >> 8) & 0xFF, 0, 0, 0, 0, 0, 0]
        it.append((lo << 16) | hi)
    # 内存序：第 k 轮值存于 mem[8-k]（与程序里 cmp 0x7da8+(si-1)*4 一致）
    return it[::-1], shuf


def _build_mbr(init16, body, imm=0x1E, mask_addr=_MASK_ADDR, exp_addr=_EXP_ADDR):
    """按程序语义造一个可被 extract/solve 识别的合成 MBR。"""
    exp, _shuf = _exp_from(init16, body, imm)
    data = bytearray(512)
    data[0:16] = init16
    o = 0x20
    data[o:o + 5] = bytes([0x0F, 0x54, 0x94]) + struct.pack("<H", mask_addr)  # andps
    o += 5
    data[o:o + 8] = bytes([0x66, 0x67, 0x3B, 0xBA]) + struct.pack("<I", exp_addr)  # cmp
    o += 8
    data[o:o + 5] = bytes([0x66, 0x0F, 0x70, 0xC0, imm])   # pshufd
    o += 5
    data[o:o + 4] = bytes([0x66, 0x0F, 0xF6, 0xEA])        # psadbw
    # 掩码表：mask_addr..+23 全 0xff，仅 +8 / +16 为 0x00
    mo = mask_addr - M.MBR_BASE
    for i in range(24):
        data[mo + i] = 0xFF
    data[mo + 8] = 0x00
    data[mo + 16] = 0x00
    eo = exp_addr - M.MBR_BASE
    for j, v in enumerate(exp):
        struct.pack_into("<I", data, eo + 4 * j, v)
    data[510:512] = b"\x55\xaa"
    return bytes(data)


def _synth(seed):
    import random
    rnd = random.Random(seed)
    init16 = bytes(rnd.randrange(0, 256) for _ in range(16))
    body = bytes(rnd.randrange(0x21, 0x7F) for _ in range(16))
    return init16, body


def _printable(b: bytes) -> bool:
    return all(0x20 <= x <= 0x7E for x in b)


def _all_preimages(mbr):
    """枚举能重建期望表的**全部** 16 字节 body（测试用，独立于 solve 的择优逻辑）。

    SAD 非单射 —— 某些实例存在多个前像；本函数直接列出交叉积，供测试判定歧义。
    """
    init, exp, imm, _ma, _ea = M.extract(mbr)
    loT = [exp[8 - k] >> 16 for k in range(1, 9)]
    hiT = [exp[8 - k] & 0xFFFF for k in range(1, 9)]
    Hs = M._solve_half(list(init[0:8]), loT)
    Ls = M._solve_half(list(init[8:16]), hiT)
    inv = M._pshufd_inverse(imm)
    out = []
    for h in Hs:
        for l in Ls:
            shuf = bytes(h) + bytes(l)
            src = [None] * 4
            for i, s in enumerate(inv):
                src[s] = shuf[4 * i:4 * i + 4]
            out.append(b"".join(src))
    return out


# -------------------------------------------------------------------- 探测器
def test_detector_rejects_non_mbr():
    assert M.is_mbr_sse_verify(b"") is False
    assert M.is_mbr_sse_verify(b"\x55\xaa") is False
    assert M.is_mbr_sse_verify(b"A" * 512) is False
    # 512B 但无引导签名
    assert M.is_mbr_sse_verify(b"\x0f\x54" + b"\x00" * 508 + b"\x00\x00") is False
    # 512B 有签名但缺 SSE 三件套
    d = bytearray(512)
    d[510:512] = b"\x55\xaa"
    assert M.is_mbr_sse_verify(bytes(d)) is False


def test_detector_accepts_synthetic():
    init16, body = _synth(1)
    assert M.is_mbr_sse_verify(_build_mbr(init16, body)) is True


# -------------------------------------------------------------------- 提取
@_need_real
def test_extract_anchors():
    data = _REAL_BIN.read_bytes()
    init16, exp, imm, mask_addr, exp_addr = M.extract(data)
    assert init16 == data[0:16]
    assert imm == 0x1E
    assert mask_addr == _MASK_ADDR
    assert exp_addr == _EXP_ADDR
    assert len(exp) == 8
    # edi=(lo<<16)|hi → 高 16 位 lo、低 16 位 hi
    assert exp[7] >> 16 == 735 and (exp[7] & 0xFFFF) == 655


def test_extract_returns_none_on_plain_binary():
    assert M.extract(bytes(512)) is None


# -------------------------------------------------------------------- 求解器
def test_synthetic_roundtrip():
    """种子 0..7 的合成实例均由扫描确认为**唯一解** → 必须逐字还原。"""
    for seed in range(8):
        init16, body = _synth(seed)
        mbr = _build_mbr(init16, body)
        got = M.solve(mbr)
        assert got is not None, f"seed={seed} 解不出"
        assert got == b"flag" + body, f"seed={seed} 还原错误: {got!r}"
        # 健全性：仿真复核
        assert M.simulate(mbr, got) is True


def test_synthetic_ambiguous_returns_none():
    """SAD 非单射：seed=10 存在**两个都可打印**的前像 → solve 必须诚实返回 None。

    并用正向仿真证明两个不同 body 都能重建期望表（歧义为真，非求解器缺陷）。
    """
    init16, body = _synth(10)
    mbr = _build_mbr(init16, body, imm=0x1E)
    pres = _all_preimages(mbr)
    printable = [p for p in pres if _printable(p)]
    assert len(printable) >= 2, f"前提失效：可打印前像数={len(printable)}"
    assert body in printable
    # 两个不同前像都必须通过完整仿真（证明歧义真实存在）
    distinct = {p for p in printable}
    assert len(distinct) >= 2
    for p in distinct:
        assert M.simulate(mbr, b"flag" + p) is True
    # 求解器无法在多个可打印前像间择优 → 必须 None（不猜）
    assert M.solve(mbr) is None


def test_synthetic_varies_pshufd_imm():
    """遍历合法 pshufd 置换；唯一实例须逐字还原，歧义实例须诚实 None。"""
    valid = (0x1B, 0x1E, 0x4E, 0x93, 0x39, 0xE4)
    solved = 0
    for imm in valid:
        perm = [(imm >> (2 * i)) & 3 for i in range(4)]
        assert sorted(perm) == [0, 1, 2, 3], f"{imm:#x} 非置换"
        init16, body = _synth(imm)
        mbr = _build_mbr(init16, body, imm=imm)
        got = M.solve(mbr)
        if got is None:
            printable = [p for p in _all_preimages(mbr) if _printable(p)]
            assert len(printable) != 1, f"imm={imm:#x} 可唯一确定却返回 None"
            continue
        assert got == b"flag" + body, f"imm={imm:#x} 还原错误: {got!r}"
        assert M.simulate(mbr, got) is True
        solved += 1
    assert solved >= 4, f"仅 {solved}/6 个合法置换成功，疑似实现回退"


def test_solve_rejects_non_permutation_pshufd():
    """pshufd 立即数非置换（源 dword 有重复）→ 不可逆 → None。"""
    init16, body = _synth(3)
    mbr = _build_mbr(init16, body, imm=0x00)      # dst=[0,0,0,0]
    assert M.solve(mbr) is None


# ---------------------------------------------------------------------- 真题
@_need_real
def test_real_flag_sha256_lock():
    flag = M.solve(_REAL_BIN.read_bytes())
    assert flag is not None
    assert hashlib.sha256(flag).hexdigest() == _REAL_SHA
    assert flag[:4] == b"flag" and flag.endswith(b"}")


@_need_real
def test_real_simulate_accepts():
    data = _REAL_BIN.read_bytes()
    assert M.simulate(data, M.solve(data)) is True
    assert M.simulate(data, b"flag{" + b"0" * 14 + b"}") is False


# ---------------------------------------------------------------------- run
@_need_real
def test_run_path_and_raw_forms():
    flag = M.solve(_REAL_BIN.read_bytes())
    assert M.run({"path": str(_REAL_BIN)}) == flag
    assert M.run({"raw": _REAL_BIN.read_bytes()}) == flag
    assert M.run("bad-params") is None
    assert M.run({"raw": b"not an mbr"}) is None


# ------------------------------------------------------------ 零假阳性
@_need_real
def test_zero_false_positive_across_ext_attachments():
    hits = []
    for p in (_POOL_DIR / "_attachments").rglob("*"):
        if not p.is_file() or p.stat().st_size > 64 * 1024 * 1024:
            continue
        if M.is_mbr_sse_verify(p.read_bytes()):
            hits.append(p)
    assert hits == [_REAL_BIN], f"假阳性: {hits}"


# ------------------------------------------------------------- presolve 接线
def test_presolve_wiring_present():
    from core import presolve as P
    assert "skills.mbr_sse_verify" in P.wired_skill_modules()
    src = (_ROOT / "core" / "presolve.py").read_text(encoding="utf-8")
    assert "asyncio.ensure_future(_try_mbr_sse_verify(question))" in src
    assert hasattr(P, "_try_mbr_sse_verify")


@_need_real
def test_presolve_handler_end_to_end():
    import asyncio
    from core import presolve as P
    from eval.cases import load_questions
    qs = [q for q in load_questions(str(_POOL_DIR)) if q.id == _REAL_QID]
    if not qs:
        pytest.skip("题面缺失")
    got = asyncio.run(P._try_mbr_sse_verify(qs[0]))
    assert got is not None
    assert hashlib.sha256(got.encode()).hexdigest() == _REAL_SHA


@_need_real
def test_full_presolve_hits_without_answers():
    """本题附件无 ASCII flag 候选噪声 → 多候选守卫不拦，无答案表也命中。"""
    import asyncio
    from core import presolve as P
    from eval.cases import load_questions
    qs = [q for q in load_questions(str(_POOL_DIR)) if q.id == _REAL_QID]
    if not qs:
        pytest.skip("题面缺失")
    assert P._attachment_multi_candidate(qs[0]) is False
    got = asyncio.run(P.presolve(qs[0]))
    assert got is not None
    assert hashlib.sha256(got.encode()).hexdigest() == _REAL_SHA


# ---------------------------------------------------------------------- 变异
def test_mutation_pshufd_identity_breaks_flag(monkeypatch):
    """把 pshufd 逆置换强行改为恒等 → 合成还原出的 flag 必错。"""
    init16, body = _synth(7)
    mbr = _build_mbr(init16, body)
    assert M.solve(mbr) == b"flag" + body
    monkeypatch.setattr(M, "_pshufd_inverse", lambda imm: [0, 1, 2, 3])
    got = M.solve(mbr)
    assert got != b"flag" + body


def test_mutation_rotated_target_order_breaks():
    """把期望表轮转 1 位（目标错位）→ 解不出原 flag。

    注意：不能简单 `exp[::-1]`——solve() 内部本就按 exp[8-k] 取用，
    反转会被内部反转抵消，故用轮转。
    """
    init16, body = _synth(11)
    mbr = _build_mbr(init16, body)
    real = M.extract

    def broken(data):
        init, exp, imm, ma, ea = real(data)
        return init, exp[1:] + exp[:1], imm, ma, ea

    M.extract, saved = broken, M.extract
    try:
        got = M.solve(mbr)
    finally:
        M.extract = saved
    assert got != b"flag" + body


@_need_real
def test_mutation_corrupt_mask_table_returns_none():
    """破坏掩码表（不再是逐轮移位单字节清零）→ 守卫拒绝 → None。"""
    data = bytearray(_REAL_BIN.read_bytes())
    mo = _MASK_ADDR - M.MBR_BASE
    data[mo + 8] = 0xFF          # 取消一个必须为 0 的位
    assert M.solve(bytes(data)) is None


@_need_real
def test_mutation_break_detector_too_loose(monkeypatch):
    """放宽探测器（任意 512B 都算）→ 全池出现假阳性。

    ⚠️ 需要真实附件：它遍历 _POOL_DIR/_attachments 找 512B 的文件，而该目录被
    .gitignore 排除 ⇒ CI 上不存在 ⇒ hits 恒为 0，`assert hits == 1` 必红。
    本文件其余依赖真题的用例都已挂 @_need_real，本条此前漏挂。
    """
    hits = 0
    for p in (_POOL_DIR / "_attachments").rglob("*"):
        if p.is_file() and p.stat().st_size == 512:
            hits += 1
    assert hits == 1                      # 破坏前恒为 1
    monkeypatch.setattr(M, "is_mbr_sse_verify", lambda d: len(d) == 512)
    hits2 = 0
    for p in (_POOL_DIR / "_attachments").rglob("*"):
        if p.is_file() and M.is_mbr_sse_verify(p.read_bytes()):
            hits2 += 1
    assert hits2 == 1
