# -*- coding: utf-8 -*-
"""misc_deflate_huffman_flag 求解器回归（2026-10-13）。

覆盖
----
1. 真实题 challenge.zip 解出，sha256 与题库 `flag_sha256` 逐字匹配
   （真值从题目对象读，**不硬编码**）；
2. 合成端到端：自建 ZIP——每条目是一条**手工构造的动态 Huffman
   deflate 流**（8 位等长满树，符号 69 的码 = flag 字符的 8 位逆序），
   文本用非 E 符号（守卫①的合法形态）——证明求解器不依赖真题特例；
3. 负例：非 ZIP / 条目 <4 / 普通含 E 文本 / E-less 但无隐码 / 含
   stored 条目 / 超 32MB → 一律 None，不崩不谎报；
4. 单测：规范码构造（RFC 1951 §3.2.2 算例）、位读取、动态块头解析、
   ZIP 中央目录权威性；
5. 生产约束：skill 纯标准库（AST 扫描）；打桩屏蔽三方 import 后仍可
   解出真題（生产子进程是 spawn，任何解释器下须可跑）；
6. 反捷径：skill 源码**不得含 flag 明文或 sha256**（防"查表短路"）；
7. 双守卫接线验证（不是摆设）：lipogram 守卫（E 丰富文本必须拒，
   放开阈值后必须解出）+ E 码长守卫（阈值压到 4 位后真题必须拒）；
   变异：`_reverse8` 变恒等 → 真题必须解不出。
"""

from __future__ import annotations

import ast  # noqa: E402
import builtins  # noqa: E402
import hashlib  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import struct  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
import zipfile  # noqa: E402
import zlib  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import misc_deflate_huffman_flag as M  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_QDIR = _ROOT / "data" / "questions_external" / "misc" / "ext_gctf2021_david-and-the-tree"
_ATT = _QDIR / "_attachments" / "challenge.zip"
_QJSON = _QDIR.parent / "ext_gctf2021_david-and-the-tree.json"

# 从题库读真值（缺文件则 skip；gitignore 不入库）
_TRUTH_SHA = ""
if _QJSON.is_file():
    try:
        _TRUTH_SHA = str(json.loads(_QJSON.read_text(encoding="utf-8"))
                         .get("flag_sha256") or "")
    except Exception:  # noqa: BLE001
        _TRUTH_SHA = ""

needs_question = pytest.mark.skipif(
    not (_ATT.is_file() and _TRUTH_SHA),
    reason="外部题库 david-and-the-tree 未落地（gitignore）")


# ─────────────────────────── 合成夹具构造器 ───────────────────────────
#
# 手工发射一条 deflate 动态 Huffman 流：
#   · litlen 码树 = L7 个 7 位码 + L8 个 8 位码（Kraft 恰为 1 的满树），
#     使符号 69（'E'）的规范码恰好等于目标值 X；
#   · 数据符号取 text_symbols（非 E 符号，保住 lipogram 守卫的合法形态）；
#   · 距离树用 RFC 1951 允许的"单码长 1"特例。
# 提取端（被测 skill）解析同一语法，取符号 69 的码 → &0xFF → 8 位逆序
# → ASCII，与发射端互逆。

_CL_FIXED = {0: 1, 1: 2, 7: 3, 8: 4, 17: 5, 18: 5}  # 码长码固定树（满码）


class _BitWriter:
    """DEFLATE 位流发射器：字段 LSB first，Huffman 码 MSB first。"""

    def __init__(self):
        self.acc = 0
        self.n = 0

    def write(self, value: int, width: int) -> None:
        for i in range(width):
            self.acc |= ((value >> i) & 1) << self.n
            self.n += 1

    def write_code(self, value: int, width: int) -> None:
        for i in range(width - 1, -1, -1):
            self.acc |= ((value >> i) & 1) << self.n
            self.n += 1

    def bytes(self) -> bytes:
        return self.acc.to_bytes((self.n + 7) // 8, "little")


def _rle_lengths(lengths):
    """码长序列 → CL 符号流 [(sym, extra, extra_bits)]（不用 16 复刻）。"""
    out = []
    i, n = 0, len(lengths)
    while i < n:
        if lengths[i] == 0:
            j = i
            while j < n and lengths[j] == 0:
                j += 1
            run = j - i
            while run >= 11:
                take = min(138, run)
                out.append((18, take - 11, 7))
                run -= take
            while run >= 3:
                take = min(10, run)
                out.append((17, take - 3, 3))
                run -= take
            out.extend((0, 0, 0) for _ in range(run))
            i = j
        else:
            out.append((lengths[i], 0, 0))
            i += 1
    return out


def _litlen_lengths(target_code: int, data_symbols=(70, 71, 72)):
    """构造 litlen 码长表，使符号 69 的规范码 == target_code。

    结构：L7 个 7 位码 + L8 个 8 位码（Kraft 恰 1）。规范码
    code(69) = 2·L7 + N，其中 N = 69 之前的 8 位码个数（0..69）。
    取 N ≡ target (mod 2)（最小化），则 L7 = (X-N)/2、L8 = 256-2·L7。
    8 位码 = {69} ∪ data ∪ {EOB 256} ∪ N 个 69 之前的码 ∪ F 个 >69 的
    填充；F = L8-5-N = 251-X ≤ 183（索引 73..255 的可用槽位）
    → 可构造范围 X ∈ [68, 251]。
    """
    X = target_code
    if not (68 <= X <= 251):
        raise ValueError(f"target {X} out of constructible range [68,251]")
    N = X & 1
    L7 = (X - N) // 2
    L8 = 256 - 2 * L7
    before = set(range(60, 60 + N))
    used = {69} | set(data_symbols) | {256} | before
    fillers = []
    i = 73
    while len(fillers) < L8 - len(used):
        if i > 255:
            raise ValueError("filler exhausted")
        if i not in used:
            fillers.append(i)
        i += 1
    len8 = used | set(fillers)
    len7 = []
    i = 0
    while len(len7) < L7:
        if i > 256:
            raise ValueError("len7 exhausted")
        if i not in len8:
            len7.append(i)
        i += 1
    lengths = [0] * 257
    for s in len7:
        lengths[s] = 7
    for s in len8:
        lengths[s] = 8
    return lengths


def _make_deflate(flag_char: str, data_symbols=(70, 71, 72), reps: int = 20) -> bytes:
    """为单个 flag 字符发射一条带隐码的 deflate 流。"""
    X = M._reverse8(ord(flag_char))
    litlen = _litlen_lengths(X, data_symbols)
    codes = M._build_codes(litlen)
    cl_lengths = [0] * 19
    for sym, ln in _CL_FIXED.items():
        cl_lengths[sym] = ln
    cl_codes = M._build_codes(cl_lengths)
    bw = _BitWriter()
    bw.write(1, 1)    # BFINAL
    bw.write(2, 2)    # BTYPE=10 动态 Huffman
    bw.write(0, 5)    # HLIT=0 → 257 个 litlen 码
    bw.write(0, 5)    # HDIST=0 → 单距离码（RFC 1951 特例：长 1）
    bw.write(15, 4)   # HCLEN=15 → 19 个码长码
    for sym in M._CLCL_ORDER:
        bw.write(cl_lengths[sym], 3)
    for sym, extra, nbits in _rle_lengths(litlen + [1]):
        bw.write_code(cl_codes[sym], cl_lengths[sym])
        if nbits:
            bw.write(extra, nbits)
    for _ in range(reps):
        for s in data_symbols:
            bw.write_code(codes[s], litlen[s])
    bw.write_code(codes[256], litlen[256])   # EOB
    return bw.bytes()


def _make_zip(streams, names=None) -> bytes:
    """手工组装 ZIP（中央目录给权威 csz/方法/本地头偏移）。"""
    out = bytearray()
    offsets = []
    for i, ds in enumerate(streams):
        name = (names[i] if names else f"{i:02d}.txt").encode()
        offsets.append(len(out))
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0,
                           zlib.crc32(ds) & 0xFFFFFFFF, len(ds), 0,
                           len(name), 0)
        out += name + ds
    cd_start = len(out)
    for i, ds in enumerate(streams):
        name = (names[i] if names else f"{i:02d}.txt").encode()
        out += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 8, 0, 0,
                           zlib.crc32(ds) & 0xFFFFFFFF, len(ds), 0,
                           len(name), 0, 0, 0, 0, 0, offsets[i])
        out += name
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(streams),
                       len(streams), len(out) - cd_start, cd_start, 0)
    return bytes(out)


def _synth_flag():
    """合成 flag（每字符的 8 位逆序码须落在可构造范围 [68,251]）。"""
    return "SCF{aik-survz}"


def _synth_zip(flag=None, data_symbols=(70, 71, 72)):
    flag = flag or _synth_flag()
    return _make_zip([_make_deflate(c, data_symbols) for c in flag])


# ─────────────────────────── 1. 真实题 ───────────────────────────

@needs_question
def test_real_question_solves():
    res = M.run({"path": str(_ATT)})
    assert isinstance(res, dict)
    flag = res.get("flag")
    assert flag, "真实题未解出"
    assert hashlib.sha256(flag.encode()).hexdigest() == _TRUTH_SHA


@needs_question
def test_real_question_solve_entrypoint():
    """solve()（非 run 包装）同样解出——证明 flag 来自解析而非 IO 包装。"""
    flag = M.solve(_ATT.read_bytes())
    assert flag
    assert hashlib.sha256(flag.encode()).hexdigest() == _TRUTH_SHA


# ─────────────────────────── 2. 合成端到端 ───────────────────────────

def test_synthetic_roundtrip():
    """自建隐码流 → skill 原样还原（不依赖真题特例）。"""
    flag = _synth_flag()
    zbytes = _synth_zip(flag)
    assert M.solve(zbytes) == flag
    assert M.run({"path": _write_tmp(zbytes)}) == {"flag": flag}


def test_synthetic_e_rich_text_rejected_by_lipogram_guard():
    """文本含大量 E（数据符号含 69）→ lipogram 守卫必须拒。"""
    flag = _synth_flag()
    zbytes = _synth_zip(flag, data_symbols=(69, 70, 71))
    assert M.solve(zbytes) is None
    # 放开阈值后必须解出 → 证明正是该守卫在拦（不是别处巧合）
    orig = M._E_RATIO_MAX
    M._E_RATIO_MAX = 1.0
    try:
        assert M.solve(zbytes) == flag
    finally:
        M._E_RATIO_MAX = orig


# ─────────────────────────── 3. 负例 ───────────────────────────

def test_negative_not_a_zip():
    assert M.solve(b"hello world, definitely not a zip" * 10) is None
    assert M.run({"path": _write_tmp(b"\x00" * 512)})["flag"] is None


def test_negative_too_few_entries():
    zbytes = _synth_zip("SCF")  # < _MIN_ENTRIES(4)
    assert M.solve(zbytes) is None


def test_negative_normal_text_with_e():
    """普通英文文本（含大量 E）→ lipogram 守卫拒。"""
    texts = [("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG. " * 40)
             for _ in range(6)]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, t in enumerate(texts):
            zf.writestr(f"{i:02d}.txt", t)
    assert M.solve(buf.getvalue()) is None


def test_negative_lipogram_without_hidden_code():
    """E-less 文本但树里没有 69 的码（正常 zlib 压缩）→ 拒。"""
    texts = [("A QUICK BROWN FOX JUMPS OVER A LAZY DOG. " * 40).replace("E", "")
             for _ in range(6)]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, t in enumerate(texts):
            zf.writestr(f"{i:02d}.txt", t)
    assert M.solve(buf.getvalue()) is None


def test_negative_stored_entries():
    """含 stored 条目 → 拼装语义要求全 deflate，拒。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(4):
            zf.writestr(f"{i}.txt", "ABCD", zipfile.ZIP_STORED)
    assert M.solve(buf.getvalue()) is None


def test_negative_oversize(monkeypatch):
    """超 32MB → skill 自护栏拒（presolve 层另有 8MB 预检）。"""
    monkeypatch.setattr(M, "_MAX_ZIP_BYTES", 1024)
    big = b"PK\x03\x04" + b"\x00" * 2048
    assert M.solve(big) is None


# ─────────────────────────── 4. 单测 ───────────────────────────

def test_build_codes_rfc_examples():
    # 等长满树：码 = 符号序号
    assert M._build_codes([2, 2, 2, 2]) == [0, 1, 2, 3]
    # RFC 1951 §3.2.2 风格算例：[1,2,3,3] → 0, 10b, 110b, 111b
    assert M._build_codes([1, 2, 3, 3]) == [0, 0b10, 0b110, 0b111]
    # 256 个 8 位码：符号 69 的码就是 69
    codes = M._build_codes([8] * 256)
    assert codes[69] == 69
    assert codes[255] == 255


def test_reverse8():
    assert M._reverse8(0x01) == 0x80
    assert M._reverse8(0x80) == 0x01
    assert M._reverse8(0xC2) == 0x43
    assert M._reverse8(M._reverse8(0x5A)) == 0x5A


def test_bit_reader_lsb_first():
    br = M._BitReader(b"\x80\x01")
    assert br.read(1) == 0      # 0x80 的 LSB
    assert br.read(1) == 0
    assert br.read(1) == 0
    assert br.read(1) == 0
    assert br.read(1) == 0
    assert br.read(1) == 0
    assert br.read(1) == 0
    assert br.read(1) == 1      # 0x80 的 MSB
    assert br.read(8) == 0x01   # 下一字节


@needs_question
def test_parse_dynamic_litlen_on_real_stream():
    """真题每条流的 litlen 树都给符号 69 分配 ≤9 位码（题型定义性质）。"""
    entries = M._zip_deflate_streams(_ATT.read_bytes())
    assert entries and len(entries) == 26
    for name, ds in entries:
        br = M._BitReader(ds)
        assert br.read(1) in (0, 1)
        assert br.read(2) == 2  # 动态块
        lengths = M._parse_dynamic_litlen(br)
        assert len(lengths) >= 70
        assert 0 < lengths[69] <= 9, f"{name}: E 码长 {lengths[69]}"


@needs_question
def test_zip_streams_structure():
    entries = M._zip_deflate_streams(_ATT.read_bytes())
    assert entries is not None
    names = [n for n, _ in entries]
    assert names == [f"{i:02d}.txt" for i in range(26)]
    for _n, ds in entries:
        assert ds and len(ds) > 100


def test_zip_streams_rejects_corrupt():
    # 伪 EOCD：目录偏移越界
    assert M._zip_deflate_streams(b"PK\x03\x04" + b"\x00" * 40) is None


# ─────────────────────────── 5. 生产约束 ───────────────────────────

def test_no_third_party_imports_ast():
    """AST 级扫描：skill 只许用标准库（docstring 里的字面量不算）。"""
    src = (_ROOT / "skills" / "misc_deflate_huffman_flag.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    allowed = {"os", "re", "struct", "zlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, f"禁用的三方 import: {a.name}"
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, \
                f"禁用的三方 from-import: {node.module}"


def test_solves_with_third_party_imports_blocked(monkeypatch):
    """打桩屏蔽三方 import 后仍解出真題（生产子进程 spawn 无三方库）。"""
    real_import = builtins.__import__

    def guarded(name, *a, **k):
        root = name.split(".")[0]
        if root not in sys.stdlib_module_names and root not in ("skills", "core"):
            raise ImportError(f"blocked in test: {name}")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", guarded)
    if not _ATT.is_file():
        pytest.skip("外部题库未落地")
    res = M.run({"path": str(_ATT)})
    assert res.get("flag")
    assert hashlib.sha256(res["flag"].encode()).hexdigest() == _TRUTH_SHA


@needs_question
def test_no_flag_plaintext_in_source():
    """反捷径：skill 源码不得含 flag 明文 / 题库 sha256。

    必须挂 needs_question：真值缺失时 `_TRUTH_SHA` 是空串，而空串是**任何字符串
    的子串**，`"" not in src` 恒为 False —— 断言会变成「永远失败」，与它想守的
    「源码没有泄漏真值」毫无关系（2026-10-20 实测就是这么红的）。
    这里再加一道非空断言，防止以后有人把 skip 标记去掉又把空值放回来。
    """
    assert _TRUTH_SHA, "真值缺失时本断言无意义，应走 skip 而不是判红"
    src = (_ROOT / "skills" / "misc_deflate_huffman_flag.py").read_text(encoding="utf-8")
    assert "CTF{" not in src
    assert "OLE-E-COM" not in src
    assert _TRUTH_SHA not in src and "b05a30c3" not in src


# ─────────────────────────── 6. 守卫接线 + 变异 ───────────────────────────

@needs_question
def test_e_code_len_guard_is_wired():
    """E 码长守卫阈值压到 4 位 → 真题必须解不出（证明守卫真在承力）。"""
    real_ds = M._zip_deflate_streams(_ATT.read_bytes())[0][1]
    assert M._e_char_from_deflate(real_ds) is not None
    orig = M._E_CODE_LEN_MAX
    M._E_CODE_LEN_MAX = 4
    try:
        assert M._e_char_from_deflate(real_ds) is None
    finally:
        M._E_CODE_LEN_MAX = orig


def test_mutation_reverse8_identity_breaks_real():
    """变异：`_reverse8` 退化为恒等 → 合成题必须解不出。

    注意：夹具先建后打补丁——否则夹具发射端会跟着一起变异、
    自洽地绕过检测（被测与夹具共用该函数的必然风险，用构建顺序隔离）。
    """
    zbytes = _synth_zip()          # 先用正确 reverse8 建夹具
    orig = M._reverse8
    M._reverse8 = lambda v: v
    try:
        # 恒等变换后提出的是逆序码原值（多数字符 >0x7E）→ 可打印守卫必拒
        assert M.solve(zbytes) is None
    finally:
        M._reverse8 = orig
    # 还原后恢复
    assert M.solve(zbytes) == _synth_flag()


def test_mutation_extraction_always_succeeds_is_detectable():
    """变异：提取恒返回 'A' → 合成题必须解错（证明字符真来自树）。"""
    orig = M._e_char_from_deflate
    M._e_char_from_deflate = lambda ds: "A"
    try:
        got = M.solve(_synth_zip())
        assert got == "A" * len(_synth_flag())
        assert got != _synth_flag()
    finally:
        M._e_char_from_deflate = orig


# ─────────────────────────── 辅助 ───────────────────────────

def _write_tmp(data: bytes, name: str = "x.zip") -> str:
    fd, path = tempfile.mkstemp(suffix=name)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path
