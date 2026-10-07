"""skills/rev_xor_verify（C++ 口令校验器 XOR+查表 反推）行为 + 变异测试。

真实性：真实 CSAW-Quals 2023 rev/rox 的 sha256 锁——附件缺失时跳过；
       断言返回值的 sha256 与题面 flag_sha256 逐字一致（测试里不落明文 flag）。
合成：自建 (key, data, expected) 一致三元组，把已知口令按程序语义反推成 expected，
       断言求解器能还原出**能重建 expected** 的口令（证明是算法在解，不是硬编码）。
性质：验证源码里 300× 嵌套循环恒为 no-op（XOR 计数相消）。
变异验证：破坏 key 段顺序 / 数据表 / 长度搜索 / 分支语义后，真题或合成必须**解不出**。
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import rev_xor_verify as R  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_POOL_DIR = _ROOT / "data" / "questions_ext"
_REAL_BIN = (_POOL_DIR / "_attachments" / "rev" / "2023q-rev-rox" / "food")
_REAL_QID = "ext_nyu_ctf_bench_2023q_rev_rox"
_j = _POOL_DIR / "rev" / f"{_REAL_QID}.json"
_REAL_SHA = None
if _j.exists():
    _REAL_SHA = json.loads(_j.read_text(encoding="utf-8")).get("flag_sha256")

_need_real = pytest.mark.skipif(
    not (_REAL_BIN.exists() and _REAL_SHA), reason=f"真题附件/题面缺失: {_REAL_BIN}")


# ------------------------------------------------------------------ 合成工具
def _reconstruct(key, data, pwd, L=None):
    """按程序语义正推 expected（part1 xor + part2 查表；part3 证为 no-op）。"""
    n = len(data)
    L = L or len(key)
    length = len(pwd)
    out = bytearray()
    for i in range(L):
        v = key[i] ^ (pwd[i] if i < length else 0)
        v ^= data[R._mod_like_program(pwd[i % length] + data[(i * 10 + 12) % n], n)] & 0xFF
        out.append(v & 0xFF)
    return bytes(out)


def _make_instance(length, seed):
    rnd = random.Random(seed)
    n = 500
    data = [rnd.randrange(0, 250) for _ in range(n)]
    key = bytes(rnd.randrange(1, 255) for _ in range(64))
    pwd = bytes(rnd.randrange(0x20, 0x7F) for _ in range(length))
    return key, data, pwd, _reconstruct(key, data, pwd)


# ------------------------------------------------------------------- KEY 提取
@_need_real
def test_scan_key_length_and_anchors():
    blob = _REAL_BIN.read_bytes()
    info = R._parse_elf(blob)
    _, t_off, t_size, _ = info["sections"][".text"]
    key = R._scan_key(blob[t_off:t_off + t_size])
    assert key is not None and len(key) == 74
    assert key[0] == 0x3F and key[1] == 0x42 and key[-1] == 0x34   # disp 次序锚点


@_need_real
def test_data_table_and_expected_anchors():
    blob = _REAL_BIN.read_bytes()
    info = R._parse_elf(blob)
    ro_addr, ro_off, ro_size, _ = info["sections"][".rodata"]
    data = R._find_data_table(blob[info["sections"][".text"][1]:
                                   info["sections"][".text"][1] + info["sections"][".text"][2]],
                              ro_addr, ro_off, ro_size, blob)
    assert data is not None and len(data) == 3497
    assert data[:3] == [60, 100, 88]
    exp = R._find_expected(blob[ro_off:ro_off + ro_size])
    assert exp.startswith(b"flag{") and exp.endswith(b"}") and len(exp) == 74


@_need_real
def test_extract_returns_triple():
    got = R.extract(str(_REAL_BIN))
    assert got is not None
    key, data, expected = got
    assert len(key) == 74 and len(data) == 3497 and len(expected) == 74


# --------------------------------------------------------------------- 求解器
def test_synthetic_solver_roundtrip():
    for length in (1, 3, 7, 16, 29):
        key, data, pwd, expected = _make_instance(length, seed=length)
        solved = R._solve_password(key, data, expected)
        assert solved is not None
        assert len(solved) == length
        # 关键判据：解出的口令能**重建** expected（而非要求等于原随机口令）
        assert _reconstruct(key, data, solved) == expected


def test_synthetic_min_length_is_chosen():
    """长度搜索取最小的可行 len（与程序里输入被 %len 复用一致）。"""
    key, data, pwd, expected = _make_instance(6, seed=99)
    solved = R._solve_password(key, data, expected)
    assert solved is not None and len(solved) == 6


# ----------------------------------------------------- no-op 性质（关键洞察）
def test_part3_loop_is_identity():
    for seed in range(4):
        rnd = random.Random(seed)
        L = 40
        v = bytearray(rnd.randrange(256) for _ in range(L))
        orig = bytes(v)
        for j in range(5, L):
            for d in range(0, 300):
                b = 1 if v[j - 5] == 0x6E else 0
                v[j] = (v[j] ^ ((d << 5) & 0xFF) ^ b) & 0xFF
        assert bytes(v) == orig


# --------------------------------------------------------------------- 真题
@_need_real
def test_real_flag_sha256_lock():
    flag = R.solve(str(_REAL_BIN))
    assert flag is not None
    assert hashlib.sha256(flag).hexdigest() == _REAL_SHA


@_need_real
def test_real_solve_without_expected_sha_returns_csawctf_wrapper():
    flag = R.solve(str(_REAL_BIN))
    assert flag.startswith(b"csawctf{") and flag.endswith(b"}")


def test_solve_with_wrong_expected_sha_returns_none():
    if not _REAL_BIN.exists():
        pytest.skip("真题附件缺失")
    assert R.solve(str(_REAL_BIN), expected_sha256="0" * 64) is None


# --------------------------------------------------------------------- run
@_need_real
def test_run_path_and_raw_forms():
    flag = R.solve(str(_REAL_BIN))
    assert R.run({"path": str(_REAL_BIN)}) == flag
    assert R.run({"path": str(_REAL_BIN), "expected_sha256": _REAL_SHA}) == flag
    raw = _REAL_BIN.read_bytes()
    assert R.run({"raw": raw, "expected_sha256": _REAL_SHA}) == flag
    assert R.run("bad-params") is None
    assert R.run({"raw": b"not an elf"}) is None


# ---------------------------------------------------- 探测器 + 零假阳性
def test_detector_rejects_non_elf():
    assert R.is_rev_xor_verify(b"") is False
    assert R.is_rev_xor_verify(b"hello world") is False
    assert R.is_rev_xor_verify(b"\x7fELF\x01") is False     # 32 位


@_need_real
def test_zero_false_positive_across_ext_attachments():
    hits = []
    for p in (_POOL_DIR / "_attachments").rglob("*"):
        if not p.is_file() or p.stat().st_size > 64 * 1024 * 1024:
            continue
        if R.is_rev_xor_verify(p.read_bytes()):
            hits.append(p)
    assert hits == [_REAL_BIN], f"假阳性: {hits}"


# --------------------------------------------------------------- presolve 接线
def test_presolve_wiring_present():
    from core import presolve as P
    assert "skills.rev_xor_verify" in P.wired_skill_modules()
    src = (_ROOT / "core" / "presolve.py").read_text(encoding="utf-8")
    assert "asyncio.ensure_future(_try_rev_xor_verify(question))" in src
    assert hasattr(P, "_try_rev_xor_verify")


@_need_real
def test_presolve_handler_end_to_end():
    import asyncio
    from core import presolve as P
    from eval.cases import load_questions
    qs = [q for q in load_questions(str(_POOL_DIR)) if q.id == _REAL_QID]
    if not qs:
        pytest.skip("题面缺失")
    got = asyncio.run(P._try_rev_xor_verify(qs[0]))
    assert got is not None
    assert hashlib.sha256(got.encode()).hexdigest() == _REAL_SHA


@_need_real
def test_full_presolve_hits_without_answers():
    """本题诱饵串含空格 → 严守 \\S 的候选模式不匹配 → 多候选守卫不拦，无答案表也命中。"""
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


# --------------------------------------------------------------------- 变异
@_need_real
def test_mutation_key_order_reversed(monkeypatch):
    """把 key 段按 disp 降序取 → key 反序 → 真题解不出。"""
    real = R._scan_key

    def broken(text):
        k = real(text)
        return k[::-1] if k else k

    monkeypatch.setattr(R, "_scan_key", broken)
    flag = R.solve(str(_REAL_BIN))
    assert flag is None or hashlib.sha256(flag).hexdigest() != _REAL_SHA


@_need_real
def test_mutation_data_table_rotated(monkeypatch):
    """数据表整体错位 1 → 查表错 → 真题解不出。"""
    real = R._find_data_table

    def broken(*a, **k):
        d = real(*a, **k)
        return d[1:] + d[:1] if d else d

    monkeypatch.setattr(R, "_find_data_table", broken)
    flag = R.solve(str(_REAL_BIN))
    assert flag is None or hashlib.sha256(flag).hexdigest() != _REAL_SHA


def test_mutation_solver_skips_length_one(monkeypatch):
    """长度搜索从 2 起 → 长度为 1 的合成实例解不出。"""
    key, data, pwd, expected = _make_instance(1, seed=1)

    def broken(key_, data_, expected_):
        n = len(data_)
        L = len(expected_)
        K = len(key_)
        for length in range(2, K + 1):          # 漏掉 len=1
            cands = [set(range(256)) for _ in range(length)]
            ok = True
            for i in range(L):
                b = i % length
                d1 = data_[(i * 10 + 12) % n]
                want = {a for a in range(256)
                        if (data_[R._mod_like_program(a + d1, n)] & 0xFF)
                        == (expected_[i] ^ key_[i] ^ (a if i < length else 0))}
                cands[b] &= want
                if not cands[b]:
                    ok = False
                    break
            if ok and all(cands):
                return bytes(min(c) for c in cands)
        return None

    monkeypatch.setattr(R, "_solve_password", broken)
    assert R._solve_password(key, data, expected) is None


def test_mutation_solver_ignores_len_branch(monkeypatch):
    """把「i<len 才 ^in[i]」的分支写成恒 ^in[i%len] → 合成实例解不出/重建失败。"""
    key, data, pwd, expected = _make_instance(5, seed=7)

    def broken(key_, data_, expected_):
        n = len(data_)
        L = len(expected_)
        K = len(key_)
        for length in range(1, K + 1):
            cands = [set(range(256)) for _ in range(length)]
            ok = True
            for i in range(L):
                b = i % length
                d1 = data_[(i * 10 + 12) % n]
                want = {a for a in range(256)
                        if (data_[R._mod_like_program(a + d1, n)] & 0xFF)
                        == (expected_[i] ^ key_[i] ^ a)}   # 恒 ^a（漏掉 i>=len 不加）
                cands[b] &= want
                if not cands[b]:
                    ok = False
                    break
            if ok and all(cands):
                return bytes(min(c) for c in cands)
        return None

    monkeypatch.setattr(R, "_solve_password", broken)
    solved = R._solve_password(key, data, expected)
    assert solved is None or _reconstruct(key, data, solved) != expected
