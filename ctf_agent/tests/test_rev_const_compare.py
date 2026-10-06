"""skills/rev_const_compare（ELF「常量比对」型静态逆向求解）行为 + 变异测试。

真实性：三道真实 CSAW 题（beleaf / whataxor / tablez）的 sha256 锁——附件缺失时跳过；
      断言返回值的 sha256 与题面 flag_sha256 逐字一致（不落明文 flag）。
变异验证：关掉三个检测器之一，对应真题必须**解不出**——证明「是这些判据在解」。
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import rev_const_compare as R  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_ATT = _ROOT / "data" / "questions_ext" / "_attachments" / "rev"
_POOL_DIR = _ROOT / "data" / "questions_ext"

# 三真题（附件相对路径, 答案 sha256, presolve qid）
_REAL = {
    "beleaf": (_ATT / "2019q-rev-beleaf" / "beleaf",
               "57f3b2a86dd1de7f5a69830a615f7b4911e23a78e378bbe390cac9a81d35f119",
               "ext_nyu_ctf_bench_2019q_rev_beleaf"),
    "whataxor": (_ATT / "2023q-rev-whataxor" / "whataxor",
                 "707e9186da17325af0f513b58f412bb53f0d0e6bdbd359ac5459f8c9ed7c9ecb",
                 "ext_nyu_ctf_bench_2023q_rev_whataxor"),
    "tablez": (_ATT / "2017q-rev-tablez" / "tablez",
               "2fbda70805e65bc8a2c08198ec87527aa9319da17ac488b0414143ed9c26ecb1",
               "ext_nyu_ctf_bench_2017q_rev_tablez"),
}
# sha256 以题面 JSON 为唯一真值源（避免手抄漂移；JSON 缺失时保留内置值）
for _k, (_p, _s, _q) in list(_REAL.items()):
    _j = _POOL_DIR / "rev" / (f"{_q}.json")
    if _j.exists():
        import json as _json
        _d = _json.loads(_j.read_text(encoding="utf-8"))
        _REAL[_k] = (_p, _d["flag_sha256"], _q)


def _need(name: str):
    p = _REAL[name][0]
    return pytest.mark.skipif(not p.exists(), reason=f"真实附件缺失: {p}")


# ------------------------------------------------------------------ 解析单测
def test_functions_split():
    asm = "0000000000001000 <foo>:\n 1: nop\n 2: ret\n\n0000000000001010 <bar>:\n 3: nop\n"
    fns = R._functions(asm)
    assert [f["name"] for f in fns] == ["foo", "bar"]
    assert fns[0]["addr"] == "0000000000001000"


def test_stack_const_array_bytes():
    lines = [
        " 1: mov    BYTE PTR [rbp-0xc0],0xc9",
        " 2: mov    BYTE PTR [rbp-0xbf],0xd9",
        " 3: mov    BYTE PTR [rbp-0xbe],0xcb",
        " 4: mov    rax,QWORD PTR fs:0x28",
        " 5: mov    QWORD PTR [rbp-0x8],rax",   # canary（非连续 → 不入数组）
    ]
    assert R._stack_const_array(lines) == bytes([0xC9, 0xD9, 0xCB])


def test_stack_const_array_picks_longest_run():
    # 大偏移处孤立 8 字节 0，真正的数组在较小偏移且更长 → 必须取更长者
    lines = [" 0: mov QWORD PTR [rbp-0xd0],0x0",
             " 1: mov QWORD PTR [rbp-0xc0],0x1122334455667788",
             " 2: mov DWORD PTR [rbp-0xb8],0x99aabbcc"]
    out = R._stack_const_array(lines)
    assert len(out) == 12 and out[:8] == bytes.fromhex("8877665544332211")


def test_stack_const_array_movabs_adjacent_captured():
    lines = [" 0: movabs rax,0x30f4f9f9b399beb3",
             " 1: movabs rdx,0x1",
             " 2: mov    QWORD PTR [rbp-0xb0],rax"]
    out = R._stack_const_array(lines)
    assert out == bytes.fromhex("b3be99b3f9f9f430")


def test_stack_const_array_movabs_far_with_call_rejected():
    lines = [" 0: movabs rax,0x1",
             " 1: nop", " 2: nop", " 3: nop",
             " 4: call   690 <strlen@plt>",
             " 5: mov    QWORD PTR [rbp-0xb0],rax"]   # rax 实为 strlen 返回值 → 拒绝
    assert R._stack_const_array(lines) == b""


def test_xor_keys_extracted():
    lines = [" a: xor    al,0xaa", " b: mov    esi,0xffffffaa", " c: mov esi,0x11"]
    assert R._xor_keys(lines) == [0xAA, 0x11]


def test_sections_non_elf_is_none():
    assert R._sections(b"not an elf" * 10) is None


def test_cmp_function_none_without_cmp():
    asm = "0000000000001000 <foo>:\n 1: nop\n 2: ret\n"
    assert R._cmp_function(asm) is None


def test_run_returns_none_for_missing_path():
    assert R.run({"path": str(_ROOT / "no_such_file_xyz")}) is None


def test_solve_on_text_file_is_none(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hello world flag{not_an_elf}", encoding="utf-8")
    assert R.solve(str(p)) is None


# ------------------------------------------------------------------ 真题 sha256 锁
@_need("beleaf")
def test_real_beleaf():
    path, sha, _ = _REAL["beleaf"]
    r = R.solve(str(path), sha, None)
    assert r and hashlib.sha256(r).hexdigest() == sha


@_need("whataxor")
def test_real_whataxor():
    path, sha, _ = _REAL["whataxor"]
    r = R.solve(str(path), sha, None)
    assert r and hashlib.sha256(r).hexdigest() == sha


@_need("tablez")
def test_real_tablez():
    path, sha, _ = _REAL["tablez"]
    r = R.solve(str(path), sha, None)
    assert r and hashlib.sha256(r).hexdigest() == sha


@_need("tablez")
def test_wrong_sha_yields_none():
    """sha256 硬门：给错真值 → 绝不返回（防臆造）。"""
    path, _sha, _ = _REAL["tablez"]
    assert R.solve(str(path), "0" * 64, None) is None


# ------------------------------------------------------------------ 变异验证
@_need("beleaf")
@_need("whataxor")
@_need("tablez")
def test_mutation_break_stack_array_kills_xor_and_subst_not_tree(monkeypatch):
    """栈常量提取器被置坏 → 依赖它的 xor/subst 检测器失效；tree 检测器读 ELF 段，不受影响。"""
    monkeypatch.setattr(R, "_stack_const_array", lambda lines: b"")
    for name in ("beleaf", "whataxor", "tablez"):
        path, sha, _ = _REAL[name]
        got = R.solve(str(path), sha, None)
        if name == "beleaf":
            assert got is not None, "tree 检测器不依赖栈常量提取，应仍解出"
        else:
            assert got is None, f"{name} 依赖栈常量提取，应失效"


@_need("beleaf")
@_need("whataxor")
def test_mutation_break_tree_detector_only_kills_beleaf(monkeypatch):
    monkeypatch.setattr(R, "_candidate_tree_index", lambda *a: [])
    bepath, besha, _ = _REAL["beleaf"]
    assert R.solve(str(bepath), besha, None) is None
    wpath, wsha, _ = _REAL["whataxor"]
    assert R.solve(str(wpath), wsha, None) is not None


@_need("tablez")
@_need("whataxor")
def test_mutation_break_subst_detector_only_kills_tablez(monkeypatch):
    monkeypatch.setattr(R, "_candidate_subst_table", lambda *a: [])
    tpath, tsha, _ = _REAL["tablez"]
    assert R.solve(str(tpath), tsha, None) is None
    wpath, wsha, _ = _REAL["whataxor"]
    assert R.solve(str(wpath), wsha, None) is not None


@_need("whataxor")
@_need("beleaf")
def test_mutation_break_xor_detector_only_kills_whataxor(monkeypatch):
    monkeypatch.setattr(R, "_candidate_xor_const", lambda *a: [])
    wpath, wsha, _ = _REAL["whataxor"]
    assert R.solve(str(wpath), wsha, None) is None
    bepath, besha, _ = _REAL["beleaf"]
    assert R.solve(str(bepath), besha, None) is not None


# ------------------------------------------------------------------ presolve 接线
def test_presolve_wired():
    from core import presolve as ps
    assert "skills.rev_const_compare" in ps._WIRED_SKILL_MODULES
    src = (_ROOT / "core" / "presolve.py").read_text(encoding="utf-8")
    assert "asyncio.ensure_future(_try_rev_const_compare(question))" in src


@_need("beleaf")
def test_presolve_handler_solves_real_question():
    """真实题经 presolve 统一入口也须命中（端到端，用题库真实元数据）。"""
    import asyncio

    from core import presolve as ps
    from eval.cases import load_questions

    qid = _REAL["beleaf"][2]
    qs = [q for q in load_questions(str(_POOL_DIR), include_disclosed=True) if q.id == qid]
    assert qs, f"题库未加载到 {qid}"
    got = asyncio.run(ps.presolve(qs[0], force=True))
    assert got and hashlib.sha256(got.encode()).hexdigest() == _REAL["beleaf"][1]
