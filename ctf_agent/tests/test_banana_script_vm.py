"""skills/banana_script（bananascript 编码解码 + 滚动异或还原）行为 + 变异测试。

真实性：真实 CSAW-Quals 2017 rev/bananaScript 的 sha256 锁——附件缺失时跳过；
       断言返回值的 sha256 与题面 flag_sha256 逐字一致（测试里不落明文 flag）。
合成：自建「store 常量」指令行，把 48 个词值用已知 8 字节密钥与目标 flag 反推，
       断言 solve_text 能逐字还原（证明是算法在解，不是硬编码常量）。
变异验证：破坏字符表 / crib / 单词判定后，合成与真题都必须**解不出**——证明
       「是这些判据在解」。
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import banana_script as B  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_POOL_DIR = _ROOT / "data" / "questions_ext"
_REAL_SCRIPT = (_POOL_DIR / "_attachments" / "rev" / "2017q-rev-bananascript"
                / "banana.script")
_REAL_BIN = (_POOL_DIR / "_attachments" / "rev" / "2017q-rev-bananascript"
             / "monkeyDo")
_REAL_QID = "ext_nyu_ctf_bench_2017q_rev_bananascript"
_REAL_SHA = "2819d24b75a686324e1d7222101999def0e6a99ffe3bde0e8ebf7388a128653f"
_j = _POOL_DIR / "rev" / f"{_REAL_QID}.json"
if _j.exists():  # sha256 以题面 JSON 为唯一真值源（避免手抄漂移）
    _REAL_SHA = json.loads(_j.read_text(encoding="utf-8"))["flag_sha256"]

_need_real = pytest.mark.skipif(not _REAL_SCRIPT.exists(),
                                reason=f"真题附件缺失: {_REAL_SCRIPT}")


# ------------------------------------------------------------------ 合成工具
def _build_script(flag: str, key) -> str:
    """把 flag 用 8 字节滚动密钥 k 反推成「store 常量」指令行（全 banana 词）。"""
    ct = [B.char_to_number(flag[i]) ^ key[i % 8] for i in range(len(flag))]
    words = [B.number_to_word(v) for v in ct]
    reg = B.number_to_word(8)   # 寄存器词 r0
    op = B.number_to_word(16)   # store 操作词
    return f"{reg} {op} " + " ".join(words) + "\n"


_SYN_BODY = ("synthetic_banana_vm_test_" * 2)[:42]
_SYN_FLAG = "flag{" + _SYN_BODY + "}"
_SYN_KEY = [11, 100, 127, 5, 86, 127, 127, 127]


# --------------------------------------------------------------- 字符表 / 词值
def test_alphabet_size_and_order_anchors():
    assert len(B.ALPHABET) == 96
    # 顺序锚点：词值 → 字符（来自二进制 FUN_00405d09 的初始化序列）
    assert B.number_to_char(127) == "a"
    assert B.number_to_char(122) == "f"
    assert B.number_to_char(101) == "A"
    assert B.number_to_char(75) == " "
    assert B.number_to_char(74) == "\n"
    assert B.number_to_char(73) == "0"
    assert B.number_to_char(40) == "{"
    assert B.number_to_char(39) == "}"
    assert B.number_to_char(32) == "<"


def test_alphabet_roundtrip_all_96():
    for idx, ch in enumerate(B.ALPHABET):
        n = 127 - idx
        assert B.number_to_char(n) == ch
        assert B.char_to_number(ch) == n


def test_number_to_char_undefined_raises():
    for n in (0, 31, 128, 200):
        with pytest.raises(KeyError):
            B.number_to_char(n)


def test_word_value_anchors():
    assert B.word_value("BANANAS") == 127
    assert B.word_value("Bananas") == 64
    assert B.word_value("bananas") == 0
    assert B.word_value("banANAS") == 15
    assert B.word_value("banAnas") == 8


def test_number_to_word_roundtrip():
    for n in range(128):
        w = B.number_to_word(n)
        assert len(w) == 7
        assert B.word_value(w) == n


def test_encode_decode_roundtrip():
    for s in ("Hello, World! 42", "flag{0r4ng3}", "a b c\nd", B.ALPHABET):
        assert B.decode(B.encode(s)) == s


def test_decode_illegal_token_is_placeholder():
    assert B.decode("BANANAS bbbbbbb") == "a" + "\ufffd"


# ------------------------------------------------------------------- 检测器
@_need_real
def test_is_banana_script_real_positive():
    assert B.is_banana_script(_REAL_SCRIPT.read_bytes()) is True


def test_is_banana_script_negatives():
    assert B.is_banana_script(b"") is False
    assert B.is_banana_script("hello world this is plain english text " * 3) is False
    # 词形不对（结尾不是 s）
    assert B.is_banana_script("banana " * 40) is False
    # 二进制魔数开头
    assert B.is_banana_script(b"\x7fELF" + b"\x00" * 4096) is False
    # 单词数不足
    assert B.is_banana_script("BANANAS banAnas bananas") is False


# --------------------------------------------------------------- 求解（合成）
def test_recover_synthetic_roundtrip():
    script = _build_script(_SYN_FLAG, _SYN_KEY)
    assert len(_SYN_FLAG) == 48
    assert all(c in B.BODY_CHARS for c in _SYN_FLAG[5:-1])
    assert B.solve_text(script) == _SYN_FLAG


def test_recover_synthetic_another_key():
    flag = "flag{" + ("le3t_f0rm_c0n51st3ncy_ch3ck_42" + "_" * 14) + "}"
    flag = flag[:47] + "}"
    key = [1, 2, 3, 4, 5, 127, 127, 126]
    assert B.solve_text(_build_script(flag, key)) == flag


def test_solve_text_rejects_non_banana():
    assert B.solve_text("no bananas here at all") is None


def test_solve_text_rejects_short_const():
    # store 常量少于 16 词 → 不构成候选
    line = f"{B.number_to_word(8)} {B.number_to_word(16)} " + " ".join(
        B.number_to_word(127) for _ in range(8))
    assert B.solve_text(line) is None


def test_recover_requires_length_multiple_of_8():
    short = "flag{" + "x" * 26 + "}"      # 32 → 可
    assert len(short) == 32
    assert B.solve_text(_build_script(short, _SYN_KEY)) is not None
    odd = "flag{" + "x" * 26            # 31 → 非 8 倍数
    assert B.solve_text(_build_script(odd, _SYN_KEY)) is None


def test_run_path_and_raw_equivalence():
    script = _build_script(_SYN_FLAG, _SYN_KEY)
    assert B.run({"raw": script}) == _SYN_FLAG.encode()
    assert B.run({"raw": script.encode()}) == _SYN_FLAG.encode()
    assert B.run({"path": "/nonexistent/nope.script"}) is None
    assert B.run(None) is None
    assert B.run({"nothing": 1}) is None


# ------------------------------------------------------------------ 真题锁
@_need_real
def test_real_challenge_sha256_lock():
    out = B.solve(str(_REAL_SCRIPT))
    assert out is not None
    assert hashlib.sha256(out).hexdigest() == _REAL_SHA


@_need_real
def test_real_challenge_run_entry():
    assert B.run({"path": str(_REAL_SCRIPT)}) is not None


@_need_real
def test_real_binary_is_not_a_script():
    # monkeyDo 是 ELF，绝不能当脚本吃进去
    assert B.is_banana_script(_REAL_BIN.read_bytes()) is False
    assert B.solve(str(_REAL_BIN)) is None


@_need_real
def test_zero_false_positive_across_ext_attachments():
    """全池附件：只应有 banana.script 一个被判为脚本并解出。"""
    hits = []
    for p in _POOL_DIR.rglob("*"):
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > 4 * 1024 * 1024:
                continue
            if B.is_banana_script(p.read_bytes()):
                hits.append(p.name)
        except OSError:
            continue
    assert hits == ["banana.script"], f"意外命中: {hits}"


# ------------------------------------------------------------------ 变异验证
def test_mutation_word_bit_order_reversed(monkeypatch):
    """把 7 位词值读成 LSB 在前 → 真题不再解出原 flag。

    注：字符表本身是双射，反转它并不改变「crib 恒得 flag{」这一性质，故这里
    选择真正不对称的判据——词值的位序。
    """
    if not _REAL_SCRIPT.exists():
        pytest.skip("真题附件缺失")
    orig = B.word_value
    monkeypatch.setattr(
        B, "word_value",
        lambda w: int(bin(orig(w))[2:].zfill(7)[::-1], 2))
    out = B.solve(str(_REAL_SCRIPT))
    assert out is None or hashlib.sha256(out).hexdigest() != _REAL_SHA


def test_mutation_break_crib(monkeypatch):
    """把 crib 换成非法串 → 解不出。"""
    monkeypatch.setattr(B, "CRIB", "zzzz{")
    assert B.solve_text(_build_script(_SYN_FLAG, _SYN_KEY)) is None


def test_mutation_break_store_op_detection(monkeypatch):
    """清空 store 操作词集合 → 取不到候选常量 → 解不出。"""
    monkeypatch.setattr(B, "_STORE_OP_WORDS", frozenset())
    assert B.solve_text(_build_script(_SYN_FLAG, _SYN_KEY)) is None


def test_mutation_narrow_body_charset(monkeypatch):
    """把正文字符集收窄到纯 a-f → 约束变化，还原结果不再是注入 flag。"""
    script = _build_script(_SYN_FLAG, _SYN_KEY)
    monkeypatch.setattr(B, "BODY_CHARS", frozenset("abcdef"))
    assert B.solve_text(script) != _SYN_FLAG


def test_mutation_break_word_shape_detector(monkeypatch):
    """放宽单词判定（任何 7 字母都算）→ 非 banana 文本被误吃，抛出假阳性。"""
    text = "abcdefg hijklmn opqrstu " * 8   # 24 个 7 字母 token
    assert B.is_banana_script(text) is False        # 真判据：拒
    monkeypatch.setattr(B, "_WORD_RE", __import__("re").compile(r"^[a-z]{7}$"))
    assert B.is_banana_script(text) is True         # 判据被破坏 → 假阳性


@_need_real
def test_mutation_real_breaks_too(monkeypatch):
    monkeypatch.setattr(B, "ALPHABET", B.ALPHABET[::-1])
    assert B.solve(str(_REAL_SCRIPT)) is None


# ------------------------------------------------------------- presolve 接线
def test_presolve_wiring():
    from core import presolve as P
    assert "skills.banana_script" in P.wired_skill_modules()
    assert hasattr(P, "_try_banana_script")
    src = (Path(P.__file__)).read_text(encoding="utf-8")
    assert "asyncio.ensure_future(_try_banana_script(question))" in src


def test_presolve_handler_end_to_end():
    """直接调 handler：真题必须返回 sha256 吻合的 flag。"""
    if not _REAL_SCRIPT.exists():
        pytest.skip("真题附件缺失")
    import asyncio
    from core import presolve as P
    from eval.cases import load_questions
    qs = [q for q in load_questions("data/questions_ext") if q.id == _REAL_QID]
    if not qs:
        pytest.skip("题面 JSON 缺失")
    flag = asyncio.run(P._try_banana_script(qs[0]))
    assert flag is not None
    assert hashlib.sha256(flag.encode()).hexdigest() == _REAL_SHA


def test_presolve_handler_skips_non_reverse():
    import asyncio
    from core import presolve as P

    class _Q:
        id = "synthetic_non_reverse"
        category = "misc"
        attachments = []
        flag_sha256 = ""
        flag_pattern = ""

    assert asyncio.run(P._try_banana_script(_Q())) is None
