"""skills/emoji_binary（二进制 emoji 流解码）行为 + 变异测试。

真实性：真实 CSAW-Finals 2023 forensics/emoji 的 sha256 锁——附件缺失时跳过；
       断言返回值的 sha256 与题面 flag_sha256 逐字一致（测试里以 sha256 为准）。
合成：自建「emoji → bit」映射（8 符号 / 4 对）反推整段流，断言 decode 逐字还原
       （证明是算法在解，不是硬编码常量）。
变异验证：破坏位序 / 关掉候选择优 / 放宽探测器门槛后，必须「解不出或选错」
       ——证明「是这些判据在解」。
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import emoji_binary as E  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_POOL_DIR = _ROOT / "data" / "questions_ext"
_REAL_TXT = (_POOL_DIR / "_attachments" / "forensics" / "2023f-for-emoji"
             / "emoji.txt")
_REAL_PNG = (_POOL_DIR / "_attachments" / "forensics" / "2023f-for-emoji"
             / "emoji.png")
_REAL_QID = "ext_nyu_ctf_bench_2023f_for_emoji"
_REAL_FLAG = "csawctf{emoji_game_on_fleeeeeeeeeek}"
_j = _POOL_DIR / "forensics" / f"{_REAL_QID}.json"


def _read_real_sha() -> str | None:
    """读真题 sha256；题面 JSON 缺失时返回 None。

    ⚠️ 这里**不能**在模块级直接 json.loads(_j.read_text())：题面 JSON 属于
    gitignored 题库，CI 上不存在 ⇒ 导入期抛 FileNotFoundError ⇒ pytest 以
    **exit 2（收集期错误）** 整体崩掉 —— 把「附件缺失」放大成「全盘失败」，
    连不依赖真题的合成用例也一起陪葬。真实题断言另有 skipif 兜底。
    """
    if not _j.exists():
        return None
    try:
        return json.loads(_j.read_text(encoding="utf-8"))["flag_sha256"]
    except Exception:          # 坏 JSON / 缺字段
        return None


_REAL_SHA = _read_real_sha()

# 真题「附件 + 题面 JSON」都齐了才算可用（原先只判附件，漏了题面这一半）
_need_real = pytest.mark.skipif(
    not _REAL_TXT.exists() or _REAL_SHA is None,
    reason=f"真题附件/题面缺失: {_REAL_TXT}")


# ------------------------------------------------------------------ 合成工具
_SYNTH = ["🍎", "🍌", "🍇", "🍉", "🍓", "🍒", "🍑", "🥝"]  # 前 4 = bit0，后 4 = bit1


def _build_stream(text: str) -> str:
    """把 ASCII 文本编码成二进制 emoji 流（MSB 先，8 符号/字节）。"""
    bits = "".join(f"{b:08b}" for b in text.encode("ascii"))
    out = []
    for i, bit in enumerate(bits):
        base = 4 if bit == "1" else 0
        out.append(_SYNTH[base + (i % 4)])
    return "".join(out)


_SYN_FLAG = "flag{synthetic_emoji_binary_ok_1234}"


# --------------------------------------------------------------- 分词 / 判定
def test_tokenize_keeps_zwj_sequence_as_one_token():
    toks = E.tokenize("⚽️❤️\u200d🩹👍")
    assert len(toks) == 3
    assert toks[0] == "⚽\ufe0f"
    assert toks[1] == "❤\ufe0f\u200d🩹"


def test_identity_merges_variation_selector():
    assert E._identity("⚽\ufe0f") == E._identity("⚽")
    assert E._identity("❤\ufe0f\u200d🩹") == "❤\u200d🩹"


def test_is_emoji_token_anchors():
    assert E._is_emoji_token("🥩")
    assert E._is_emoji_token("➕")          # U+2795 是 Sm，仍属 emoji 型
    assert not E._is_emoji_token("a")
    assert not E._is_emoji_token("1")


@_need_real
def test_real_file_is_emoji_binary():
    assert _REAL_TXT.exists()
    assert E.is_emoji_binary(_REAL_TXT.read_text(encoding="utf-8"))


@_need_real
def test_real_png_is_not_emoji_binary():
    assert E.is_emoji_binary(_REAL_PNG.read_bytes()) is False


def test_plain_ascii_not_emoji_binary():
    assert E.is_emoji_binary("hello world this is not emoji") is False


def test_rejects_length_not_multiple_of_8():
    assert E.is_emoji_binary(_build_stream("abc")) is True   # 24 bit 合法
    stream = _build_stream("abcd")[:-1]                      # 32-1 = 31 bit
    assert E.is_emoji_binary(stream) is False
    assert E.decode(stream) is None


def test_rejects_too_few_distinct_symbols():
    # 16 个同符号（distinct=1 < 4）→ 非二进制流
    assert E.is_emoji_binary("🥩" * 16) is False


# ------------------------------------------------------------------ 求解逻辑
def test_rank_prefers_lowercase_prefix():
    good = _REAL_FLAG
    mixed = "cqavctF{Emgja_cale^oj_ble%eaee%eaej}"
    assert E._rank(good) > E._rank(mixed)


def test_synthetic_roundtrip():
    stream = _build_stream(_SYN_FLAG)
    assert E.is_emoji_binary(stream)
    assert E.decode(stream) == _SYN_FLAG


def test_synthetic_roundtrip_with_sha():
    stream = _build_stream(_SYN_FLAG)
    sha = hashlib.sha256(_SYN_FLAG.encode()).hexdigest()
    assert E.decode(stream, expected_sha256=sha) == _SYN_FLAG


def test_decode_returns_none_on_wrong_sha():
    stream = _build_stream(_SYN_FLAG)
    assert E.decode(stream, expected_sha256="0" * 64) is None


@_need_real
def test_solve_real_question_matches_sha256():
    flag = E.solve(str(_REAL_TXT))
    assert flag is not None
    assert hashlib.sha256(flag).hexdigest() == _REAL_SHA


@_need_real
def test_solve_real_question_with_expected_sha():
    flag = E.solve(str(_REAL_TXT), expected_sha256=_REAL_SHA)
    assert flag is not None
    assert flag.decode() == _REAL_FLAG


@_need_real
def test_zero_false_positive_across_ext_attachments():
    """全 ext 池附件：只有 emoji.txt 被判为二进制 emoji 流。"""
    hits = []
    for p in (_POOL_DIR / "_attachments").rglob("*"):
        if not p.is_file() or p.stat().st_size > 8 * 1024 * 1024:
            continue
        try:
            txt = p.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue
        if E.is_emoji_binary(txt):
            hits.append(p.name)
    assert hits == ["emoji.txt"], hits


def test_run_accepts_path_raw_and_expected():
    stream = _build_stream(_SYN_FLAG)
    assert E.run({"raw": stream}) == _SYN_FLAG.encode()
    assert E.run({"raw": stream.encode("utf-8")}) == _SYN_FLAG.encode()
    assert E.run({"raw": "not emoji"}) is None
    assert E.run("bad-params") is None
    if _REAL_TXT.exists():
        assert E.run({"path": str(_REAL_TXT)}) == _REAL_FLAG.encode()


# ------------------------------------------------------------- 变异验证
def test_mutation_bit_order_reversed(monkeypatch):
    """把字节内位序反转（MSB→LSB）→ 真题与合成都解不出。"""
    orig = E._search_bytes

    def _reversed_search(toks):
        res = []
        for raw in orig(toks):
            res.append(bytes(int(f"{b:08b}"[::-1], 2) for b in raw))
        return res

    monkeypatch.setattr(E, "_search_bytes", _reversed_search)
    assert E.decode(_build_stream(_SYN_FLAG)) != _SYN_FLAG
    if _REAL_TXT.exists():
        assert E.solve(str(_REAL_TXT)) != _REAL_FLAG.encode()


def test_mutation_rank_disabled(monkeypatch):
    """关掉候选择优（取第一个）→ 真题会选到以大写混排为前缀的错解。"""
    if not _REAL_TXT.exists():
        pytest.skip("真题附件缺失")
    toks = [t for t in E.tokenize(_REAL_TXT.read_text(encoding="utf-8"))
            if not t.isspace()]
    cands = []
    for raw in E._search_bytes(toks):
        s = raw.decode("ascii")
        if E._FLAG_RE.fullmatch(s):
            cands.append(s)
    assert len(cands) >= 2, "本题应至少有 2 个可打印候选，否则变异无意义"
    first = cands[0]
    monkeypatch.setattr(E, "decode", lambda text, expected_sha256=None: (
        first if E._FLAG_RE.fullmatch(first) else None))
    assert E.decode(_REAL_TXT.read_text(encoding="utf-8")) != _REAL_FLAG


def test_mutation_detector_too_loose(monkeypatch):
    """把「emoji 型 token」判据放宽为恒真 → 纯 ASCII 文本被误判为 emoji 流。"""
    ascii16 = "abcdefghijklmnop"     # 16 token、distinct=16，本应被拒
    assert E.is_emoji_binary(ascii16) is False
    monkeypatch.setattr(E, "_is_emoji_token", lambda tok: True)
    assert E.is_emoji_binary(ascii16) is True   # 破坏后假阳性


# ------------------------------------------------------------- presolve 接线
def test_presolve_wiring():
    from core import presolve as P
    assert "skills.emoji_binary" in P.wired_skill_modules()
    assert hasattr(P, "_try_emoji_binary")
    src = Path(P.__file__).read_text(encoding="utf-8")
    assert "asyncio.ensure_future(_try_emoji_binary(question))" in src


def test_presolve_handler_end_to_end():
    """直接调 handler：真题必须返回 sha256 吻合的 flag。"""
    if not _REAL_TXT.exists():
        pytest.skip("真题附件缺失")
    import asyncio
    from core import presolve as P
    from eval.cases import load_questions
    qs = [q for q in load_questions("data/questions_ext") if q.id == _REAL_QID]
    if not qs:
        pytest.skip("题面 JSON 缺失")
    flag = asyncio.run(P._try_emoji_binary(qs[0]))
    assert flag is not None
    assert hashlib.sha256(flag.encode()).hexdigest() == _REAL_SHA


def test_presolve_handler_no_attachment_returns_none():
    import asyncio
    from core import presolve as P

    class _Q:
        id = "synthetic_no_attach"
        category = "misc"
        attachments = []
        flag_sha256 = ""
        flag_pattern = ""

    assert asyncio.run(P._try_emoji_binary(_Q())) is None


def test_presolve_multi_candidate_guard_and_a_group_hit():
    """本题 emoji.png 含宽匹配噪声候选 → 无真值时守卫拦截；A 组（有答案表）命中。

    与 2017q_rev_bananascript 同类：no-answers 路径被 `_attachment_multi_candidate`
    正确跳过（宁漏不虚报），可解性依赖答案表 / run.py 路径。这是**诚实边界**，
    不是缺陷——守卫行为本身正确。
    """
    if not _REAL_TXT.exists():
        pytest.skip("真题附件缺失")
    import asyncio
    from core import presolve as P
    from eval.cases import load_questions, preset_answers
    qs = [q for q in load_questions("data/questions_ext") if q.id == _REAL_QID]
    if not qs:
        pytest.skip("题面 JSON 缺失")
    q = qs[0]
    assert P._attachment_multi_candidate(q) is True          # png 二进制宽匹配噪声
    # 无真值 → 全部嗅探被跳过（返回 None）
    assert asyncio.run(P.presolve(q, answers=None, force=True)) is None
    # 有真值（A 组口径）→ 命中，且 sha256 吻合
    flag = asyncio.run(P.presolve(q, answers=preset_answers(qs), force=True))
    assert flag is not None
    assert hashlib.sha256(flag.encode()).hexdigest() == _REAL_SHA
