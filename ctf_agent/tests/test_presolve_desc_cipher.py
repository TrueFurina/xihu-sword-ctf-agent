"""presolve「密文写在题面」覆盖（2026-10-15）。

防回归目标（每条都对应一个**实测踩过**的坑，不是凭空写的守卫）：

  ① 输入源盲区：`_try_fast_solve` 原先只把**附件正文**当输入，无附件时 s=""
     ⇒ 「密文在题面」端到端实测 **0/4**。改造后须 ≥3/4。
  ② 大小写污染：原实现先 `desc.lower()`。base64 大小写敏感，小写化后即便喂进
     解码器也解不出 —— 该用例专门用**含大写字母**的密文，能抓住此回归。
  ③ 候选提取形态：第一版正则 `[A-Za-z]{12,}` 抓不到 `snhr{jhlz4e_zo1ma_vr}`
     （含 {}_ 打断连续字母），点划连续型正则抓不到空格分隔的摩斯 ⇒ 两类都是 0 命中。
     用例直接断言「凯撒密文被抓到」「摩斯整段被抓到」。
  ④ 有界性：候选条数/单条长度必须有上限，否则长题面会拖垮 presolve。
  ⑤ 不虚报：题面无 flag 时不得返回任何东西；摩斯形态因码表无 `{}`、
     无法产出合规 `flag{...}` 外壳，**当前返回 None**（明确不留幻想，也防止
     将来有人靠"猜外壳"把 LAGMRSECDEOK 包装成假 flag 骗过闸门）。
"""

import asyncio
import base64
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core import presolve as P  # noqa: E402


# ── 构造样本 ──────────────────────────────────────────────────────────
def _b64n(s: str, n: int) -> str:
    b = s.encode()
    for _ in range(n):
        b = base64.b64encode(b)
    return b.decode()


def _caesar(s: str, k: int) -> str:
    out = []
    for ch in s:
        if ch.isalpha():
            base = ord("a") if ch.islower() else ord("A")
            out.append(chr((ord(ch) - base + k) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


_MORSE_T = {
    "f": "..-.", "l": ".-..", "a": ".-", "g": "--.", "t": "-", "e": ".",
    "s": "...", "m": "--", "o": "---", "r": ".-.", "c": "-.-.", "d": "-..",
}


def _morse(s: str) -> str:
    return " ".join(_MORSE_T.get(c, "") for c in s.lower())


FLAG_B64 = "flag{D3sc_b64_OK}"
# 凯撒样本**必须含大写**：lower() 污染会让密文大小写失真 ⇒ 解码结果对不上真值。
# 全小写样本对该回归是盲的（第一版就踩过：样本全小写 ⇒ 污染了也全绿）。
FLAG_CAE = "flag{D3sc_Caes4r_OK}"


def _q(qid="t1", cat="crypto", desc="", attachments=None):
    q = type("Q", (), {})()
    q.id = qid
    q.category = cat
    q.description = desc
    q.attachments = attachments or []
    q.flag_pattern = ""
    return q


def _run(coro):
    return asyncio.run(coro)


# ── ① + ②：端到端（题面密文，无附件）──────────────────────────────────
def test_b64_single_in_desc_is_solved():
    """单层 base64 写在题面（无附件）必须解出。"""
    desc = f"base64 编码串如下，解码得到 flag：\n{_b64n(FLAG_B64, 1)}"
    got = _run(P._try_fast_solve(_q("b1", "crypto", desc)))
    assert got and FLAG_B64 in str(got), f"题面单层 base64 未解出: {got!r}"


def test_b64_multilayer_in_desc_is_solved():
    """三层 base64 写在题面（无附件）必须解出。"""
    desc = f"以下密文经过多层 base64 编码，请解码：\n{_b64n(FLAG_B64, 3)}"
    got = _run(P._try_fast_solve(_q("b3", "crypto", desc)))
    assert got and FLAG_B64 in str(got), f"题面多层 base64 未解出: {got!r}"


def test_caesar_in_desc_is_solved():
    """凯撒密文写在题面必须解出。

    同时是 ②「大小写污染」的检测器：密文含大写字母，若实现把 lower() 后的
    文本喂给解码器，此处必失败。
    """
    ct = _caesar(FLAG_CAE, 7)
    assert any(c.isupper() for c in ct), "样本必须含大写字母，否则抓不到 lower 污染"
    desc = f"凯撒密码加密后的密文为：{ct}，求原文"
    got = _run(P._try_fast_solve(_q("c1", "crypto", desc)))
    assert got and FLAG_CAE in str(got), f"题面凯撒未解出（可能 lower 污染）: {got!r}"


def test_desc_candidates_preserve_case():
    """候选提取必须保留原始大小写（base64 大小写敏感的硬前提）。"""
    raw = "密文 ABCdefXYZ012+/= 请解码"
    cands = P._desc_cipher_candidates(raw)
    joined = " ".join(cands)
    assert any(c.isupper() for c in joined), f"候选丢失大写: {cands}"
    assert "ABCdefXYZ012+/=" in joined, f"候选未包含原始串: {cands}"


# ── ③：候选提取形态（两类都曾 0 命中）─────────────────────────────────
def test_candidate_extract_caesar_like_token():
    """形如 `snhr{jhlz4e_zo1ma_vr}`（含 {}_ 打断连续字母）必须被抓到。"""
    ct = _caesar(FLAG_CAE, 7)
    cands = P._desc_cipher_candidates(f"密文为：{ct}，求原文")
    assert cands, f"含括号下划线的密文 token 未被提取: {ct}"
    assert any(ct.strip() in c or c in ct for c in cands), f"提取片段不完整: {cands}"


def test_candidate_extract_morse_segment():
    """空格分隔的摩斯整段必须被抓到（第一版正则要求连续点划，实测 0 命中）。"""
    mc = _morse("flagtest")
    cands = P._desc_cipher_candidates(f"摩斯电码如下：{mc}")
    assert cands, f"摩斯整段未被提取: {mc!r}"
    assert any("." in c and "-" in c for c in cands), f"提取结果非摩斯: {cands}"


def test_candidate_extract_skips_short_noise():
    """过短 token 不得进候选（防噪声放大）。"""
    cands = P._desc_cipher_candidates("abc de fg 中文说明 x")
    assert all(len(c) >= P._DESC_CAND_MINLEN for c in cands), f"混入了过短片段: {cands}"


# ── ④：有界性 ─────────────────────────────────────────────────────────
def test_candidate_count_is_bounded():
    """候选条数必须有上限，长题面不得爆炸。

    ⚠️ 上界**硬编码**，不引用 `_DESC_CAND_MAX`：若断言写成
    `len(cands) <= P._DESC_CAND_MAX`，则把常量改大的变异会让断言跟着一起放宽
    ⇒ 恒绿、抓不到回归（2026-10-15 变异验证实测：该写法 M3 未被抓）。
    守卫必须站在被测常量之外。
    """
    big = " ".join(f"token{i:04d}abcdef" for i in range(500))
    cands = P._desc_cipher_candidates(big)
    assert len(cands) <= 64, f"候选数 {len(cands)} 爆炸（题面 500 token）"
    assert len(cands) < 500, f"候选数 {len(cands)} 未被截断"


def test_candidate_length_is_bounded():
    """单条候选必须截断（同为独立硬编码上界，理由见上）。"""
    long_tok = "A" * 10000
    cands = P._desc_cipher_candidates(long_tok)
    assert cands, "超长 token 被整个丢弃"
    assert all(len(c) <= 4096 for c in cands), f"单条未截断: {[len(c) for c in cands]}"


def test_worst_case_desc_is_fast():
    """最坏题面不得把 _try_fast_solve 拖成墙钟炸弹（实测 10ms 量级，阈值宽松）。"""
    import time
    desc = ("base64 解码：" + " ".join(
        base64.b64encode(bytes([i % 256]) * 40).decode() for i in range(60)))
    t0 = time.perf_counter()
    _run(P._try_fast_solve(_q("w1", "crypto", desc)))
    ms = (time.perf_counter() - t0) * 1000
    assert ms < 5000, f"最坏题面耗时 {ms:.0f}ms 超阈值，可能引入新卡死点"


# ── ⑤：原行为保持 + 不虚报 ────────────────────────────────────────────
def test_attachment_path_still_works(tmp_path):
    """附件路径（原行为）不得被破坏。"""
    p = tmp_path / "c.txt"
    p.write_text(_b64n(FLAG_B64, 2), encoding="utf-8")
    q = _q("a1", "crypto", "base64 编码，见附件", attachments=[str(p)])
    got = _run(P._try_fast_solve(q))
    assert got and FLAG_B64 in str(got), f"附件路径回归: {got!r}"


def test_no_flag_in_desc_returns_none():
    """题面无 flag 时不得返回任何东西（不虚报铁律）。"""
    desc = "base64 编码：" + _b64n("这是一段没有答案的普通中文文本", 1)
    got = _run(P._try_fast_solve(_q("n1", "crypto", desc)))
    assert not got, f"无 flag 题面却返回了 {got!r}（虚报）"


def test_morse_in_desc_does_not_fabricate():
    """摩斯形态当前不支持产出合规 flag{} —— 必须返回 None，**不得猜外壳**。

    理由（诚实记录）：摩斯码表无 `{`/`}` 标准编码，解码结果形如 `FLAGTEST`
    无外壳；强行补 `flag{...}` 就是编造答案，违反项目「不虚报」铁律。
    本用例正是防「靠猜外壳把 LAGMRSECDEOK 包装成假 flag 骗过闸门」的守卫。
    """
    desc = f"摩斯电码如下，请解码：{_morse('flagtest')}"
    got = _run(P._try_fast_solve(_q("m1", "misc", desc)))
    assert not got, f"摩斯形态返回了可疑结果 {got!r}（若为真实修复请同步更新本用例）"


def test_non_crypto_category_is_skipped():
    """非 crypto/misc 分类直接跳过（原行为）。"""
    desc = f"base64 编码：{_b64n(FLAG_B64, 1)}"
    assert _run(P._try_fast_solve(_q("s1", "pwn", desc))) is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
