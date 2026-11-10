"""presolve 题面八进制 ASCII 明文识别（2026-11-11 新增，确定性、零 LLM）。

防回归目标（每条对应一个真实缺口 / 一个误触发面）：

  ① 题面八进制序列命中：语料 real_crypto_anwang_crypto1 是「八进制 ASCII 序列
     解码得 key/data」，presolve 此前对此类「密文写在题面」形态命中 0。
     新增 _desc_octal_candidates 后须能从题面八进制序列解出 flag。
  ② 不误触发（文件权限 / 年份 / 普通数字）：八进制段解码若 >127（如 0644→420）
     或含 4 位以上数字（如 2024），必须被拒，不得把普通数字当密文。
  ③ 不虚报：题面无 flag 模式时返回 None（任何命中须经 _FLAG_RE + _is_plausible_flag）。
  ④ 有界：候选条数/单长必须截断，长题面不得爆炸。
"""

import asyncio
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core import presolve as P  # noqa: E402


def _octal_of(s: str) -> str:
    """把字符串逐字节转成空格分隔的 3 位八进制序列。"""
    return " ".join(f"{b:03o}" for b in s.encode("latin-1"))


FLAG = "flag{oct4l_d3m0_OK}"


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


# ── ① 端到端：题面八进制序列直出 flag ──────────────────────────────────
def test_octal_in_desc_is_solved():
    """题面给出八进制 ASCII 序列（无附件）必须解出 flag。"""
    desc = f"题目提示：以下为八进制 ASCII 序列，逐字节解码即为答案：\n{_octal_of(FLAG)}"
    got = _run(P._try_fast_solve(_q("oct1", "crypto", desc)))
    assert got and FLAG in str(got), f"题面八进制序列未解出: {got!r}"


def test_octal_unit_extracts_plaintext():
    """_desc_octal_candidates 能从题面八进制段解码出明文候选。"""
    desc = f"解码这段八进制：{_octal_of('key:FLAGdec data:kwam{{x}}')} 即可得到后续输入"
    out = P._desc_octal_candidates(desc)
    assert out, f"八进制明文未被提取: {out!r}"
    assert any("key:FLAGdec" in o for o in out), f"解码结果缺失: {out}"


# ── ② 不误触发 ─────────────────────────────────────────────────────────
def test_octal_skips_file_permissions():
    """文件权限式八进制（0644 0755 0177）解码 >127，必须被拒。"""
    desc = "权限分别是 0644 0755 0177，请勿修改"
    out = P._desc_octal_candidates(desc)
    assert not out, f"文件权限八进制被误当密文: {out!r}"


def test_octal_skips_years_and_long_digits():
    """年份 / 4 位以上数字（2024 1024）必须被拒（超过 {1,3} 位数）。"""
    desc = "成立于 2024 年，编号 1024"
    out = P._desc_octal_candidates(desc)
    assert not out, f"年份/长数字被误当八进制密文: {out!r}"


def test_octal_skips_plain_text():
    """普通中文/英文描述不得产出八进制候选。"""
    desc = "请对这段 base64 密文进行凯撒移位解密"
    out = P._desc_octal_candidates(desc)
    assert not out, f"普通文本被误产八进制候选: {out!r}"


# ── ③ 不虚报 ───────────────────────────────────────────────────────────
def test_octal_no_flag_returns_none():
    """题面八进制解码后不含 flag 模式时，端到端必须返回 None（不虚报）。"""
    # 解码后是 "hello world"，无 flag 外壳
    desc = f"八进制序列如下：{_octal_of('hello world')}"
    got = _run(P._try_fast_solve(_q("octn", "crypto", desc)))
    assert not got, f"无 flag 题面却返回了 {got!r}（虚报）"


# ── ④ 有界性 ───────────────────────────────────────────────────────────
def test_octal_candidate_count_is_bounded():
    """候选条数必须有上限，长题面不得爆炸（硬编码上界，不引用常量）。"""
    # 构造大量合法八进制段（每段都解码为可打印 ASCII 含字母）
    seg = " ".join(f"{ord(c):03o}" for c in "flag{x}")
    big = "   ".join(seg for _ in range(500))
    out = P._desc_octal_candidates(big)
    assert len(out) <= 8, f"八进制候选数 {len(out)} 爆炸"


def test_octal_is_fast_on_large_desc():
    """长题面不得把 _desc_octal_candidates 拖成墙钟炸弹。"""
    import time
    big = "正常描述 " * 2000 + _octal_of(FLAG)
    t0 = time.perf_counter()
    P._desc_octal_candidates(big)
    ms = (time.perf_counter() - t0) * 1000
    assert ms < 2000, f"八进制提取耗时 {ms:.0f}ms 超阈值"


# ── 题面十六进制 ASCII 明文识别（2026-11-11 新增，与 octal 同族）───────────
def _hex_of(s: str) -> str:
    """把字符串逐字节转成连续十六进制串。"""
    return s.encode("latin-1").hex()


HEXFLAG = "flag{h3x_d3m0_OK}"


def test_hex_in_desc_is_solved():
    """题面给出十六进制 ASCII 串（无附件）必须解出 flag。"""
    desc = f"密文以十六进制给出，解码即为答案：{_hex_of(HEXFLAG)}"
    got = _run(P._try_fast_solve(_q("hex1", "crypto", desc)))
    assert got and HEXFLAG in str(got), f"题面十六进制串未解出: {got!r}"


def test_hex_spaced_bytes_is_solved():
    """题面给出空格分隔的 hex 字节序（如 `4f 4b 7b`）必须解出 flag。"""
    desc = "逐字节十六进制如下：" + " ".join(f"{b:02x}" for b in HEXFLAG.encode("latin-1"))
    got = _run(P._try_fast_solve(_q("hex2", "crypto", desc)))
    assert got and HEXFLAG in str(got), f"空格分隔 hex 未解出: {got!r}"


def test_hex_unit_extracts_plaintext():
    """_desc_hex_candidates 能从题面 hex 段解码出明文候选。"""
    desc = f"解码这段 hex：{_hex_of('key:HEXdec data:kwam{x}')} 即可得到后续输入"
    out = P._desc_hex_candidates(desc)
    assert out, f"hex 明文未被提取: {out!r}"
    assert any("key:HEXdec" in o for o in out), f"解码结果缺失: {out}"


def test_hex_skips_sha256_like():
    """64 位 SHA256 类 hex 解码为随机 binary（含 >127 控制字节）必须被拒。"""
    sha_like = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert len(sha_like) == 64 and re_fullmatch_hex(sha_like)
    out = P._desc_hex_candidates(f"完整性校验值：{sha_like}")
    assert not out, f"SHA256 类 hex 被误当明文: {out!r}"


def test_hex_skips_short_and_years():
    """年份 / 短 hex（2024、deadbeef<ASCII 不可打印）必须被拒。"""
    # 2024 仅 4 hex 位 <8 阈值；deadbeef 解码为 0xde.. 非可打印 ASCII
    out = P._desc_hex_candidates("成立于 2024 年，样本 deadbeef")
    assert not out, f"年份/短 hex 被误当明文: {out!r}"


def test_hex_no_flag_returns_none():
    """题面 hex 解码后不含 flag 模式时，端到端必须返回 None（不虚报）。"""
    desc = f"十六进制序列如下：{_hex_of('hello world')}"
    got = _run(P._try_fast_solve(_q("hexn", "crypto", desc)))
    assert not got, f"无 flag 题面却返回了 {got!r}（虚报）"


def test_hex_candidate_count_is_bounded():
    """候选条数必须有上限，长题面不得爆炸。"""
    seg = _hex_of("flag{x}")
    big = "   ".join(seg for _ in range(500))
    out = P._desc_hex_candidates(big)
    assert len(out) <= 8, f"hex 候选数 {len(out)} 爆炸"


def re_fullmatch_hex(s: str) -> bool:
    import re as _re
    return bool(_re.fullmatch(r"[0-9a-fA-F]+", s))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
