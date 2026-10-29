# -*- coding: utf-8 -*-
"""zip_fake_encryption 的 flag 形状守卫（2026-10-25 实测缺陷）。

背景（实测，非推断）：

**flag 被截断 ⇒ 本 skill 的产出 100% 被上层丢弃。**
`_extract_flag_from_zip` 只取 `m.group(1)`（花括号**内**的内容），丢掉
`flag{}` / `DASCTF{}` 外壳。实测（main `f8d3cd73`）：

```
zip_fake_encryption.run(...)      -> flag='real_flag_here'
    presolve._FLAG_RE 接受 = False    ← 产出恒被丢弃
misc_zip_fake_encryption.run(...) -> flag='flag{real_flag_here}'
    presolve._FLAG_RE 接受 = True
```

同仓库两个同类 skill 的返回形态不一致，而 `_FLAG_RE` 要求完整外壳 ⇒
`zip_fake_encryption` **即使解出真 flag 也永远进不了 presolve**，
`fast_solve('zip')` 的伪加密回退路 0 贡献；
`scripts/_batch_bruteforce.py` 则直接把截断值当答案提交。

**修截断会带来诱饵风险**：`DASCTF{ni_cai?}` 这类 zip 内诱饵原本是
`'ni_cai?'`（不可提交），修完变成可提交形态。所以必须同时标歧义——
本测试两条都盯：形状必须完整，多候选必须标 `ambiguous`。
"""
import zipfile

import pytest

from agents.crypto_toolkit import fast_solve
from skills.zip_fake_encryption import run as zip_fake_run

try:  # 验收口径：presolve 用同一条正则决定「要不要这个 flag」
    from core.presolve import _FLAG_RE
except Exception:  # noqa: BLE001
    _FLAG_RE = None


def _mk(path, entries, fake_enc=False):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    if not fake_enc:
        return str(path)
    buf = bytearray(open(path, "rb").read())
    # 本地文件头 flag_bits 在偏移 6；中央目录在偏移 8
    i = 0
    while True:
        i = buf.find(b"PK\x03\x04", i)
        if i < 0:
            break
        buf[i + 6] |= 1
        i += 4
    i = 0
    while True:
        i = buf.find(b"PK\x01\x02", i)
        if i < 0:
            break
        buf[i + 8] |= 1
        i += 4
    open(path, "wb").write(bytes(buf))
    return str(path)


# ── ① flag 必须带完整外壳（这是本测试存在的首要理由）──────────────────────
def test_flag_keeps_full_wrapper(tmp_path):
    """解出的 flag 必须是 `flag{...}` 完整形态，不能只剩花括号内内容。"""
    p = _mk(tmp_path / "plain.zip",
            [("flag.txt", b"hello flag{real_flag_here} world\n")])
    r = zip_fake_run({"path": p})
    assert r.get("ok") is True, f"未解出: {r}"
    assert r.get("flag") == "flag{real_flag_here}", (
        f"flag 形状不对: {r.get('flag')!r} —— 只取了花括号内内容会导致 "
        "presolve 的 _FLAG_RE 拒收，本 skill 产出恒被丢弃")


def test_flag_is_acceptable_by_presolve_flag_re(tmp_path):
    """必须用 presolve 的验收正则实测：解出的 flag 要能被采纳。"""
    if _FLAG_RE is None:
        pytest.skip("无法导入 presolve._FLAG_RE")
    p = _mk(tmp_path / "acc.zip", [("flag.txt", b"flag{accept_me}\n")])
    r = zip_fake_run({"path": p})
    assert _FLAG_RE.search(str(r.get("flag", ""))), (
        f"解出的 flag={r.get('flag')!r} 通不过 presolve._FLAG_RE ⇒ "
        "等于解出来了也被丢弃")


def test_every_candidate_keeps_wrapper(tmp_path):
    """`flags` 里每个候选都要完整（上层可能遍历它裁决）。"""
    p = _mk(tmp_path / "multi.zip", [
        ("a.txt", b"flag{aaa_one}\n"),
        ("b.txt", b"DASCTF{bbb_two}\n"),
    ])
    r = zip_fake_run({"path": p})
    for _name, flag in r.get("flags", []):
        assert "{" in flag and flag.endswith("}"), f"候选 {flag!r} 缺外壳"


def test_dasctf_wrapper_preserved(tmp_path):
    """DASCTF{} 外壳同样必须保留（原实现只留花括号内）。"""
    p = _mk(tmp_path / "das.zip", [("flag.txt", b"DASCTF{ni_cai?}\n")])
    r = zip_fake_run({"path": p})
    assert r.get("flag") == "DASCTF{ni_cai?}", f"外壳被吃掉: {r.get('flag')!r}"


# ── ② 多候选必须标歧义（防修完截断后把诱饵当真 flag）─────────────────────
def test_multiple_candidates_marked_ambiguous(tmp_path):
    p = _mk(tmp_path / "decoy.zip", [
        ("flag.txt", b"DASCTF{ni_cai?}\n"),
        ("readme.txt", b"flag{the_real_one}\n"),
    ])
    r = zip_fake_run({"path": p})
    assert r.get("ambiguous") is True, (
        f"zip 内命中多个不同候选却没标歧义: {r} —— 上层会把第一个（可能是诱饵）"
        "当真 flag 静默提交")
    assert len({f[1] for f in r.get("flags", [])}) >= 2


def test_single_candidate_not_marked_ambiguous(tmp_path):
    """单一候选不得无脑标歧义（否则标记失去意义）。"""
    p = _mk(tmp_path / "one.zip", [("flag.txt", b"flag{only_one}\n")])
    r = zip_fake_run({"path": p})
    assert r.get("ok") is True
    assert "ambiguous" not in r, f"单一候选不应标歧义: {r}"


# ── ③ 回归：伪加密 / 无 flag / fast_solve 回退 ─────────────────────────────
def test_fake_encryption_still_solves(tmp_path):
    p = _mk(tmp_path / "fake.zip", [("flag.txt", b"flag{fake_enc_ok}\n")],
            fake_enc=True)
    r = zip_fake_run({"path": p})
    assert r.get("ok") is True, f"伪加密未解出: {r}"
    assert r.get("flag") == "flag{fake_enc_ok}", f"{r}"


def test_no_flag_returns_not_ok(tmp_path):
    p = _mk(tmp_path / "none.zip", [("a.txt", b"nothing here\n")])
    r = zip_fake_run({"path": p})
    assert r.get("ok") is False, f"无 flag 不应 ok=True: {r}"


def test_fast_solve_zip_fallback_returns_full_flag(tmp_path):
    """fast_solve('zip') 的伪加密回退路也必须给完整 flag（原来恒被丢弃）。"""
    p = _mk(tmp_path / "fs.zip", [("flag.txt", b"flag{fs_fallback}\n")])
    r = fast_solve("zip", path=p, zip_path=p, s="")
    assert isinstance(r, dict), f"返回 {type(r).__name__} 而非 dict"
    assert r.get("flag") == "flag{fs_fallback}", (
        f"fast_solve('zip') 回退路 flag 形状不对: {r}")
