# -*- coding: utf-8 -*-
"""ZipCrypto 第一道筛的向量化改造回归（2026-10-09）。

背景
----
`skills/zip_crypto_bruteforce` 的第一道筛（12 字节头校验）原本是**纯 Python
逐字节流式推 keys**，是爆破的主要瓶颈。本机实测（真 ZipCrypto fixture）：

    逐个 `_pass1_candidates`        :  46,203 候选/秒
    run() 端到端（含命中复核）       :  25,000 候选/秒
    `itertools.product` 生成候选    : 6,797,611 候选/秒（**不是**瓶颈）
    → 改造后 `_scan_enum`           : 1,055,728 ~ 2,099,356 候选/秒

⇒ 瓶颈确实在筛选，不在生成。改造把整批候选的 keys 推进交给 numpy。

本文件锁死三件事
----------------
1. **向量版与逐个版结果必须逐条一致**（对拍，含真命中样本）
2. **`_scan_enum` 的字节推进顺序必须与 `itertools.product` 一致**
   —— 这是实现时真踩过的 bug：写成从**末位**开始推 keys，
   症状是「端到端报未命中、但回退路径能解出」，极难定位。
   ⚠️ 对拍样本**必须包含真命中**，否则这类 bug 抓不到
   （第一版对拍用 3 位 `abc` 全空间，命中数为 0 ⇒ 顺序错了也全绿）。
3. **无 numpy 时必须回退且结果一致**（numpy 是硬依赖，但导入失败不能拖垮 skill）

变异验证
--------
* 把 `_scan_enum` 里 `pows[j]` 换成 `base ** j`（从末位推）⇒
  `test_scan_enum_byte_order_*` 必须 FAIL；
* 把 `_pass1_vector` 的 numpy 分支删掉（恒走逐个）⇒
  `test_vector_matches_one_by_one` 仍绿（等价），但
  `test_enum_covers_fixture_password` 仍绿 ⇒ 说明这两条**不足以**证明
  向量路径在用，所以另有 `test_enum_path_is_used_by_run` 直接断言接线。
"""

from __future__ import annotations

import itertools
import random
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skills import zip_crypto_bruteforce as Z  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "zipcrypto_66688.zip"
_FIXTURE_PWD = b"66688"

pytestmark = pytest.mark.skipif(
    not FIXTURE.exists(), reason="fixture zipcrypto_66688.zip 缺失")


@pytest.fixture(scope="module")
def entry_data():
    hdr, body, crc, check, method, usize = Z._local_entry(str(FIXTURE), "Readme.txt")
    return {"hdr": hdr, "crc": crc, "check": check, "method": method}


# --------------------------------------------------------------------------
# 1) 向量版 == 逐个版（逐条对拍）
# --------------------------------------------------------------------------
def test_vector_matches_one_by_one(entry_data):
    """`_pass1_vector` 的命中集合必须与逐个 `_pass1_candidates` 完全一致。

    样本刻意包含 fixture 的真密码（66688）与它的邻居（66687），
    保证「有命中可对」——全不中的样本对拍没有意义。
    """
    hdr, check = entry_data["hdr"], entry_data["check"]
    random.seed(20261009)
    alph = b"abcXYZ0129"
    pwds = [bytes(random.choice(alph) for _ in range(random.randint(1, 6)))
            for _ in range(5000)]
    pwds += [_FIXTURE_PWD, b"66687", b"a", b"zzzz"]

    ref = [i for i, p in enumerate(pwds)
           if Z._pass1_candidates(hdr, check, p)]
    vec = Z._pass1_vector(hdr, check, pwds)

    assert ref, "样本里一个命中都没有 —— 对拍失去意义，请换样本"
    assert ref == vec, (
        f"向量版与逐个版不一致：逐个 {len(ref)} 个命中 / 向量 {len(vec)} 个。"
        f"仅出现在逐个版的={sorted(set(ref) - set(vec))[:10]}，"
        f"仅出现在向量版的={sorted(set(vec) - set(ref))[:10]}")


def test_vector_empty_and_zero_len(entry_data):
    """空列表与空密码（长度 0）不能炸。"""
    hdr, check = entry_data["hdr"], entry_data["check"]
    assert Z._pass1_vector(hdr, check, []) == []
    assert Z._pass1_vector(hdr, check, [b"", b"a"]) == \
        [i for i, p in enumerate([b"", b"a"])
         if Z._pass1_candidates(hdr, check, p)]


# --------------------------------------------------------------------------
# 2) 字节顺序：与 itertools.product 同序 + 真密码必须被覆盖
# --------------------------------------------------------------------------
def test_pwd_from_index_matches_product():
    """`_pwd_from_index` 的编号必须与 `itertools.product` 同序（末位变化最快）。"""
    for table in (b"0123456789", b"abc"):
        for L in (1, 2, 3):
            n = len(table) ** L
            ref = [bytes(x) for x in itertools.islice(
                itertools.product(table, repeat=L), n)]
            assert all(Z._pwd_from_index(i, table, L) == ref[i]
                       for i in range(n)), (
                f"L={L} 编号与 itertools.product 不同序")


def test_scan_enum_matches_product_with_real_hits(entry_data):
    """`_scan_enum` 的命中集合必须与逐个版一致（**样本必须含真命中**）。

    第一版对拍用 3 位 `abc`（27 条，0 命中）⇒ 字节顺序写反了也全绿。
    这里改用 digits 5 位（100,000 条，实测 379 个命中）。
    """
    hdr, check = entry_data["hdr"], entry_data["check"]
    table = b"0123456789"
    L = 5
    n = len(table) ** L
    enum_hits = Z._scan_enum(hdr, check, table, L, 0, n)

    ref_all = [bytes(x) for x in itertools.product(table, repeat=L)]
    ref_hits = [i for i, p in enumerate(ref_all)
                if Z._pass1_candidates(hdr, check, p)]

    assert len(ref_hits) > 50, (
        f"参考命中只有 {len(ref_hits)} 个 —— 样本太小，抓不到顺序类 bug")
    assert enum_hits == ref_hits, (
        f"_scan_enum 命中 {len(enum_hits)} 个 / 逐个版 {len(ref_hits)} 个。"
        f"多出来的={sorted(set(enum_hits) - set(ref_hits))[:10]}，"
        f"漏掉的={sorted(set(ref_hits) - set(enum_hits))[:10]}")


def test_scan_enum_byte_order_covers_fixture_password(entry_data):
    """**核心用例**：向量枚举必须能命中 fixture 真密码并还原成 `66688`。

    变异方式：把 `_scan_enum` 的位权从 `base ** (length-1-j)` 改成
    `base ** j`（从末位开始推 keys）⇒ 本用例必须 FAIL。

    ⚠️ 这个 bug 真实发生过：端到端只报「未命中」，而**无 numpy 的回退路径
    却能解出**，靠两者对照才定位到。所以这里直接钉住「向量路径能解出」。
    """
    hdr, check = entry_data["hdr"], entry_data["check"]
    table = b"0123456789"
    hits = Z._scan_enum(hdr, check, table, 5, 0, 100_000)
    assert 66688 in hits, (
        "向量枚举漏掉了 fixture 密码 66688 —— 极可能是 keys 推进的字节顺序"
        "（按位权从高到低）写反了：ZipCrypto 的 keys 是流式的，"
        "顺序错一位整个筛选结果就作废，而症状只是「解不出」，很难定位")
    assert Z._pwd_from_index(66688, table, 5) == _FIXTURE_PWD

    # 命中者必须能被逐个版复核通过（防止向量版给出假命中）
    for gi in hits[:50]:
        assert Z._pass1_candidates(hdr, check, Z._pwd_from_index(gi, table, 5))


def test_enum_path_is_used_by_run(entry_data):
    """`run()` 在有 numpy 时必须真的走 `_scan_enum`（而不是悄悄回退）。

    这是「守卫自己必须能抓住目标」的配套检查：前两条用例在向量路径
    被删掉后仍然全绿（因为回退路径结果等价），只有这条会红。
    """
    if not Z._HAVE_NUMPY:
        pytest.skip("本机无 numpy，向量路径不可用")
    called = {"n": 0}
    real = Z._scan_enum

    def spy(*a, **kw):
        called["n"] += 1
        return real(*a, **kw)

    Z._scan_enum = spy
    try:
        res = Z.run({"zip_path": str(FIXTURE), "entry": "Readme.txt",
                     "max_len": 6, "max_candidates": 2_000_000,
                     "charsets": ["digits", "lower", "alnum"]})
    finally:
        Z._scan_enum = real

    assert called["n"] > 0, "run() 一次都没调 _scan_enum ⇒ 向量路径没被用上"
    assert res.get("ok") and res.get("password") == _FIXTURE_PWD.decode(), (
        f"走向量路径却没解出 fixture：{res}")


# --------------------------------------------------------------------------
# 3) 无 numpy 回退：结果必须一致
# --------------------------------------------------------------------------
def test_fallback_without_numpy_still_solves(entry_data, monkeypatch):
    """numpy 取不到时回退逐个实现，**仍必须解出** fixture。

    变异方式：把 `_scan_charsets` 里 `if not _HAVE_NUMPY` 分支删掉
    （无 numpy 时仍走向量）⇒ 本用例必须 FAIL（会 AttributeError 或漏解）。
    """
    monkeypatch.setattr(Z, "_HAVE_NUMPY", False)
    res = Z.run({"zip_path": str(FIXTURE), "entry": "Readme.txt",
                 "max_len": 6, "max_candidates": 2_000_000,
                 "charsets": ["digits", "lower", "alnum"]})
    assert res.get("ok"), f"无 numpy 回退路径解不出 fixture：{res}"
    assert res.get("password") == _FIXTURE_PWD.decode()
    # 回退路径也必须遵守候选上限语义
    over = Z.run({"zip_path": str(FIXTURE), "entry": "Readme.txt",
                  "min_len": 1, "max_len": 4, "max_candidates": 1_000,
                  "charsets": ["lower"]})
    assert not over.get("ok") and "超上限" in (over.get("error") or ""), (
        f"回退路径的超上限语义变了：{over}")


# --------------------------------------------------------------------------
# 4) 提速必须有据可依（不是拍脑袋说「变快了」）
# --------------------------------------------------------------------------
def test_vector_screening_is_faster_than_one_by_one(entry_data):
    """向量筛选相对逐个筛选必须有**数量级**优势（实测口径，宽松阈值防 CI 抖动）。

    逐个版本机 46,203 候选/秒；向量版 ≥ 1,000,000 候选/秒。
    阈值取 3x（远低于实测 24x）—— 本用例只想抓住「退化回逐个」这种回归，
    不做精确性能门禁（CI 机器差异大）。
    """
    if not Z._HAVE_NUMPY:
        pytest.skip("本机无 numpy")
    hdr, check = entry_data["hdr"], entry_data["check"]
    pwds = [bytes(x) for x in itertools.islice(
        itertools.product(b"abcdefghijklmnopqrstuvwxyz", repeat=4), 20_000)]

    t0 = time.perf_counter()
    for p in pwds:
        Z._pass1_candidates(hdr, check, p)
    slow = time.perf_counter() - t0

    t0 = time.perf_counter()
    Z._pass1_vector(hdr, check, pwds)
    fast = time.perf_counter() - t0

    assert fast > 0 and slow / fast >= 3.0, (
        f"向量筛选没有数量级优势：逐个 {slow:.3f}s / 向量 {fast:.3f}s "
        f"= {slow / fast:.1f}x（实测应 ~24x，低于 3x 说明退化成逐个了）")
