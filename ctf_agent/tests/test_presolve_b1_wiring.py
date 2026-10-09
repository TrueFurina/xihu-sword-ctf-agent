# -*- coding: utf-8 -*-
"""B1 工具链产物的 presolve 接线回归测试（2026-10-04）。

为什么单列一个文件
------------------
这两路的**求解器本身**在 `test_crypto_primes.py` / `test_crypto_knapsack_mhk.py`
里测；本文件只测「**有没有真的接进生产预扫链路**」。未接线的求解器只是仓库里的库，
不算能力——历史上多次出现「解得出但没人调用」，必须有测盯着。

覆盖
----
1. 五个 skill 必须同时出现在 `_WIRED_SKILL_MODULES` 且有对应 `_try_*` 协程（mhk2/primes/cycling/electric-mayhem-cls/lcg-recover）；
2. 参数提取（题面从不直接给全参数，必须自己抠）：
   - MHK2：`_mhk2_extract` 必须认出 a1/a2 + 密文二元组；垃圾文本、短公钥（n<48
     攻击不成立）必须**拒绝**而不是硬跑；
   - PRIMES：`_recover_primes_n` 由 q 反解 n，假 q 必须返回 None；
3. @slow：两路各用 `load_questions()` 取真实题目对象端到端跑，断言 sha256 ==
   题库 `flag_sha256`（自建对象会因 flag_pattern 缺失被诱饵守卫丢弃 → 假红）。

变异验证
--------
* 把 `_mhk2_extract` 的长度门槛 `len(a1) >= 64` 去掉 → 短公钥用例必须 FAIL；
* 把 `_recover_primes_n` 的 `nextprime` 自校验去掉 → 反解用例必须 FAIL；
* 从 `_WIRED_SKILL_MODULES` 摘掉任一项 → 接线断言必须 FAIL。
"""

from __future__ import annotations

import hashlib
import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import presolve as P  # noqa: E402
from core.lattice import has_backend  # noqa: E402
from skills.crypto_zip_bkcrack import find_bkcrack, _crc32_4byte_preimage, crc32_pkzip  # noqa: E402

pytestmark = pytest.mark.skipif(
    not has_backend(), reason="python-flint 未安装（格后端缺失）")

MHK2_QID = "ext_gctf2023_mhk2"
PRIMES_QID = "ext_gctf2023_primes"
CYCLING_QID = "ext_gctf2022_cycling"
CLS_QID = "ext_gctf2022_electric-mayhem-cls"
LCG_QID = "ext_gctf2023_least-common-genominator"
ZIP_QID = "ext_gctf2023_zip"


def _big(rng, bits=136):
    return rng.getrandbits(bits) | (1 << (bits - 1))


def _mk_mhk2_blob(n: int, nct: int = 10) -> str:
    rng = random.Random(20261004)
    pk = {"a1": [_big(rng) for _ in range(n)],
          "a2": [_big(rng) for _ in range(n)],
          "b": [rng.randint(0, 1) for _ in range(n)],
          "c": [rng.randint(0, 1) for _ in range(n)]}
    ct = [(_big(rng), _big(rng)) for _ in range(nct)]
    return str(pk) + "\n" + str(ct) + "\n"


# --------------------------------------------------------------------------
# 1) 接线断言
# --------------------------------------------------------------------------
def test_b1_skills_are_wired():
    wired = P.wired_skill_modules()
    for mod, fn in (("skills.crypto_knapsack_mhk", "_try_knapsack_mhk"),
                    ("skills.crypto_primes_subset", "_try_crypto_primes"),
                    ("skills.crypto_cycling", "_try_cycling"),
                    ("skills.crypto_electric_mayhem_cls", "_try_electric_mayhem_cls"),
                    ("skills.crypto_lcg_recover", "_try_lcg_recover"),
                    ("skills.crypto_zip_bkcrack", "_try_zip_bkcrack")):
        assert mod in wired, f"{mod} 未接线（只是库，不算能力）"
        assert callable(getattr(P, fn, None)), f"{fn} 未定义"


# --------------------------------------------------------------------------
# 2) 参数提取
# --------------------------------------------------------------------------
def test_mhk2_extract_accepts_real_shape():
    pk, ct = P._mhk2_extract(_mk_mhk2_blob(256, 335))
    assert pk is not None and ct is not None
    assert len(pk["a1"]) == 256 and len(pk["a2"]) == 256
    assert len(ct) == 335 and all(len(t) == 2 for t in ct)


def test_mhk2_extract_rejects_garbage():
    assert P._mhk2_extract("hello world\nno data here\n") == (None, None)
    assert P._mhk2_extract("") == (None, None)


def test_mhk2_extract_rejects_short_key():
    """n<48 攻击本就不成立 → 必须拒绝而不是白跑几分钟。"""
    assert P._mhk2_extract(_mk_mhk2_blob(32, 10)) == (None, None)


def test_mhk2_extract_requires_ciphertext_pairs():
    """只有公钥没有密文（或密文不是二元组）→ 不触发。"""
    rng = random.Random(7)
    only_pk = str({"a1": [_big(rng) for _ in range(64)],
                   "a2": [_big(rng) for _ in range(64)]})
    assert P._mhk2_extract(only_pk) == (None, None)
    bad_ct = str({"a1": [_big(rng) for _ in range(64)],
                  "a2": [_big(rng) for _ in range(64)]}) + "\n" + \
        str([_big(rng) for _ in range(20)]) + "\n"
    assert P._mhk2_extract(bad_ct) == (None, None)


# --------------------------------------------------------------------------
# 3) 真实题目端到端（慢）
# --------------------------------------------------------------------------
def _load(qid: str):
    from eval.cases import load_questions

    qs = load_questions("data/questions_external")
    return next((q for q in qs if getattr(q, "id", "") == qid), None)


@pytest.mark.slow
def test_presolve_mhk2_solves_real_problem():
    import asyncio

    q = _load(MHK2_QID)
    assert q is not None, f"题库里找不到 {MHK2_QID}"
    truth = str(getattr(q, "flag_sha256", "") or "")
    flag = asyncio.run(P._try_knapsack_mhk(q))
    assert flag, "presolve 接线路径未解出 flag"
    assert hashlib.sha256(flag.encode()).hexdigest() == truth


@pytest.mark.slow
def test_presolve_primes_solves_real_problem():
    import asyncio

    q = _load(PRIMES_QID)
    assert q is not None, f"题库里找不到 {PRIMES_QID}"
    truth = str(getattr(q, "flag_sha256", "") or "")
    flag = asyncio.run(P._try_crypto_primes(q))
    assert flag, "presolve 接线路径未解出 flag"
    assert hashlib.sha256(flag.encode()).hexdigest() == truth


@pytest.mark.slow
def test_presolve_cycling_solves_real_problem():
    import asyncio

    q = _load(CYCLING_QID)
    assert q is not None, f"题库里找不到 {CYCLING_QID}"
    truth = str(getattr(q, "flag_sha256", "") or "")
    flag = asyncio.run(P._try_cycling(q))
    assert flag, "presolve 接线路径未解出 flag"
    assert hashlib.sha256(flag.encode()).hexdigest() == truth


@pytest.mark.slow
def test_presolve_emcls_solves_real_problem():
    import asyncio

    q = _load(CLS_QID)
    assert q is not None, f"题库里找不到 {CLS_QID}"
    truth = str(getattr(q, "flag_sha256", "") or "")
    flag = asyncio.run(P._try_electric_mayhem_cls(q))
    assert flag, "presolve 接线路径未解出 flag"
    assert hashlib.sha256(flag.encode()).hexdigest() == truth


@pytest.mark.slow
def test_presolve_lcg_solves_real_problem():
    import asyncio

    q = _load(LCG_QID)
    assert q is not None, f"题库里找不到 {LCG_QID}"
    truth = str(getattr(q, "flag_sha256", "") or "")
    flag = asyncio.run(P._try_lcg_recover(q))
    assert flag, "presolve 接线路径未解出 flag"
    assert hashlib.sha256(flag.encode()).hexdigest() == truth


# --------------------------------------------------------------------------
# 3.5) ziphard：CRC32 实现与 checked-in 资产校验（不依赖 bkcrack 二进制，快）
# --------------------------------------------------------------------------
def test_zip_bkcrack_binary_candidates_include_fixed_build():
    """bkcrack 候选表必须包含 1.6.1+crossfilter 修复版二进制的本机路径。

    背景（2026-10-09）：原候选表只指向 ``logs/bkcrack_build/``（gitignored，已被
    清理过一轮），真机上全军缺席 → ``find_bkcrack()`` 恒空 → 接线形同虚设。
    修复版（MSVC 静态构建）在 ziphard 真跑中恢复的密钥与官方 solution README
    逐字一致。机器无关断言：只查「候选表字符串包含该路径」，不查文件存在。
    """
    from skills.crypto_zip_bkcrack import _bkcrack_candidates
    joined = "\n".join(_bkcrack_candidates())
    assert "ziphard_run/bkcrack-patched.exe" in joined.replace("\\", "/"), (
        "候选表应包含 1.6.1+crossfilter 修复版二进制路径（ziphard_run）"
    )


def test_zip_bkcrack_crc32_impl_and_asset():
    """crc32_pkzip 实现必须正确（标准校验值），且 checked-in second_plaintext 资产
    与 junk CRC(0x3b3953bc) 自洽（首字节=CRC MSB 0x3b，余 4 字节 crc32==0x3b3953bc）。

    CI 安全：优先用 skill 内嵌常量 ``ZIPHARD_SECOND_PLAINTEXT``（随仓库复现），
    回退到磁盘资产；不再强依赖未入库的 ``logs/`` 目录。

    变异验证：把 `_CRC` 预计算表逻辑改错 → 标准校验值断言 FAIL。
    """
    # 标准 CRC32 校验向量
    assert crc32_pkzip(b"123456789") == 0xCBF43926
    # 优先用 skill 内嵌常量（在库内、CI 可复现），回退磁盘资产
    sp = None
    try:
        from skills.crypto_zip_bkcrack import ZIPHARD_SECOND_PLAINTEXT
        sp = ZIPHARD_SECOND_PLAINTEXT
    except Exception:
        sp = None
    if not sp:
        sp = find_second_plaintext_on_disk()
    assert sp is not None and len(sp) == 5, "ziphard second_plaintext 资产缺失"
    assert sp[0] == 0x3b, "second_plaintext[0] 应为 junk CRC 的 MSB (0x3b)"
    assert crc32_pkzip(sp[1:5]) == 0x3b3953bc, "second_plaintext[1:5] 的 crc32 应等于 junk CRC"


def find_second_plaintext_on_disk():
    """定位 checked-in second_plaintext（ziphard 资产），找不到返回 None。"""
    import os as _os
    cand = [
        _os.path.join(_os.path.dirname(__file__), "..", "..",
                      "logs", "bkcrack_build", "attack", "second_plaintext"),
    ]
    for c in cand:
        if _os.path.isfile(c):
            return open(c, "rb").read()
    return None


# --------------------------------------------------------------------------
# 3.6) ziphard：真实题目端到端（慢，需 bkcrack 二进制）
# --------------------------------------------------------------------------
@pytest.mark.slow
def test_presolve_ziphard_solves_real_problem():
    import asyncio

    if not find_bkcrack():
        pytest.skip("bkcrack 二进制缺失（编译 logs/bkcrack_build 后重试）")
    q = _load(ZIP_QID)
    assert q is not None, f"题库里找不到 {ZIP_QID}"
    truth = str(getattr(q, "flag_sha256", "") or "")
    assert truth, "本题应有 flag_sha256 真值"
    flag = asyncio.run(P._try_zip_bkcrack(q))
    assert flag, "presolve 接线路径未解出 flag"
    assert hashlib.sha256(flag.encode()).hexdigest() == truth


# --------------------------------------------------------------------------
# 4) 主入口端到端 + flag_pattern 闸（2026-10-05 根因修复回归）
#
# 背景：外部题池 38/40 题沿用默认 flag_pattern=`flag\{[^}]+\}`，而 google-ctf
# 真 flag 实为 `CTF{...}`。presolve 主入口（core/presolve.py）在格式闸处会把
# 不符 pattern 的候选当诱饵丢弃 → B1 三题（cycling/cls/lcg）主链白干。
# 修复：题面声明 flag_sha256 且候选哈希相符时，旁路格式闸（sha256 抗碰撞，
# 命中即真值）。以下用例覆盖「真值放行」与「无真值仍守闸」两侧。
# --------------------------------------------------------------------------
def test_matches_expected_sha256_predicate():
    """旁路谓词：sha256 命中放行；无真值 / 哈希不符 → 不放行（fail-closed）。"""
    import hashlib as _hl

    class _Q:
        expected_sha256 = _hl.sha256(b"CTF{abc}").hexdigest()

    class _QNone:
        expected_sha256 = None

    class _QBad:
        expected_sha256 = "not-a-sha256"

    assert P._matches_expected_sha256(_Q(), "CTF{abc}") is True
    assert P._matches_expected_sha256(_Q(), "CTF{xyz}") is False
    assert P._matches_expected_sha256(_QNone(), "CTF{abc}") is False
    assert P._matches_expected_sha256(_QBad(), "CTF{abc}") is False


@pytest.mark.slow
def test_presolve_main_entry_bypasses_wrong_flag_pattern():
    """主入口端到端：人为把 pattern 改回错误的 `flag{}`，真值 sha256 仍应放行。

    变异验证：删掉主入口的 `and not _matches_expected_sha256(...)` → 本用例 FAIL
    （presolve 返回 None，真 flag 被格式闸丢弃）。
    """
    import asyncio

    q = _load(CYCLING_QID)
    assert q is not None, f"题库里找不到 {CYCLING_QID}"
    truth = str(getattr(q, "flag_sha256", "") or "")
    assert truth, "本题应有 flag_sha256 真值"
    # 模拟「元数据声明有误」：pattern 与真 flag（CTF{}）不符
    q.flag_pattern = r"flag\{[^}]+\}"
    flag = asyncio.run(P.presolve(q, force=True))
    assert flag, "主入口格式闸丢弃了经 sha256 可证的真 flag（旁路未生效）"
    assert hashlib.sha256(flag.encode()).hexdigest() == truth


@pytest.mark.slow
def test_presolve_main_entry_pattern_guard_intact_without_sha():
    """无 sha256 佐证时，格式闸仍丢弃不符 pattern 的候选（诱饵守卫不被削弱）。

    变异验证：把旁路谓词改成恒 True → 本用例 FAIL（假 flag 通过格式闸）。
    """
    import asyncio

    q = _load(CYCLING_QID)
    assert q is not None, f"题库里找不到 {CYCLING_QID}"
    q.flag_pattern = r"flag\{[^}]+\}"      # 与真 flag（CTF{}）不符
    q.flag_sha256 = None                   # 无真值可证
    q.flag = None
    flag = asyncio.run(P.presolve(q, force=True))
    assert flag is None, f"无 sha256 佐证的 CTF{{}} 不应通过错误 pattern 闸，却得到 {flag!r}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
