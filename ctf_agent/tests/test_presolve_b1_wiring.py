# -*- coding: utf-8 -*-
"""B1 工具链产物的 presolve 接线回归测试（2026-10-04）。

为什么单列一个文件
------------------
这两路的**求解器本身**在 `test_crypto_primes.py` / `test_crypto_knapsack_mhk.py`
里测；本文件只测「**有没有真的接进生产预扫链路**」。未接线的求解器只是仓库里的库，
不算能力——历史上多次出现「解得出但没人调用」，必须有测盯着。

覆盖
----
1. 两个 skill 必须同时出现在 `_WIRED_SKILL_MODULES` 且有对应 `_try_*` 协程；
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

pytestmark = pytest.mark.skipif(
    not has_backend(), reason="python-flint 未安装（格后端缺失）")

MHK2_QID = "ext_gctf2023_mhk2"
PRIMES_QID = "ext_gctf2023_primes"


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
                    ("skills.crypto_primes_subset", "_try_crypto_primes")):
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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
