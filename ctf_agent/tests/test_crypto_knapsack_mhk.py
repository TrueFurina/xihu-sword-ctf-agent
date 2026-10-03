# -*- coding: utf-8 -*-
"""crypto_knapsack_mhk（MHK 背包等价密钥恢复）回归测试。

覆盖三件事：
1. **格工具的数学性质**：饱和核必须既正交、又饱和（flint 的 nullspace() 只满足前者，
   这正是历史上攻击失败的坑，本文件用饱和性断言把它钉死）；
2. **端到端攻击**：n=64 自造实例（固定 seed，确定性）必须恢复出真正的 p/e；
3. **解密位重组**：MHK2 的 7-bit ASCII 重组（每 8 位取前 7 位）极易写错，单独钉死。

为什么夹具用 n=64 而不是题目真实的 n=256
-----------------------------------------
n=256 单把公钥恢复约 150s（两把 300s），放进 CI 不可接受。实测 n≥48 攻击即成立
（n=16/24/32 因短向量范数相对 p 过大而不成立），故取 n=64：稳定命中、约 1~2s。
真实 MHK2 题目（n=256）由 ``--run-slow`` 开启的慢测覆盖，作为真值证据。

变异验证（改动实现后必须手工复跑，确认本文件真的会红）
-----------------------------------------------------
* 把 ``saturated_kernel`` 换成 ``fmpz_mat(...).nullspace()[0]`` → 端到端用例必须 FAIL；
* 把 ``_recover_from_pair`` 的 ``cc = 2 * sigma`` 改成 ``-2 * sigma`` → 必须 FAIL；
* 把区间下界 ``lo = -(u0 // v0)`` 写成 ``lo = -u0 // v0`` 之外的等价错误形式 → 必须 FAIL；
* 把解密步长 ``range(0, len(bits), 8)`` 改成 ``range(0, len(bits), 7)`` → 解密用例必须 FAIL。
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.lattice import (  # noqa: E402
    LatticeBackendMissing,
    dot,
    has_backend,
    kernel_satisfies,
    lll,
    norm2_bits,
    saturated_kernel,
)
from skills.crypto_knapsack_mhk import (  # noqa: E402
    MHKAttackError,
    crypto_knapsack_mhk,
    decrypt_mhk2,
    recover_secret_key,
)

flint = pytest.importorskip("flint", reason="格后端 python-flint 未安装")

S_BITS = 128
N_SMALL = 64  # 快层夹具规模（实测 ≥48 攻击成立，64 稳定命中且 ~1s）


# --------------------------------------------------------------------------
# 夹具：确定性自造 MHK 实例（与题面 MHK2.sage 的私钥生成方式一致）
# --------------------------------------------------------------------------
def _gen_instance(n: int = N_SMALL, bits: int = S_BITS, seed: int = 1):
    """生成 (a, p, e, s)：a_j = e·s_j mod p，p = sum(s)+2 为素数。"""
    from sympy import isprime

    rnd = random.Random(seed)
    while True:
        s = [rnd.getrandbits(bits) for _ in range(n)]
        p = sum(s) + 2
        if isprime(p):
            break
    e = rnd.randrange((p - 1) // 2, p - 1)
    return [e * x % p for x in s], p, e, s


def _bits_of(msg: str) -> str:
    """复刻题面 encrypt() 的位串：int.from_bytes(...).'b'，天然去掉首字节前导 0。"""
    return bin(int.from_bytes(msg.encode(), "big"))[2:]


def _make_ciphertext(bit: int, p1: int, e1: int, p2: int, e2: int, rnd: random.Random):
    """构造一对密文使 decrypt_bit 得回 bit。

    题面 encrypt_bit 用子集和 + rejection sampling；这里直接指定
    M1 = e1^{-1}C1 mod p1 为一个**偶数**（奇偶 0），M2 = 偶数 + bit，
    于是 bit = (M1 + M2) % 2。这样密文不是常数，能真正钉死位重组逻辑。
    """
    x1 = 2 * rnd.randrange(1 << 40)
    x2 = 2 * rnd.randrange(1 << 40) + bit
    return e1 * x1 % p1, e2 * x2 % p2


# --------------------------------------------------------------------------
# 1. 格工具性质
# --------------------------------------------------------------------------
def test_saturated_kernel_is_orthogonal_and_saturated():
    """饱和核必须正交，且是**饱和**的（不能被更大的整数向量整除出更短格点）。

    反例（flint nullspace 的坑）：rows=[[2,4]] 的核，
    非饱和基给 [[-2,1]]（正确应为 [[-2,1]]？）——此处用经典例子：
    rows=[[2,0],[0,2]] 的核在 Z^2 中只有 0；取 rows=[[2,2]]，核为 (-1,1)（本原）。
    真正的饱和性检验：核基的任意整系数组合，若除以 g>1 仍在核内且仍是整向量，
    说明基非饱和。这里用「核基的最大公因子」判据。
    """
    rows = [[6, 10, 14]]  # 核：3x+5y+7z=0
    basis = saturated_kernel(rows)
    assert basis, "核不应为空"
    assert kernel_satisfies(rows, basis), "核向量必须满足 rows @ v = 0"
    # 饱和：每个基向量提取公因子后，若仍是整数向量则必须不再满足核方程
    from math import gcd

    for v in basis:
        g = 0
        for x in v:
            g = gcd(g, abs(x))
        assert g == 1, f"核基非本原（公因子 {g}）：{v}"
    assert len(basis) == 2, f"3 变量 1 方程 → 核秩应为 2，实得 {len(basis)}"


def test_kernel_rank_matches_nullity():
    """m×n 满秩矩阵的核秩 = n - m。"""
    rows = [[1, 0, 0, 0], [0, 1, 0, 0]]
    basis = saturated_kernel(rows)
    assert len(basis) == 2
    assert kernel_satisfies(rows, basis)
    assert all(dot(r, v) == 0 for r in rows for v in basis)


def test_lll_really_shortens_the_basis():
    """LLL 后基的范数必须显著小于原始基（否则说明后端/输入有问题）。"""
    rows = [[1, 0, 0], [0, 1, 0], [123456789, 987654321, 1]]
    before = max(norm2_bits(v) for v in rows)
    after = max(norm2_bits(v) for v in lll(rows))
    assert after < before, f"LLL 未把基约短：{before} → {after}"


def test_backend_missing_is_loud_not_silent(monkeypatch):
    """无 flint 时必须抛错，绝不静默走浮点兜底（float LLL 会算错）。"""
    import core.lattice as lattice
    import skills.crypto_knapsack_mhk as mhk

    monkeypatch.setattr(lattice, "has_backend", lambda: False)
    monkeypatch.setattr(mhk, "lll", lattice.lll)  # 走同一入口
    with pytest.raises(LatticeBackendMissing):
        saturated_kernel([[1, 2, 3]])
    with pytest.raises(LatticeBackendMissing):
        lll([[1, 0], [0, 1]])


# --------------------------------------------------------------------------
# 2. 端到端攻击（快层夹具）
# --------------------------------------------------------------------------
@pytest.mark.parametrize("seed", [1, 2])
def test_recover_secret_key_on_synthetic_instance(seed):
    """n=64 自造实例：必须恢复出与生成时完全相同的 p 和 e。"""
    a, p, e, _s = _gen_instance(seed=seed)
    r = recover_secret_key(a, s_bits=S_BITS)
    assert r is not None, f"seed={seed} 未命中"
    assert r["p"] == p, "恢复的 p 与真值不符"
    assert r["e"] == e, "恢复的 e 与真值不符"
    # 恢复出的 s 必须是**可用的等价密钥**（逐坐标校验）
    assert all((e * sj - aj) % p == 0 for aj, sj in zip(a, r["s"]))


def test_recover_key_via_skill_entry():
    """skill 入口 recover_key 的契约。"""
    a, p, e, _ = _gen_instance(seed=3)
    out = crypto_knapsack_mhk({"kind": "recover_key", "a": a})
    assert out["ok"] is True, out
    assert out["p"] == p and out["e"] == e
    assert isinstance(out["drop"], int)


def test_skill_rejects_bad_input():
    assert crypto_knapsack_mhk({"kind": "recover_key"})["ok"] is False
    assert crypto_knapsack_mhk({"kind": "mhk2_decrypt", "pk": {}})["ok"] is False
    assert crypto_knapsack_mhk({"kind": "nope"})["ok"] is False
    with pytest.raises(MHKAttackError):
        recover_secret_key([1, 2, 3])


def test_small_n_does_not_claim_victory():
    """n=32 已知攻击不成立：要么老实返回 None，要么给出的必须是**真等价密钥**。

    钉死「没解出却硬报 p/e」的假胜（validate 通过即等价密钥，故只允许这两种结果）。
    """
    a, p, _e, _s = _gen_instance(n=32, seed=32)
    r = recover_secret_key(a, s_bits=S_BITS)
    if r is not None:
        assert all((r["e"] * sj - aj) % r["p"] == 0 for aj, sj in zip(a, r["s"]))


# --------------------------------------------------------------------------
# 3. MHK2 解密位重组
# --------------------------------------------------------------------------
def test_decrypt_mhk2_reassembles_7bit_ascii():
    """两把公钥 + 逐比特密文 → 7-bit ASCII 明文（每 8 位取前 7 位）。"""
    msg = "CTF{kn4ps4ck}"
    a1, p1, e1, _ = _gen_instance(seed=11)
    a2, p2, e2, _ = _gen_instance(seed=12)
    rnd = random.Random(7)
    ct = [_make_ciphertext(int(b), p1, e1, p2, e2, rnd) for b in _bits_of(msg)]
    assert len(ct) == 8 * len(msg) - 1, "位串长度应等于 8·len(msg) 去掉前导 0"

    out = decrypt_mhk2({"a1": a1, "a2": a2}, ct, s_bits=S_BITS)
    assert out == msg, f"解密不符：{out!r} != {msg!r}"

    via_skill = crypto_knapsack_mhk({"kind": "mhk2_decrypt", "pk": {"a1": a1, "a2": a2}, "ct": ct})
    assert via_skill["ok"] is True and via_skill["plaintext"] == msg


def test_decrypt_requires_both_public_keys():
    a1, _, _, _ = _gen_instance(seed=21)
    with pytest.raises(MHKAttackError):
        decrypt_mhk2({"a1": a1}, [(1, 2)])


# --------------------------------------------------------------------------
# 4. 慢层：真实题目端到端（默认跳过，--run-slow 开启）
# --------------------------------------------------------------------------
REAL_FLAG = "CTF{faNNYPAcKs_ARe_4maZiNg_AnD_und3Rr@t3d}"


@pytest.mark.slow
def test_real_mhk2_end_to_end():
    """Google CTF 2023 MHK2 真实附件端到端（n=256，约 300s）。

    这是「工具链补齐后确实能解出外部公开真题」的真值证据，不放进默认 CI。
    """
    if not has_backend():
        pytest.skip("需要 python-flint")
    import ast

    path = ROOT / "data/questions_external/crypto/ext_gctf2023_mhk2/_attachments/output.txt"
    if not path.exists():
        pytest.skip(f"缺少题目附件：{path}")
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    pk, ct = ast.literal_eval(lines[0]), ast.literal_eval(lines[1])
    out = decrypt_mhk2({"a1": pk["a1"], "a2": pk["a2"]}, ct, verbose=True)
    assert out == REAL_FLAG, f"真实题解密不符：{out!r}"
