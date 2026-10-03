# -*- coding: utf-8 -*-
"""核心格工具：LLL 格基约减 + **饱和**整数核。

为什么必须走 C 后端
--------------------
CTF crypto 里的格题条目动辄 100+ bit（MHK2 是 136 bit × 256 维）。
浮点 Gram-Schmidt 的纯 Python LLL 在这个量级上精度彻底崩溃，
会**静默返回「看起来约减过」的错基**——比直接报错危险得多
（记忆教训：「装上了 ≠ 能用」）。

因此本模块：
  * 优先使用 ``python-flint``（C 实现，255×256/136bit 的 LLL 实测 0.32s）；
  * 无后端时**明确抛 ``LatticeBackendMissing``**，绝不静默降级到浮点 LLL。

为什么强调「饱和」核
--------------------
``flint`` 的 ``fmpz_mat.nullspace()`` 返回的是**非饱和**基（各行带大公因子），
直接用会让格的指数暴涨、LLL 完全失效——实测 255 维格 LLL 后范数是 2^134
而不是理论值 2^4，攻击直接失败。
正确做法见 :func:`saturated_kernel`：转置 + HNF(transform=True)，
取右变换中「对应零行」的列构造饱和核。

用法::

    from core.lattice import lll, saturated_kernel
    basis = saturated_kernel([a])      # {x : <a,x> = 0} 的饱和整数基
    short = lll(basis)                 # 约减后的短向量
"""

from __future__ import annotations

from typing import List, Sequence

__all__ = [
    "LatticeBackendMissing",
    "has_backend",
    "require_backend",
    "lll",
    "saturated_kernel",
    "dot",
    "norm2_bits",
    "kernel_satisfies",
]

#: 纯 Python 兜底一旦放开就会静默算错，故此处硬编码为「不支持」。
_PURE_PYTHON_LLL_SUPPORTED = False


class LatticeBackendMissing(RuntimeError):
    """无可用格后端（python-flint 未安装）。

    刻意不提供浮点兜底：在 ≥100 bit 条目上浮点 LLL 会静默产出错误结果。
    """


def has_backend() -> bool:
    """python-flint 是否可用。"""
    try:
        import flint  # noqa: F401
    except Exception:
        return False
    return True


def require_backend() -> None:
    """确保后端可用，否则抛 :class:`LatticeBackendMissing`。"""
    if not has_backend():
        raise LatticeBackendMissing(
            "格运算需要 python-flint（pip install python-flint）。"
            "本模块刻意不提供浮点兜底：100+ bit 条目的浮点 LLL 会静默算错。"
        )


def _as_mat(rows: Sequence[Sequence[int]]):
    """把行向量列表转成 fmpz_mat（顺带做 int 归一化）。"""
    from flint import fmpz_mat

    return fmpz_mat([[int(x) for x in row] for row in rows])


def lll(rows: Sequence[Sequence[int]]) -> List[List[int]]:
    """LLL 约减（行向量输入 → 行向量输出）。

    Args:
        rows: 行向量（整数）。列数可大于行数（嵌入格）。
    Returns:
        约减后的行向量列表，条目均为 Python int。

    Raises:
        LatticeBackendMissing: 无 python-flint。
    """
    require_backend()
    if not rows:
        return []
    return [[int(x) for x in row] for row in _as_mat(rows).lll().tolist()]


def saturated_kernel(rows: Sequence[Sequence[int]]) -> List[List[int]]:
    """``{x : rows @ x = 0}`` 的**饱和**整数基（行向量）。

    饱和 = ``Z^n ∩ span_Q(rows)`` 的核，即核里不漏掉"整点除以公因子"的那些点。
    flint 的 ``nullspace()`` 给的是非饱和基，这正是攻击失败的经典坑，故此处
    走「转置 + HNF(transform=True)」：

        H = M^T · T   （T 为右变换，幺模）
        H 的零行 → T 中对应列即为核向量；HNF 保证结果饱和。

    Args:
        rows: m×n 整数矩阵（行向量），求右核。
    Returns:
        核的饱和基（行向量），行数 = n - rank。
    """
    require_backend()
    if not rows:
        return []
    m, n = len(rows), len(rows[0])
    # 转置：M^T 是 n×m，其行 = 原矩阵的列
    mt = [[int(rows[i][j]) for i in range(m)] for j in range(n)]
    H, T = _as_mat(mt).hnf(transform=True)
    ht, tt = H.tolist(), T.tolist()
    zero_rows = [j for j in range(n) if all(ht[j][i] == 0 for i in range(m))]
    return [[int(tt[i][j]) for j in range(n)] for i in zero_rows]


def dot(x: Sequence[int], y: Sequence[int]) -> int:
    """整数内积。"""
    return sum(int(a) * int(b) for a, b in zip(x, y))


def norm2_bits(v: Sequence[int]) -> int:
    """||v||^2 的位长（诊断用：判断 LLL 是否真的把基约短了）。"""
    return sum(int(x) * int(x) for x in v).bit_length()


def kernel_satisfies(rows: Sequence[Sequence[int]],
                     basis: Sequence[Sequence[int]]) -> bool:
    """校验 basis 中每个向量都满足 rows @ v = 0。"""
    return all(all(dot(r, v) == 0 for r in rows) for v in basis)
