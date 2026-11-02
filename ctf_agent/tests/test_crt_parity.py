# -*- coding: utf-8 -*-
"""CRT 三处实现的语义分工守卫（2026-11-01 审计 R117）。

背景
----
同一概念「中国剩余定理」在本仓有三处实现，语义不同：

    skills/crypto_hastad_broadcast.py::_crt   任意个数；允许非互素（gcd 降模）；
                                             无解返回 None
    scripts/_solve_10733.py::crt              仅 2 个；前提互素；非互素抛 ValueError
    skills/crypto_high_exponent.py::_crt      仅 2 个；前提互素；非互素抛 ValueError

发现方式：按函数体指纹扫全仓，`_crt`/`crt` 体完全相同的两处被识别为同一概念。

风险
----
两模数版本**依赖调用方保证互素**。当前两处调用方都是 RSA 的 (p, q)（不同素数，
必然互素），所以安全——但这是**调用方的保证，不是函数的保证**。
换个人拿它合并非互素模数，会拿到异常而非正确答案。

原本没有任何提示。现在两处都：
  · 在 docstring 写明「前提：gcd(m1, m2) == 1」
  · 非互素时抛带指引的 ValueError（指向通用版本）
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pathlib

import pytest


def _src(rel):
    return (pathlib.Path(_ROOT) / rel).read_text(encoding="utf-8")


def _strip_comments(txt):
    out = []
    for ln in txt.splitlines():
        q = False
        cut = None
        for j, c in enumerate(ln):
            if c in ("'", '"'):
                q = not q
            elif c == "#" and not q:
                cut = j
                break
        out.append(ln[:cut] if cut is not None else ln)
    return "\n".join(out)


# ── 源码级：两模数版本必须声明互素前提 ─────────────────────────────────────
@pytest.mark.parametrize("rel,fn", [
    ("scripts/_solve_10733.py", "def crt("),
    ("skills/crypto_high_exponent.py", "def _crt("),
])
def test_two_modulus_crt_declares_coprime_precondition(rel, fn):
    """两模数 CRT 必须在 docstring 里写明互素前提。"""
    src = _src(rel)
    i = src.find(fn)
    assert i != -1, f"{rel} 里找不到 {fn}"
    head = src[i:i + 900]
    assert "gcd(m1, m2) == 1" in head or "要求模数互素" in head, \
        f"{rel} 的两模数 CRT 未声明互素前提"


@pytest.mark.parametrize("rel,fn", [
    ("scripts/_solve_10733.py", "def crt("),
    ("skills/crypto_high_exponent.py", "def _crt("),
])
def test_two_modulus_crt_guards_non_coprime(rel, fn):
    """非互素时必须抛带指引的 ValueError，而不是让 pow() 抛原始错误。"""
    code = _strip_comments(_src(rel))
    i = code.find(fn)
    body = code[i:i + 1600]
    assert "raise ValueError" in body, f"{rel} 的非互素分支没有显式抛 ValueError"
    assert ("互素" in body) or ("gcd" in body), f"{rel} 的报错未说明原因"
    assert "crypto_hastad_broadcast" in body, \
        f"{rel} 的报错未指向通用版本（用户不知道去哪找）"


def test_general_crt_still_exists():
    """通用版本必须仍在，且保留「无解返回 None」的语义。"""
    code = _strip_comments(_src("skills/crypto_hastad_broadcast.py"))
    assert "def _crt(" in code
    assert "residues" in code and "moduli" in code, "通用版本签名变了"
    assert "return None" in code, "通用版本丢了『无解返回 None』的语义"


# ── 行为级：三处对同一输入的行为必须符合各自约定 ───────────────────────────
def test_two_modulus_raises_on_non_coprime():
    """两模数版：非互素 → ValueError。"""
    src = _src("skills/crypto_high_exponent.py")
    ns = {"__name__": "probe"}
    # 只执行 _crt 定义（该文件顶层只有函数定义与 if __name__ 守卫）
    import ast
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_crt":
            exec(compile(ast.Module([node], []), "<c>", "exec"), ns)
            break
    crt2 = ns["_crt"]
    assert crt2(2, 3, 3, 5) == 8          # 互素：正常求解

    # ⚠️ 不能只断言 `pytest.raises(ValueError)`——去掉我们的检查后，
    # `pow(m1, -1, m2)` 自己也会抛 ValueError（"base is not invertible"），
    # 测试照样通过（实测确认：第一版就是这样空转的）。
    # 必须断言**我们自己的**报错特征：含「互素」且指向通用版本。
    with pytest.raises(ValueError) as ei:
        crt2(2, 6, 5, 9)
    msg = str(ei.value)
    assert "互素" in msg, f"抛的不是我们加的守卫，而是底层错误: {msg}"
    assert "crypto_hastad_broadcast" in msg, f"报错未指向通用版本: {msg}"


def test_general_crt_handles_non_coprime():
    """通用版本：非互素但一致 → 能解；不一致 → None。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "hastad", os.path.join(_ROOT, "skills", "crypto_hastad_broadcast.py"))
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:                      # 缺第三方依赖时跳过
        pytest.skip("crypto_hastad_broadcast 依赖缺失")

    got = mod._crt([2, 5], [6, 9])         # gcd=3, 2≡5 mod 3 → 有解
    assert got is not None
    assert got[1] == 18
    assert mod._crt([1, 2], [4, 6]) is None, "不一致时必须返回 None（不是抛异常）"
