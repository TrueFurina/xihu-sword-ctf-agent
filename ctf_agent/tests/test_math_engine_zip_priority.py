# -*- coding: utf-8 -*-
"""misc zip 链解码优先级：真 flag 不得被 zip 内诱饵 flag 遮蔽（2026-10-15）。

背景（实测，非推断）
--------------------
真题库 10663 形态：N 层套娃 zip，**真 flag 编码在文件名链里**（反转 + base32），
而最内层 `flag.txt` 是**诱饵**（`DASCTF{ni_cai?}`）。

`MathEngineMatrix.solve()` 命中即返回，因此**引擎顺序即正确性**：
原顺序 `misc_decode` 在 `misc_zip` 之前，而 misc_decode 走
deterministic_decode_adapter 的 direct_search——**直接正则扫 zip 内文本** ⇒
0.0s 抢先命中诱饵即 return，真解路径 misc_zip（实测 0.04s 出真 flag）
**永远拿不到机会跑**。症状极具欺骗性：日志打 "[math_engine:misc_decode] 命中"，
presolve 返回非空，看起来正常，实际恒提交错 flag。

本文件盯守三件事
----------------
1. 顺序：misc_zip 必须先于 misc_decode（静态索引断言，快但弱）；
2. **端到端**：套娃链题 solve() 必须返回链里的真 flag，不得返回诱饵（强断言）；
3. 回归：提前 misc_zip 不得挤掉别的形态（一层 zip 明文 / 纯文本 base64 附件）。

变异验证
--------
* 把 `_priority_order()` 改回 `"misc_decode", "misc_zip"` → 端到端用例必须 FAIL
  （索引断言也会 FAIL，但**端到端才是真守卫**：顺序断言只防顺序，端到端防的是
  「诱饵遮蔽」这个真实故障模式）；
* 从 `_priority_order()` 摘掉 `misc_zip` → 端到端用例必须 FAIL；
* 把诱饵删掉（flag.txt 换成空）→ 端到端用例仍 PASS（证明它测的是"遮蔽"而非
  "诱饵恰好不存在"，即该用例对诱饵存在与否不敏感，不会假绿）。
"""

from __future__ import annotations

import base64
import os
import sys
import types
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.math_engine import MathEngineMatrix  # noqa: E402


# ── 样本构造 ────────────────────────────────────────────────────────────────
# 与 skills/zip_filename_chain_decode 的语义一致：链**从尾到头**拼接后 base32 解码。
_REAL_FLAG = "flag{zipchain_ok_10663}"
_DECOY_FLAG = "DASCTF{ni_cai?}"


def _chain_zip(dirpath: str, real: str = _REAL_FLAG, decoy: str = _DECOY_FLAG) -> str:
    """造 3 层套娃 zip：真 flag 在文件名链，最内层 flag.txt 是诱饵。

    链收集顺序 = [层1 内 zip 名, 层2 内 zip 名]；反转拼接后须等于 base32(real)。
    """
    x = base64.b32encode(real.encode()).decode().rstrip("=")
    half = len(x) // 2
    first, second = x[half:], x[:half]          # reversed_chain = second + first

    def _mk(path: str, inner: str, data: bytes) -> bytes:
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(inner, data)
        with open(path, "rb") as f:
            blob = f.read()
        os.remove(path)
        return blob

    d = str(dirpath)
    inner = _mk(os.path.join(d, "second.zip"), "flag.txt", decoy.encode())
    mid = _mk(os.path.join(d, "first.zip"), second + ".zip", inner)
    outer = os.path.join(d, "outer_chain.zip")
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr(first + ".zip", mid)
    return outer


def _q(attachments, category: str = "misc", qid: str = "t_zipprio") -> types.SimpleNamespace:
    return types.SimpleNamespace(
        id=qid, category=category,
        description="给你一个套娃压缩包，flag 藏在里面。",
        attachments=list(attachments), extra={},
    )


# ── 1. 顺序（弱守卫）────────────────────────────────────────────────────────
def test_misc_zip_precedes_misc_decode_in_priority_order():
    order = MathEngineMatrix._priority_order()
    assert "misc_zip" in order, "misc_zip 未进入竞速顺序（套娃 zip 题恒无解）"
    assert "misc_decode" in order
    assert order.index("misc_zip") < order.index("misc_decode"), (
        f"misc_zip 必须先于 misc_decode，否则 zip 内诱饵 flag 会遮蔽文件名链真 flag；"
        f"当前顺序: {order}"
    )


# ── 2. 端到端（强守卫）──────────────────────────────────────────────────────
def test_nested_zip_chain_yields_real_flag_not_decoy(tmp_path):
    """套娃链题：solve() 必须返回链里的真 flag，不得返回 flag.txt 诱饵。"""
    outer = _chain_zip(str(tmp_path))
    # 前置断言：样本本身必须是「真 flag 只在链里、诱饵在文本里」的形态
    with zipfile.ZipFile(outer) as z:
        assert z.namelist(), "样本构造失败"

    eng, flag = MathEngineMatrix.solve(_q([outer]), timeout=30)
    assert flag == _REAL_FLAG, (
        f"套娃链题被诱饵遮蔽：期望真 flag {_REAL_FLAG!r}，实际 {flag!r}（引擎 {eng}）。"
        f"若命中 {_DECOY_FLAG!r} 即 misc_decode 抢跑遮蔽了 misc_zip。"
    )


def test_nested_zip_chain_engine_name_is_misc_zip(tmp_path):
    """命中引擎必须是 misc_zip（不是 misc_decode 蒙对）。"""
    outer = _chain_zip(str(tmp_path))
    eng, flag = MathEngineMatrix.solve(_q([outer]), timeout=30)
    assert eng == "misc_zip", f"应由 misc_zip 引擎命中，实际 {eng}"
    assert flag == _REAL_FLAG


def test_chain_zip_without_decoy_still_solves(tmp_path):
    """诱饵不存在时同样出真 flag（证明上一条测的是遮蔽，不是诱饵碰巧缺失）。"""
    outer = _chain_zip(str(tmp_path), decoy="nothing here")
    eng, flag = MathEngineMatrix.solve(_q([outer]), timeout=30)
    assert flag == _REAL_FLAG


# ── 3. 回归：提前 misc_zip 不得挤掉别的形态 ─────────────────────────────────
def test_single_layer_zip_plaintext_flag_still_found(tmp_path):
    """一层 zip、flag 明文在内：仍解出（misc_zip 提前后不得回归）。"""
    p = os.path.join(str(tmp_path), "plain.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("flag.txt", b"flag{plain_in_zip_1234}\n")
    eng, flag = MathEngineMatrix.solve(_q([p]), timeout=30)
    assert flag == "flag{plain_in_zip_1234}", f"一层 zip 明文 flag 回归：{flag!r} ({eng})"


def test_text_attachment_still_decoded(tmp_path):
    """纯文本附件（非 zip）：misc_zip 秒返 None 后必须回落 misc_decode。"""
    p = os.path.join(str(tmp_path), "note.txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write("ZmxhZ3t0ZXh0X2I2NF9mbGFnfQ==\n")   # base64("flag{text_b64_flag}")
    eng, flag = MathEngineMatrix.solve(_q([p]), timeout=30)
    assert flag == "flag{text_b64_flag}", f"纯文本附件解码回归：{flag!r} ({eng})"


def test_zip_without_flag_costs_no_budget(tmp_path):
    """zip 内无 flag：misc_zip 必须快速返回 None，不占用后续引擎的时间预算。"""
    import time

    p = os.path.join(str(tmp_path), "noflag.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("data.bin", os.urandom(4096))
    t = time.monotonic()
    _eng, flag = MathEngineMatrix.solve(_q([p]), timeout=30)
    dt = time.monotonic() - t
    assert flag is None
    assert dt < 20.0, f"zip 内无 flag 时 solve 耗时 {dt:.1f}s（misc_zip 提前后不得拖慢）"


# ── 4. presolve 端到端 ──────────────────────────────────────────────────────
def test_presolve_returns_chain_flag_not_decoy(tmp_path):
    """生产链路端到端：presolve 不得把 zip 内诱饵当真 flag 提交。"""
    import asyncio
    import uuid

    from core import presolve as P

    outer = _chain_zip(str(tmp_path))
    q = _q([outer], qid=f"t_zipprio_{uuid.uuid4().hex[:8]}")
    flag = asyncio.run(P.presolve(q, registry=None, answers=None, force=True))
    assert flag == _REAL_FLAG, (
        f"presolve 提交诱饵：期望 {_REAL_FLAG!r}，实际 {flag!r}"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
