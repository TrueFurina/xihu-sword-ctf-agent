# -*- coding: utf-8 -*-
"""多层编码解码：顺序特异性与跨区一致性守卫（2026-11-01 审计 R118）。

病灶一：**解码顺序**
    `_try_decode` / `_try_base_decode` 原来按 Base64 → Base32 → Base16 尝试。

    但 **hex 的字符集是 base64 的字符集真子集**（0-9a-f 全在 base64 字母表里），
    所以纯 hex 串会先被 Base64 分支"成功"解码成乱码并提前 return：

        输入 "666c61677b6865787d"
        Base64 先试 → '뮜�^�������'      ← isprintable 部分通过，直接 return
        正确的 Base16 → 'flag{hex}'

    修复：按**特异性从高到低**——Base16（全 hex + 偶数长，最严格）
    → Base32（大写字母表 + 长度约束）→ Base64（最宽松）。

病灶二：**同一功能两处实现**
    同一函数体出现在 `skills/base64_multilayer.py` 与
    `tools/adapters/deterministic_decode_adapter.py`——一处走 CTF 解题链路，
    一处走工具调用链路。改一边漏另一边就是行为漂移。

    另有一份更完整的 `agents/crypto_toolkit._inline_multilayer_decode`
    （含 ROT13 收尾 + 多层循环），注释写着"替代有 bug 的 base64_multilayer"。
"""
import base64
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pathlib
import re

import pytest

SKILL = pathlib.Path(_ROOT) / "skills" / "base64_multilayer.py"
ADAPTER = pathlib.Path(_ROOT) / "tools" / "adapters" / "deterministic_decode_adapter.py"


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


# ── 源码级：顺序必须是 16 → 32 → 64 ────────────────────────────────────────
@pytest.mark.parametrize("path,name", [
    (SKILL, "base64_multilayer"),
    (ADAPTER, "deterministic_decode_adapter"),
])
def test_decode_order_is_most_specific_first(path, name):
    """Base16 分支必须出现在 Base64 分支之前。

    变异验证：把顺序改回 Base64 优先，本测试变红。
    """
    # ⚠️ 不能用注释标记定位——_strip_comments 会把 `# Base16` 一起剥掉
    # （第一版就是这么失败的）。改用**代码特征**定位各分支。
    code = _strip_comments(path.read_text(encoding="utf-8"))
    markers = {
        "16": "bytes.fromhex",       # Base16：用 fromhex 而非 b16decode
        "32": "b32decode",
        "64": "b64decode",
    }
    pos = {}
    for k, m in markers.items():
        i = code.find(m)
        assert i >= 0, f"{name} 缺 Base{k} 分支（找不到 {m}）"
        pos[k] = i
    assert pos["16"] < pos["64"], (
        f"{name} 的 Base16 分支应在 Base64 之前（否则 hex 被 base64 抢先误解码）")
    assert pos["32"] < pos["64"], f"{name} 的 Base32 分支应在 Base64 之前"


# ── 行为级：hex 必须解对 ───────────────────────────────────────────────────
def test_skill_decodes_hex_correctly():
    """纯 hex 串必须解出明文，不能被 base64 抢先误解码。"""
    from skills.base64_multilayer import _try_decode
    assert _try_decode("666c61677b6865787d") == "flag{hex}"


def test_skill_still_decodes_base64_and_base32():
    """反向自检：改顺序不能把 base64/base32 弄坏。"""
    from skills.base64_multilayer import _try_decode
    assert _try_decode(base64.b64encode(b"flag{hello}").decode()) == "flag{hello}"
    assert _try_decode(base64.b32encode(b"flag{b32}").decode()) == "flag{b32}"


def test_adapter_decodes_hex_correctly():
    from tools.adapters.deterministic_decode_adapter import DeterministicDecodeAdapter
    a = DeterministicDecodeAdapter()
    assert a._try_base_decode("666c61677b6865787d") == "flag{hex}"


# ── 跨区一致：两处实现必须同行为 ───────────────────────────────────────────
CASES = [
    ("hex", "666c61677b6865787d"),
    ("base64", base64.b64encode(b"flag{hello}").decode()),
    ("base32", base64.b32encode(b"flag{b32}").decode()),
    ("空串", ""),
    ("非编码文本", "just some plain text"),
]


@pytest.mark.parametrize("label,text", CASES)
def test_two_implementations_agree(label, text):
    """skills 与 adapter 两条链路的解码结果必须一致。

    它们服务不同入口（CTF solver / 工具调用），一旦漂移，
    同一个输入在两条路径上会给出不同答案。
    """
    from skills.base64_multilayer import _try_decode
    from tools.adapters.deterministic_decode_adapter import DeterministicDecodeAdapter
    a = DeterministicDecodeAdapter()

    if label == "空串":
        # 空串时 skill 返回 None、adapter 返回 None —— 语义相同
        assert _try_decode(text) is None
        assert a._try_base_decode(text) is None
        return

    r_skill = _try_decode(text)
    r_adapter = a._try_base_decode(text)
    assert r_skill == r_adapter, (
        f"{label}: skills={r_skill!r} vs adapter={r_adapter!r} —— 两处实现漂移")


def test_richer_implementation_handles_multilayer_and_rot13():
    """crypto_toolkit 的版本多了 ROT13 与多层循环——记录能力边界。

    这两项是 skills/base64_multilayer 没有的（它的调用方需要另做循环）。
    本条不是要求补齐，而是**把差异写成断言**，避免有人以为三者等价。
    """
    from agents.crypto_toolkit import _inline_multilayer_decode as rich
    two_layer = base64.b64encode(base64.b64encode(b"flag{nested}")).decode()
    assert rich(two_layer) == "flag{nested}"

    rot13_wrapped = base64.b64encode(b"synt{ebg13}").decode()
    assert rich(rot13_wrapped) == "flag{rot13}"

    # 单层版不做这两件事——但也不该给出**错误**答案
    from skills.base64_multilayer import _try_decode
    assert _try_decode(two_layer) is not None      # 能解一层
    assert "flag{nested}" not in _try_decode(two_layer)  # 但解不到底
