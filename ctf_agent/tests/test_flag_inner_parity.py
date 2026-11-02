# -*- coding: utf-8 -*-
r"""flag「花括号内文」判定口径一致性守卫（2026-11-01 审计）。

病灶
----
本仓有多处实现"从候选串里取 flag 内文再算 sha256"的逻辑，其中
`{...}` 的内文提取有的用**贪婪** `(.+)`、有的用**非贪婪** `(.+?)`。

对 `"flag{correct} (hint: {other})"` 这样的候选：
    贪婪   → 内文 = "correct} (hint: {other"  → 摘要与真值不符 → **判错**
    非贪婪 → 内文 = "correct"                  → 摘要与真值相符 → 判对

后果：审计/分层/导出脚本用贪婪实现时，会把**答对的题判成答错**，
从而系统性低估解题率——方向与 R106 修好的"无真值算通过"（高估）相反。

有一条自相矛盾的证据：`_audit_truth_consistency.matches_truth` 的 docstring
写着「与 `_stratify_external_benchmark.matches_truth` **完全同口径**（直接复用）」，
而它自己用的是非贪婪、被"复用"的那个是贪婪 —— 它自己就是漂移源。

为什么贪婪在这里一律是错的
--------------------------
flag 的语义决定内文不含花括号（`verify/flag_checker.validate` 里也明确
`f.count("{") != 1` 即拒绝）。既然内文不可能含 `}`，非贪婪就是唯一正确解。

`ctfplatform/dasctf.py` 的 `^(?:flag|...)\{(.+)\}$` 不在此列——它是**全串锚定**
（`^...$`），贪婪不会跨出结尾的 `}`，行为正确，不改。
"""
import os
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pytest

#: 必须用非贪婪的实现（文件 → 该文件里不应再出现贪婪写法）
LAZY_REQUIRED = [
    "scripts/_audit_corpus_integrity.py",
    "scripts/_stratify_external_benchmark.py",
    "scripts/_export_external_benchmark.py",
    "scripts/_audit_truth_consistency.py",
    "verify/flag_checker.py",
]

#: 全串锚定，贪婪无危害，明确豁免
ANCHORED_OK = [
    "ctfplatform/dasctf.py",
]

GREEDY = re.compile(r'\\\{\(\.\+\)\\\}')      # \{(.+)\}
LAZY = re.compile(r'\\\{\(\.\+\?\)\\\}')     # \{(.+?)\}


def _read(rel):
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as f:
        return f.read()


@pytest.mark.parametrize("rel", LAZY_REQUIRED)
def test_no_greedy_inner_brace_in_verdict_paths(rel):
    """判定路径上不得出现贪婪的内文提取。"""
    src = _read(rel)
    assert not GREEDY.search(src), (
        f"{rel} 仍有贪婪 \\{{(.+)\\}}：会把 'flag{{a}} (hint: {{b}})' 整段吃进去，"
        "导致答对的题被判错")


@pytest.mark.parametrize("rel", ANCHORED_OK)
def test_anchored_pattern_may_stay_greedy(rel):
    """全串锚定的实现允许贪婪 —— 但必须真的是锚定的。

    这条是**反向自检**：如果哪天有人把 `^...$` 去掉，贪婪立刻变危险，
    本测试会因找不到锚定符号而红。
    """
    src = _read(rel)
    greedy_lines = [ln for ln in src.splitlines() if GREEDY.search(ln)]
    assert greedy_lines, f"{rel} 里没有贪婪实现了？请同步本测试"
    for ln in greedy_lines:
        assert ln.strip().startswith("_") or "^" in ln, (
            f"{rel} 的贪婪写法未见锚定符号 ^：{ln.strip()[:80]}")


# ── 行为级：用真实候选串验证语义 ────────────────────────────────────────────
def _lazy_inner(cand: bytes) -> bytes:
    return re.search(rb"\{(.+?)\}", cand, re.DOTALL).group(1)


def _greedy_inner(cand: bytes) -> bytes:
    return re.search(rb"\{(.+)\}", cand, re.DOTALL).group(1)


def test_lazy_extracts_only_the_flag():
    cand = b"answer: flag{real_flag} (hint: {decoy})"
    assert _lazy_inner(cand) == b"real_flag"


def test_greedy_would_swallow_the_decoy():
    """记录贪婪的失败方式，作为回归证据。"""
    cand = b"answer: flag{real_flag} (hint: {decoy})"
    assert _greedy_inner(cand) != b"real_flag"


def test_flag_checker_accepts_flag_with_trailing_context():
    """端到端：`flag_checker` 对带上下文的候选必须判 True。

    R106 修的是"无真值算通过"（高估），这条修的是"答对被判错"（低估），
    两者都是判定口径问题。
    """
    from verify.flag_checker import sha256_matches
    import hashlib
    truth = hashlib.sha256(b"real_flag").hexdigest()
    cand = "answer: flag{real_flag} (hint: {decoy})"
    assert sha256_matches(cand, truth) is True
