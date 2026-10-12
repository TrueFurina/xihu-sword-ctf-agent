"""thoroughlystripped presolve skill 回归测试（2026-10-08）。

锁定「null 字节剥离 ELF 的确定性字节级恢复」——从被剥离全部 null 字节的 ELF64
（CSAW-Finals 2017 thoroughlyStripped）恢复 flag，并以题面 sha256 闭环校验。

验证口径：仅比对 sha256（不依赖题面明文 flag 字面量），防止解题器静默退化。
零外部依赖、零付费调用、零网络。
"""

import hashlib
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from skills import thoroughlystripped as ts  # noqa: E402

# 题面声明的真值 sha256（外部题池：flag 字段即 64hex 占位）。
_EXPECTED_SHA256 = "4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1"

# 二进制附件候选路径（相对 ctf_agent 根；兼容不同 checkout 布局）。
_CANDIDATES = [
    os.path.join(_ROOT, "data", "questions_ext", "_attachments", "forensics",
                 "2017f-for-thoroughlystripped", "thoroughlyStripped"),
    os.path.join(os.getcwd(), "data", "questions_ext", "_attachments", "forensics",
                 "2017f-for-thoroughlystripped", "thoroughlyStripped"),
]


def _binary_path():
    for p in _CANDIDATES:
        if os.path.isfile(p):
            return p
    return None


@pytest.mark.skipif(_binary_path() is None,
                    reason="thoroughlyStripped 附件不在本地（questions_ext 未下载）")
def test_thoroughlystripped_recovers_flag():
    """确定性恢复 flag 且 sha256 闭环匹配题面真值。"""
    path = _binary_path()
    r = ts.run({"path": path})
    assert r.get("ok") is True, f"skill 返回非 ok：{r}"
    flag = r.get("flag") or ""
    assert flag.startswith("flag{") and flag.endswith("}"), f"格式异常：{flag!r}"
    assert r.get("sha256") == _EXPECTED_SHA256, "sha256 与题面真值不符（解题器可能退化）"
    assert r.get("verified") is True


def test_thoroughlystripped_wrong_path_is_honest():
    """路径缺失时如实返回 ok=False，不谎报命中。"""
    r = ts.run({"path": ""})
    assert r.get("ok") is False
    r2 = ts.run({"path": "/nonexistent/does_not_exist_xyz"})
    assert r2.get("ok") is False
