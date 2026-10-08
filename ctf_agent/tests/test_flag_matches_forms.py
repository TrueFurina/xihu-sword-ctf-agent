# -*- coding: utf-8 -*-
"""`Question.flag_matches` 三种真值形态全覆盖 + 「flag=None+flag_sha256 恒 False」回归锁。

背景（2026-10-08 实测发现的生产 bug）：
  `flag_matches` 原实现把分支 gate 在 `flag_is_placeholder`（要求 `flag` 字段**本身**
  是 sha256 串）。于是合法形态「`flag=None` + 只有 `flag_sha256`」落进明文分支、
  与 `None` 比对 → **恒 False**。而 `run.py:387` 生产判分正走此路径 ⇒ 该形态的任何
  正确答案被自己的验证器判 `hallucination`。全库形态实测 `(None,set)=79` 题受影响。

本测试锁两条：
  A. 三种形态各自正确（正确候选 True / 错误候选 False）；
  B. 回归：`flag=None` + `flag_sha256` 且候选 sha256 吻合 → **必须 True**（改回原实现即红）。
"""
import hashlib
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from eval.cases import Question  # noqa: E402


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _q(**kw) -> Question:
    base = {"id": "t1", "title": "t", "category": "crypto",
            "description": "", "attachments": []}
    base.update(kw)
    return Question.from_dict(base)


PLAIN = "flag{plain_text_here}"
SHA_OF_PLAIN = _sha(PLAIN)


class TestThreeTruthForms:
    """三种合法形态 + 一种无真值形态。"""

    def test_plain_flag_no_sha_uses_plaintext(self):
        q = _q(flag=PLAIN)                      # (plain, none)
        assert q.flag_matches(PLAIN) is True
        assert q.flag_matches("flag{wrong}") is False

    def test_sha256_placeholder_flag_uses_sha(self):
        q = _q(flag=SHA_OF_PLAIN)               # (sha256, none→flag 本身是占位)
        assert q.flag_matches(PLAIN) is True
        assert q.flag_matches("flag{wrong}") is False

    def test_none_flag_with_flag_sha256_uses_sha(self):
        """★ 本次修复对象：flag=None + flag_sha256。"""
        q = _q(flag=None, flag_sha256=SHA_OF_PLAIN)   # (None, set)
        assert q.flag_matches(PLAIN) is True
        assert q.flag_matches("flag{wrong}") is False

    def test_both_sha256_fields(self):
        q = _q(flag=SHA_OF_PLAIN, flag_sha256=SHA_OF_PLAIN)  # (sha256, set)
        assert q.flag_matches(PLAIN) is True

    def test_no_truth_at_all_never_matches(self):
        q = _q(flag=None)                        # (None, none)
        assert q.flag_matches(PLAIN) is False
        assert q.flag_matches("") is False
        assert q.flag_matches(None) is False

    def test_flag_sha256_takes_priority_over_stale_plain_flag(self):
        """`expected_sha256` 的既定优先级：有 flag_sha256 时以它为准。"""
        q = _q(flag="flag{stale}", flag_sha256=SHA_OF_PLAIN)
        assert q.flag_matches(PLAIN) is True          # 以 sha 为准
        assert q.flag_matches("flag{stale}") is False  # 旧明文不再算对


class TestRegressionNoneFlagHangFalse:
    """回归锁：三种形态的『正确候选』都必须 True——任何一条退回恒 False 即红。"""

    @pytest.mark.parametrize("kw", [
        {"flag": PLAIN},
        {"flag": SHA_OF_PLAIN},
        {"flag": None, "flag_sha256": SHA_OF_PLAIN},
        {"flag": SHA_OF_PLAIN, "flag_sha256": SHA_OF_PLAIN},
    ])
    def test_correct_candidate_always_matches(self, kw):
        q = _q(**kw)
        assert q.flag_matches(PLAIN) is True, f"形态 {kw} 的正确候选被判 False（回归）"

    def test_none_flag_form_would_fail_under_old_impl(self):
        """说明性：`flag_is_placeholder` 为 False 时，旧实现走明文分支必假。
        本断言文档化当初的失效条件——若有人把实现改回 gate 在 flag_is_placeholder，本类红。"""
        q = _q(flag=None, flag_sha256=SHA_OF_PLAIN)
        assert q.flag_is_placeholder is False   # 旧实现的前提
        assert q.expected_sha256 == SHA_OF_PLAIN
        assert q.flag_matches(PLAIN) is True    # 新实现不受该前提影响


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
