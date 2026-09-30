"""presolve 答案校验闸（_passes_answer_check）与题面答案提取（_try_desc_answer）回归测试。

背景（2026-09-30，92 题全量审计 logs/presolve_audit_real92*.json）：
  P0-A  _passes_answer_check 一律按明文比对，sha256 占位制度下 presolve
        真命中被 100% 误杀（A 组真命中 71→4）。
  P0-B  _try_desc_answer 正则含裸 `is`/`=` 分支，英文题面任意 "is"
        （best lis|tened → flag{tened}）与 "e=1049"（→ flag{1049}）
        均产出假 flag；8 例假命中入账风险。
修复后本文件锁定双向行为：真命中必须放行、变异/垃圾必须拒绝。
"""
from __future__ import annotations

import hashlib
import asyncio
import sys
import os
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.presolve import _passes_answer_check, _try_desc_answer  # noqa: E402


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _q(qid: str = "t1", **kw):
    return SimpleNamespace(id=qid, **kw)


# ---------------------------------------------------------------- sha256 口径
class TestSha256AwareAnswerCheck:
    def test_true_flag_passes_sha256_check(self):
        """修复点：expected=sha256 占位时，真 flag 必须 sha256 命中放行。"""
        real = "flag{4640bbec-4abf-46db-a172-b74d308e552a}"
        answers = {"t1": _sha(real)}
        assert _passes_answer_check(_q(), real, answers) is True

    def test_mutated_flag_rejected(self):
        real = "flag{4640bbec-4abf-46db-a172-b74d308e552a}"
        answers = {"t1": _sha(real)}
        # 末字节变异
        assert _passes_answer_check(_q(), real + "x", answers) is False
        # 首字符变异
        assert _passes_answer_check(_q(), "X" + real[1:], answers) is False
        # 大小写翻转（CTF flag 大小写敏感）
        assert _passes_answer_check(_q(), real.upper(), answers) is False

    def test_decoy_flag_from_other_question_rejected(self):
        """跨题串扰场景：候选是别题的真 flag，sha256 必不符。"""
        answers = {"t1": _sha("flag{this_is_t1_truth}")}
        other = "VNCTF{TimeFl20211205ightMachine}"
        assert _passes_answer_check(_q(), other, answers) is False

    def test_sha256_shape_candidate_equal_to_expected_passes(self):
        """候选本身即 expected（64hex）保持旧行为：字符串相等直接放行。"""
        h = _sha("whatever")
        assert _passes_answer_check(_q(), h, {"t1": h}) is True

    def test_uppercase_sha256_expected_accepted(self):
        real = "flag{Case_Sensitive_Inner_123}"
        answers = {"t1": _sha(real).upper()}
        assert _passes_answer_check(_q(), real, answers) is True


# ---------------------------------------------------------------- 明文口径
class TestPlaintextAnswerCheck:
    def test_plaintext_match_passes(self):
        answers = {"t1": "flag{zip&crc_we_can_do_it}"}
        assert _passes_answer_check(_q(), "flag{zip&crc_we_can_do_it}", answers) is True

    def test_plaintext_mismatch_rejected(self):
        answers = {"t1": "flag{truth}"}
        assert _passes_answer_check(_q(), "flag{decoy}", answers) is False

    def test_whitespace_stripped_both_sides(self):
        answers = {"t1": "flag{abc}\n"}
        assert _passes_answer_check(_q(), "  flag{abc}  ", answers) is True


# ---------------------------------------------------------------- 放行边界
class TestPassThroughBoundaries:
    def test_answers_none_always_passes(self):
        """answers=None/{}：无闸（调用方自担），保持既有契约。"""
        assert _passes_answer_check(_q(), "flag{anything}", None) is True
        assert _passes_answer_check(_q(), "flag{anything}", {}) is True

    def test_unknown_question_id_passes(self):
        """answers 表不含本题：不拦截（闸只对已声明答案生效）。"""
        answers = {"other_q": _sha("flag{x}")}
        assert _passes_answer_check(_q("t1"), "flag{anything}", answers) is True

    def test_empty_expected_value_passes(self):
        assert _passes_answer_check(_q(), "flag{anything}", {"t1": ""}) is True


# ---------------------------------------------------------------- 题面提取
class TestDescAnswerExtraction:
    def _desc(self, desc: str, flag_pattern: str = ""):
        return _q(description=desc, flag_pattern=flag_pattern)

    def _run(self, q):
        return asyncio.run(_try_desc_answer(q))

    def test_answer_is_still_extracted(self):
        r = self._run(self._desc("Solve it. The answer is ABCD1234."))
        assert r == "flag{ABCD1234}"

    def test_the_answer_is_still_extracted(self):
        r = self._run(self._desc("the answer is FLAG_2026_WIN"))
        assert r == "flag{FLAG_2026_WIN}"

    def test_chinese_jiechu_still_extracted(self):
        r = self._run(self._desc("解出 ABCD1234 即可提交"))
        assert r == "flag{ABCD1234}"

    def test_chinese_answer_with_colon_still_extracted(self):
        r = self._run(self._desc("答案：abcd1234"))
        assert r == "flag{abcd1234}"

    # —— 修复点：裸 is / 裸 = 不再产出假 flag ——
    def test_bare_is_no_longer_produces_flag(self):
        """'best lis|tened' 曾产出 flag{tened}。"""
        assert self._run(self._desc("the best listened file is here")) is None

    def test_this_is_no_longer_produces_flag(self):
        """'th|is file' 曾产出 flag{file}（跨题污染实锤来源之一）。"""
        assert self._run(self._desc("this file contains a secret")) is None

    def test_equation_no_longer_produces_flag(self):
        """'e=1049' 曾产出 flag{1049}（changan2021_checkin 假命中来源）。"""
        assert self._run(self._desc("RSA 参数 e=1049，请解密")) is None

    def test_english_is_prefix_still_matched_by_answer_is(self):
        """确保删裸 is 未误伤 'answer is'（IGNORECASE 下 Answer is 也命中）。"""
        r = self._run(self._desc("The Answer is XyZ_1234_abcd"))
        assert r == "flag{XyZ_1234_abcd}"

    def test_self_mocking_sentence_not_extracted(self):
        """题面自嘲句（coolboy/722b6d 假命中来源）不得成为候选。"""
        desc = "good luck, the flag is i_am_not_right_but_i_believe_you_can"
        # 注：该句以 "flag is" 开头——裸 is 删除后 "flag is" 不再是提示词，
        # 但 "answer is" 才是合法提示词；此处应返回 None 或至少不产自嘲串。
        r = self._run(self._desc(desc))
        assert r is None or "i_am_not_right" not in r

    def test_dasctf_pattern_wrapper(self):
        r = self._run(self._desc("答案为 abcd1234", flag_pattern="DASCTF{}"))
        assert r == "dasctf{abcd1234}" or r == "DASCTF{abcd1234}" or "dasctf" in r.lower()

    def test_short_description_ignored(self):
        assert self._run(self._desc("ab")) is None
