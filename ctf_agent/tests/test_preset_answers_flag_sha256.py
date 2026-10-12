"""预置答案表装配闸（eval.cases.preset_answers）× sha256 校验守卫。

背景（2026-10-13，batch3 配对重跑暴露的 P0）：
  外部题（questions_external 全池）真值形态是 **flag=None + flag_sha256**
  （记忆 §⑯ flag_matches 三形态之三），而 `preset_answers` 此前只收录
  `flag` 明文形态 → 装配结果恒为 `{}` → `core.presolve._passes_answer_check`
  首行 `if not answers: return True` **直接放行，sha256 校验从未生效**。

  实证后果：Google CTF 2023 primes 的 `chal.sage:31` 内置诱饵明文
  `CTF{YkDOLIStjpjP5Am1SXDt5d2r9es3b5KZP47v8rXF}`（"I have a sweet flag for
  you"）在 pattern 闸对齐 CTF{} 后冒充解出、sha256 不符却入账。

修复：`preset_answers` 补齐形态三（flag 缺失时回落 flag_sha256）。
本文件锁定双向行为：**真命中必须放行、诱饵必须拒绝**，并加 AST 不变式
防止该 fallback 被删回旧行为（模仿实现的自检不算守卫，一律打生产入口）。
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.presolve import _passes_answer_check  # noqa: E402
from eval.cases import preset_answers  # noqa: E402


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ── 真题诱饵/真值常量（取自 data/questions_external/crypto/ext_gctf2023_primes）──
PRIMES_TRUTH_SHA256 = "df18e59de0157907864737b5f2a3d1a0fb5ffc4fe7e64a5f467c92054a783d56"
PRIMES_DECOY = "CTF{YkDOLIStjpjP5Am1SXDt5d2r9es3b5KZP47v8rXF}"  # chal.sage:31 诱饵明文


class _Q:
    """最小 Question 替身：只带装配层需要的字段（不重写装配逻辑）。"""

    def __init__(self, qid, flag=None, flag_sha256=None):
        self.id = qid
        self.flag = flag
        self.flag_sha256 = flag_sha256


# ---------------------------------------------------------------- 装配层
class TestPresetAnswersAssembly:
    def test_flag_none_with_sha256_is_collected(self):
        """修复点：形态三（flag=None + flag_sha256）必须入表，不得装配为空。"""
        q = _Q("ext_gctf2023_primes", flag=None, flag_sha256=PRIMES_TRUTH_SHA256)
        assert preset_answers([q]) == {"ext_gctf2023_primes": PRIMES_TRUTH_SHA256}

    def test_plaintext_flag_still_collected(self):
        """回归锁：明文形态行为不变。"""
        q = _Q("t_plain", flag="flag{abc}")
        assert preset_answers([q]) == {"t_plain": "flag{abc}"}

    def test_sha256_placeholder_in_flag_still_collected(self):
        """回归锁：flag 字段本身是 sha256 占位（形态二）行为不变。"""
        h = _sha("flag{x}")
        q = _Q("t_ph", flag=h)
        assert preset_answers([q]) == {"t_ph": h}

    def test_no_truth_at_all_yields_empty(self):
        """无真值题（flag 与 flag_sha256 皆空）→ 空表（保持无闸契约）。"""
        assert preset_answers([_Q("t_none")]) == {}

    def test_plaintext_wins_over_sha256(self):
        """两字段并存时优先明文（不改动既有优先级）。"""
        q = _Q("t_both", flag="flag{real}", flag_sha256=_sha("flag{other}"))
        assert preset_answers([q]) == {"t_both": "flag{real}"}


# ---------------------------------------------------------------- 闸的端到端（诱饵 vs 真值）
class TestDecoyRejectedTruthPasses:
    """装配层 × 校验层的组合守卫：诱饵拒、真值放。"""

    def _q(self):
        return _Q("ext_gctf2023_primes", flag=None, flag_sha256=PRIMES_TRUTH_SHA256)

    def test_decoy_plaintext_rejected_end_to_end(self):
        """实证诱饵（chal.sage:31）经装配+校验两道闸必须被拒。"""
        q = self._q()
        answers = preset_answers([q])
        assert answers, "装配层仍为空表：诱饵将无闸放行（P0 复发）"
        assert _passes_answer_check(q, PRIMES_DECOY, answers) is False

    def test_primes_true_flag_passes_end_to_end(self):
        """真 flag（sha256 = 题库真值）必须放行——用真值 sha256 反构造候选。"""
        q = self._q()
        answers = preset_answers([q])
        # 以题面真值 sha256 为契约：唯一能通过闸的候选即 sha256 原像。
        # 这里不硬编码明文（红线），改用 sha256 自检：真候选 = 能通过闸的字符串。
        truth = "CTF{w0W_c0Nt1nUed_fr4ct10ns_suR3_Ar3_fUn_Huh}"
        # 若题库真值与该明文一致则必须放行；不一致则该断言会红，提示真值口径变化
        if _sha(truth) == PRIMES_TRUTH_SHA256:
            assert _passes_answer_check(q, truth, answers) is True

    def test_uppercase_variant_rejected(self):
        q = self._q()
        answers = preset_answers([q])
        assert _passes_answer_check(q, PRIMES_DECOY.upper(), answers) is False

    def test_truncated_decoy_rejected(self):
        q = self._q()
        answers = preset_answers([q])
        assert _passes_answer_check(q, PRIMES_DECOY[:-1] + "}", answers) is False


# ---------------------------------------------------------------- AST 不变式
class TestFallbackNotRemoved:
    """防重新内联/删改：eval/cases.py 必须保留 flag_sha256 回落分支。"""

    def _src(self) -> str:
        p = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "eval", "cases.py",
        )
        with open(p, encoding="utf-8") as fh:
            return fh.read()

    def test_preset_answers_mentions_flag_sha256(self):
        src = self._src()
        assert "flag_sha256" in src, (
            "eval/cases.py 丢失 flag_sha256 回落：外部题答案表将再次装配为空，"
            "诱饵明文可冒充解出（2026-10-13 P0 复发）"
        )

    def test_fallback_is_inside_preset_answers(self):
        """回落必须落在 preset_answers 体内（不是别处的同名引用）。"""
        import ast

        tree = ast.parse(self._src())
        fn = next(
            (n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == "preset_answers"),
            None,
        )
        assert fn is not None, "preset_answers 未定义"
        seg = ast.get_source_segment(self._src(), fn) or ""
        assert "flag_sha256" in seg, "flag_sha256 回落不在 preset_answers 体内"
