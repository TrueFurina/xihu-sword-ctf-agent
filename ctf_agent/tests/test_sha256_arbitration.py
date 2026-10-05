"""sha256 真值仲裁（2026-09-19 幻觉攻坚）单测。

背景（heldout 预算 2x 对照跑实证）：dnui_keyboard 的 keyboard_path 解码不完整产出
flag{CLCKOUTHK}（sha256 不符），无闸时被当"确定性预扫命中"直灌 candidate_flag →
goal 记 flag=✅ → 主循环 8+ 次复读同一错答案直到预算耗尽（幻觉桶）。

覆盖：
1. verify.flag_checker.sha256_matches 四态（全串匹配/内文匹配/不符/无真值 None）
2. phases.extract_flag 仲裁：真值匹配早接受（含无工具证据场景）、
   真值不符确定性拒绝（即使 flag 出现在工具产出里）、无真值回归既有行为
3. presolve._try_keyboard_path sha256 闸：不符不采信（返回 None）、无真值放行
"""
import asyncio
import hashlib
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from verify.flag_checker import sha256_matches  # noqa: E402
from core.phases import extract_flag  # noqa: E402

TRUTH = hashlib.sha256("flag{REALFLAG123}".encode()).hexdigest()


class TestSha256Matches(unittest.TestCase):
    def test_full_form_match(self):
        self.assertIs(sha256_matches("flag{REALFLAG123}", TRUTH), True)

    def test_inner_form_match(self):
        self.assertIs(
            sha256_matches("flag{REALFLAG123}",
                           hashlib.sha256(b"REALFLAG123").hexdigest()), True)

    def test_mismatch_is_false(self):
        # dnui_keyboard 实证错候选：任何大小写/包裹形态都不匹配真值
        self.assertIs(sha256_matches("flag{CLCKOUTHK}", TRUTH), False)
        self.assertIs(sha256_matches("CLCKOUTHK", TRUTH), False)

    def test_no_truth_is_none(self):
        self.assertIsNone(sha256_matches("flag{X}", None))
        self.assertIsNone(sha256_matches("flag{X}", ""))
        self.assertIsNone(sha256_matches("flag{X}", "  "))


def _ctx(flag_sha256=None, steps=None):
    q = SimpleNamespace(id="q1", flag_pattern=None, category="crypto",
                        flag_sha256=flag_sha256)
    steps = steps if steps is not None else [
        SimpleNamespace(action="tool:crypto_auto", observation="done")]
    return SimpleNamespace(question=q, _extract_failed=False, steps=steps)


class TestExtractFlagArbitration(unittest.TestCase):
    def test_truth_match_early_accept_without_tool_evidence(self):
        # sha256 匹配 = 最强证据：即使无任何工具产出也确定性采信（早接受省预算）
        ctx = _ctx(flag_sha256=TRUTH, steps=[])
        out = "my guess is flag{REALFLAG123}"
        self.assertEqual(
            extract_flag(SimpleNamespace(checker=None), ctx, {"output": out}),
            "flag{REALFLAG123}")
        self.assertFalse(ctx._extract_failed)

    def test_truth_mismatch_rejected_even_in_tool_output(self):
        # dnui_keyboard 病理：错候选即使出现在工具产出里也被确定性拒绝 + 记反幻觉
        ctx = _ctx(flag_sha256=TRUTH)
        out = "keyboard decoded: flag{CLCKOUTHK}"
        self.assertIsNone(
            extract_flag(SimpleNamespace(checker=None), ctx, {"output": out}))
        self.assertTrue(ctx._extract_failed)
        self.assertEqual(getattr(ctx, "_hallucination_strike", 0), 1)

    def test_no_truth_unchanged(self):
        # 无真值题面：工具（keyboard skill）真实解出 flag → 工具产出即放行
        # （2026-09-22 反幻觉闸：act 须带 kind=tool 表示此输出来自工具，而非 LLM 文本瞎猜）
        ctx = _ctx(flag_sha256=None)
        out = "keyboard decoded: flag{CLCKOUTHK}"
        self.assertEqual(
            extract_flag(SimpleNamespace(checker=None), ctx, {"kind": "tool", "output": out}),
            "flag{CLCKOUTHK}")
        self.assertFalse(ctx._extract_failed)


class TestKeyboardPathGate(unittest.TestCase):
    def _q(self, flag_sha256, att):
        return SimpleNamespace(id="dnui", category="crypto",
                               flag_sha256=flag_sha256, attachments=[att])

    def _run_kb(self, flag_sha256):
        fake = {"decoded": "CLCKOUTHK", "flag": "flag{CLCKOUTHK}"}
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("dummy")
            att = f.name
        try:
            with mock.patch("skills.crypto_keyboard_path.run", return_value=fake):
                from core.presolve import _try_keyboard_path
                return asyncio.run(_try_keyboard_path(self._q(flag_sha256, att)))
        finally:
            os.unlink(att)

    def test_wrong_candidate_not_trusted_when_truth_present(self):
        # 有真值且候选不符 → 绝不作为确定性命中（返回 None，仅降级普通候选）
        self.assertIsNone(self._run_kb(TRUTH))

    def test_no_truth_passthrough(self):
        # 无真值题面保持既有行为（无法确定性证伪，放行原逻辑）
        self.assertEqual(self._run_kb(None), "flag{CLCKOUTHK}")


# --------------------------------------------------------------------------
# 2026-10-05 flag_pattern 声明有误修复：宽 pattern + sha256 兜底
#
# 背景：外部题池 38/40 题 flag_pattern 沿用默认 `flag{}`，而 google-ctf 真 flag
# 实为 `CTF{...}` → 声明 pattern 在 output 里定位不到真 flag。修复：声明 pattern
# 未匹配且本题带 sha256 真值时，退回宽 pattern 扫描 + sha256 仲裁。
# 变异验证：删掉 phases.extract_flag 中的 _broad_sha256_flag 兜底 → 恢复用例 FAIL。
# --------------------------------------------------------------------------
CTF_TRUTH = hashlib.sha256("CTF{RealFlag}".encode()).hexdigest()


class TestBroadPatternSha256Fallback(unittest.TestCase):
    def _ctx_wrong_pattern(self, flag_sha256):
        ctx = _ctx(flag_sha256=flag_sha256)
        ctx.question.flag_pattern = r"flag\{[^}]+\}"  # 声明有误（与真值 CTF{} 不符）
        return ctx

    def test_wrong_declared_pattern_recovers_true_flag(self):
        ctx = self._ctx_wrong_pattern(CTF_TRUTH)
        out = "server returned CTF{RealFlag}"
        self.assertEqual(
            extract_flag(SimpleNamespace(checker=None), ctx, {"output": out}),
            "CTF{RealFlag}")
        self.assertFalse(ctx._extract_failed)

    def test_broad_fallback_skips_decoy_and_finds_true(self):
        # 输出含诱饵在前 → 宽扫描命中诱饵但 sha256 不符 → 继续找到真值
        ctx = self._ctx_wrong_pattern(CTF_TRUTH)
        out = "note: CTF{Decoy} and also CTF{RealFlag}"
        self.assertEqual(
            extract_flag(SimpleNamespace(checker=None), ctx, {"output": out}),
            "CTF{RealFlag}")

    def test_no_truth_does_not_enable_fallback(self):
        # 无 sha256 真值 → 兜底不启用，行为不变（不误纳），返回 None
        ctx = self._ctx_wrong_pattern(None)
        out = "server returned CTF{RealFlag}"
        self.assertIsNone(
            extract_flag(SimpleNamespace(checker=None), ctx, {"output": out}))

    def test_declared_pattern_still_wins_when_matching(self):
        # 回归：声明 pattern 能匹配时走原路径，兜底不介入（真值不符 → 确定性拒绝）
        ctx = _ctx(flag_sha256=TRUTH)
        out = "keyboard decoded: flag{CLCKOUTHK}"
        self.assertIsNone(
            extract_flag(SimpleNamespace(checker=None), ctx, {"output": out}))


class TestBroadFlagHelper(unittest.TestCase):
    def test_helper_returns_none_without_truth(self):
        from core.phases import _broad_sha256_flag
        ctx = _ctx(flag_sha256=None)
        self.assertIsNone(_broad_sha256_flag(ctx, "CTF{RealFlag}"))

    def test_helper_finds_sha256_verified_token(self):
        from core.phases import _broad_sha256_flag
        ctx = _ctx(flag_sha256=CTF_TRUTH)
        self.assertEqual(
            _broad_sha256_flag(ctx, "junk CTF{nope} then CTF{RealFlag} end"),
            "CTF{RealFlag}")

    def test_helper_ignores_non_flag_text(self):
        from core.phases import _broad_sha256_flag
        ctx = _ctx(flag_sha256=CTF_TRUTH)
        self.assertIsNone(_broad_sha256_flag(ctx, "no braces here at all"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
