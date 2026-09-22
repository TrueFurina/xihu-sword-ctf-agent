"""反幻觉 provenance 闸单测（2026-09-22），含变异验证。

变异验证（项目铁律：测试全绿≠测试有效）：
  用 unittest.mock.patch 把 provenance_allows 临时改为「恒放行」（=旧泄漏语义），
  断言原本被拒的打印泄漏/无证据 flag 此刻会被接受 → 证明闸门确实是这些测试在守护；
  撤掉 patch 后恢复拒绝 → 证明闸门行为真实生效。若未来有人把闸门改回宽松，
  此测试会 FAIL，防止「看起来全绿实则泄漏」回潮。
"""
import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import anti_hallucination as ah  # noqa: E402
from core.anti_hallucination import provenance_allows, is_print_leak  # noqa: E402
from core.phases import extract_flag  # noqa: E402


def _q(flag_sha256=None):
    return SimpleNamespace(id="q1", category="crypto", flag_pattern=r"flag\{[^}]+\}",
                          flag_sha256=flag_sha256)


def _ctx(tool_obs="crypto_auto done", flag_sha256=None):
    steps = [SimpleNamespace(action="tool:crypto_auto", observation=tool_obs)]
    return SimpleNamespace(question=_q(flag_sha256), _extract_failed=False, steps=steps)


def _agent():
    return SimpleNamespace(checker=None)


class TestProvenanceAllows(unittest.TestCase):
    def test_tool_output_current_ok(self):
        act = {"kind": "tool", "output": "result is flag{abc123}"}
        ok, reason = provenance_allows("flag{abc123}", _ctx(), act)
        self.assertTrue(ok)
        self.assertEqual(reason, "tool-output-current")

    def test_history_tool_obs_ok(self):
        # flag 出现在历史工具 observation，当前是 reason 步
        ctx = _ctx(tool_obs="decrypted payload flag{abc123} end")
        act = {"kind": "reason", "output": "so flag{abc123}"}
        ok, reason = provenance_allows("flag{abc123}", ctx, act)
        self.assertTrue(ok)
        self.assertEqual(reason, "tool-output-history")

    def test_print_leak_rejected(self):
        act = {"kind": "script", "output": "flag{guess}",
               "source": "x = compute()\nprint('flag{guess}')"}
        ok, reason = provenance_allows("flag{guess}", _ctx(), act)
        self.assertFalse(ok)
        self.assertEqual(reason, "print-leak(script-hardcoded-flag)")
        self.assertTrue(is_print_leak("flag{guess}", act))

    def test_no_tool_evidence_rejected(self):
        # reason 提交 flag，历史工具产出里没有该 flag
        act = {"kind": "reason", "output": "i think flag{guess}"}
        ok, reason = provenance_allows("flag{guess}", _ctx(), act)
        self.assertFalse(ok)
        self.assertEqual(reason, "no-tool-evidence")
        self.assertFalse(is_print_leak("flag{guess}", act))

    def test_script_computed_ok(self):
        # 脚本真实算出 flag（源码不含 flag 字面量）
        act = {"kind": "script", "output": "flag{abc123}",
               "source": "pt = decrypt(cipher, key)\nprint(pt)"}
        ok, _ = provenance_allows("flag{abc123}", _ctx(), act)
        self.assertTrue(ok)


class TestExtractFlagGate(unittest.TestCase):
    def test_print_leak_rejected(self):
        ctx = _ctx()
        act = {"kind": "script", "output": "flag{guess}",
               "source": "print('flag{guess}')"}
        self.assertIsNone(extract_flag(_agent(), ctx, act))
        self.assertTrue(ctx._extract_failed)

    def test_no_tool_evidence_rejected(self):
        ctx = _ctx()  # 工具产出不含 flag
        act = {"kind": "reason", "output": "flag{guess}"}
        self.assertIsNone(extract_flag(_agent(), ctx, act))
        self.assertTrue(ctx._extract_failed)

    def test_history_tool_evidence_accepted(self):
        ctx = _ctx(tool_obs="the bytes decode to flag{abc123}!!")
        act = {"kind": "reason", "output": "therefore flag{abc123}"}
        self.assertEqual(extract_flag(_agent(), ctx, act), "flag{abc123}")
        self.assertFalse(ctx._extract_failed)


class TestMutation(unittest.TestCase):
    """变异验证：把 provenance_allows 改回『恒放行』（旧泄漏语义），断言测试会翻转。"""

    def test_print_leak_caught_by_gate(self):
        ctx = _ctx()
        act = {"kind": "script", "output": "flag{guess}",
               "source": "print('flag{guess}')"}
        # 正常：闸门拒绝
        self.assertIsNone(extract_flag(_agent(), ctx, act))

        # 变异：恒放行（模拟旧 has_tool 宽松语义）
        with mock.patch.object(ah, "provenance_allows", return_value=(True, "mutant")):
            accepted = extract_flag(_agent(), ctx, act)
        # 变异后同一输入被接受 → 证明是闸门在守护，测试有牙
        self.assertEqual(accepted, "flag{guess}")

        # 撤掉变异：恢复拒绝
        self.assertIsNone(extract_flag(_agent(), ctx, act))

    def test_no_evidence_caught_by_gate(self):
        ctx = _ctx()
        act = {"kind": "reason", "output": "flag{guess}"}
        self.assertIsNone(extract_flag(_agent(), ctx, act))
        with mock.patch.object(ah, "provenance_allows", return_value=(True, "mutant")):
            self.assertEqual(extract_flag(_agent(), ctx, act), "flag{guess}")
        self.assertIsNone(extract_flag(_agent(), ctx, act))


if __name__ == "__main__":
    unittest.main(verbosity=2)
