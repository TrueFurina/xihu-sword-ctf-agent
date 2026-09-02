"""extract_flag 结构化候选提取（E1）单测：mock checker=None 走正则路径，不花真 token。"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.phases import extract_flag  # noqa: E402


def _ctx(flag_pattern=None, category="crypto"):
    q = SimpleNamespace(id="q1", flag_pattern=flag_pattern, category=category)
    # 2026-09-01：extract_flag 新增「工具证据门」（全程无工具调用即拒绝疑似猜 flag，
    # spookifier 实证：步骤#0 猜 flag 即 break）。夹具补一个工具步骤，反映真实求解
    # 「先工具实算、再提取 flag」的路径（证据门只查 has_tool_call，不查 flag 归属）。
    steps = [SimpleNamespace(action="tool:crypto_auto", observation="crypto_auto done")]
    return SimpleNamespace(question=q, _extract_failed=False, steps=steps)


def _agent():
    return SimpleNamespace(checker=None)


class TestExtractFlag(unittest.TestCase):
    def test_plain_output(self):
        ctx = _ctx()
        out = "the flag is flag{abc123}"
        self.assertEqual(extract_flag(_agent(), ctx, {"output": out}), "flag{abc123}")
        self.assertFalse(ctx._extract_failed)

    def test_template_placeholder_rejected(self):
        ctx = _ctx()
        out = "flag{%d-%d}"  # 抄题面模板
        self.assertIsNone(extract_flag(_agent(), ctx, {"output": out}))
        self.assertTrue(ctx._extract_failed)

    def test_json_candidates_list(self):
        ctx = _ctx()
        out = '{"candidates": ["flag{wrong}", "flag{real_one}", "flag{bad}"]}'
        # 第一个匹配 flag_pattern 的候选被返回
        self.assertEqual(extract_flag(_agent(), ctx, {"output": out}), "flag{wrong}")

    def test_json_block_candidates(self):
        ctx = _ctx()
        out = "here:\n```json\n{\"flags\": [\"flag{real_one}\"]}\n```"
        self.assertEqual(extract_flag(_agent(), ctx, {"output": out}), "flag{real_one}")

    def test_all_candidates_invalid(self):
        ctx = _ctx()
        out = '{"candidates": ["flag{%d}", "flag{%s}"]}'
        self.assertIsNone(extract_flag(_agent(), ctx, {"output": out}))
        self.assertTrue(ctx._extract_failed)

    def test_primary_placeholder_but_valid_candidate(self):
        ctx = _ctx()
        # 主输出是模板占位（触发 _extract_failed），但候选列表里有真 flag
        out = 'flag{%d}\n{"candidates": ["flag{real_one}"]}'
        self.assertEqual(extract_flag(_agent(), ctx, {"output": out}), "flag{real_one}")
        self.assertFalse(ctx._extract_failed)  # 找到有效候选，误触发埋点被撤销

    def test_custom_flag_pattern(self):
        ctx = _ctx(flag_pattern=r"DASCTF\{[^}]+\}")
        out = '{"candidates": ["DASCTF{ok}", "flag{nope}"]}'
        self.assertEqual(extract_flag(_agent(), ctx, {"output": out}), "DASCTF{ok}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
