"""extract_flag 结构化候选提取（E1）单测：mock checker=None 走正则路径，不花真 token。

2026-09-22 反幻觉 provenance 闸已生效：extract_flag 只采信「来自工具/脚本真实产出」
的 flag（或 sha256 真值）。本夹具统一用 kind="tool" 的 act 携带输出，等价「LLM 跑工具
得到结果后从中提取 flag」的真实路径；不再依赖旧 has_tool 的宽松「只要历史有任意工具步
就放行」（那正是 reason 提交猜 flag 的泄漏口）。
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.phases import extract_flag  # noqa: E402


def _ctx(flag_pattern=None, category="crypto", tool_obs="crypto_auto done"):
    q = SimpleNamespace(id="q1", flag_pattern=flag_pattern, category=category,
                        flag_sha256=None)
    # 一个真实的工具步骤；其 observation 默认不含 flag（检验 provenance 门不会无证据放行）
    steps = [SimpleNamespace(action="tool:crypto_auto", observation=tool_obs)]
    return SimpleNamespace(question=q, _extract_failed=False, steps=steps)


def _agent():
    return SimpleNamespace(checker=None)


def _act(out):
    # 等价「LLM 跑工具得到输出，从中提取 flag」——kind=tool 使 provenance 门采信
    return {"kind": "tool", "output": out}


class TestExtractFlag(unittest.TestCase):
    def test_plain_output(self):
        ctx = _ctx()
        out = "the flag is flag{abc123}"
        self.assertEqual(extract_flag(_agent(), ctx, _act(out)), "flag{abc123}")
        self.assertFalse(ctx._extract_failed)

    def test_template_placeholder_rejected(self):
        ctx = _ctx()
        out = "flag{%d-%d}"  # 抄题面模板
        self.assertIsNone(extract_flag(_agent(), ctx, {"output": out}))
        self.assertTrue(ctx._extract_failed)

    def test_json_candidates_list(self):
        ctx = _ctx()
        out = '{"candidates": ["flag{wrong}", "flag{real_one}", "flag{bad}"]}'
        # 第一个匹配 flag_pattern 的候选被返回（来自工具输出，provenance 采信）
        self.assertEqual(extract_flag(_agent(), ctx, _act(out)), "flag{wrong}")

    def test_json_block_candidates(self):
        ctx = _ctx()
        out = "here:\n```json\n{\"flags\": [\"flag{real_one}\"]}\n```"
        self.assertEqual(extract_flag(_agent(), ctx, _act(out)), "flag{real_one}")

    def test_all_candidates_invalid(self):
        ctx = _ctx()
        out = '{"candidates": ["flag{%d}", "flag{%s}"]}'
        self.assertIsNone(extract_flag(_agent(), ctx, {"output": out}))
        self.assertTrue(ctx._extract_failed)

    def test_primary_placeholder_but_valid_candidate(self):
        ctx = _ctx()
        # 主输出是模板占位（触发 _extract_failed），但候选列表里有真 flag
        out = 'flag{%d}\n{"candidates": ["flag{real_one}"]}'
        self.assertEqual(extract_flag(_agent(), ctx, _act(out)), "flag{real_one}")
        self.assertFalse(ctx._extract_failed)  # 找到有效候选，误触发埋点被撤销

    def test_custom_flag_pattern(self):
        ctx = _ctx(flag_pattern=r"DASCTF\{[^}]+\}")
        out = '{"candidates": ["DASCTF{ok}", "flag{nope}"]}'
        self.assertEqual(extract_flag(_agent(), ctx, _act(out)), "DASCTF{ok}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
