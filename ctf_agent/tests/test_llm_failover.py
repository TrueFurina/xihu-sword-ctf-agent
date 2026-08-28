"""llm.failover 跨 provider 兜底路由单测（mock ai_chat，零真 token）。

覆盖：熔毁主源自动切备选 / 显式 provider 不劫持 / 关闭时单源 / 全失败 / 跳过已熔断源。
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import llm.failover as fo  # noqa: E402


def _set_env(enabled="1", order="baidu,qwen"):
    # 直接写小值环境变量，避免 mock.patch.dict 在 Windows 沙箱 teardown 时
    # 尝试恢复超长预置变量而报 >32767 字符的错误。
    os.environ["CTF_AGENT_LLM_FAILOVER"] = enabled
    os.environ["CTF_AGENT_FAILOVER_ORDER"] = order


class TestFailover(unittest.TestCase):

    def test_skip_melted_primary(self):
        """主源 baidu 熔毁（None），自动切 qwen 命中。"""
        calls = []

        def fake_ai_chat(messages, system=None, temperature=0.3, max_tokens=2000,
                         model=None, provider=None):
            calls.append(provider)
            return "OK-FROM-QWEN" if provider == "qwen" else None

        _set_env()
        with mock.patch("llm.client.ai_chat", side_effect=fake_ai_chat), \
             mock.patch("llm.client.provider_circuit_open", return_value=False):
            out = fo.ai_chat_failover([{"role": "user", "content": "x"}])
        self.assertEqual(out, "OK-FROM-QWEN")
        self.assertIn("baidu", calls)
        self.assertIn("qwen", calls)

    def test_explicit_provider_not_hijacked(self):
        """竞速显式 provider=deepseek：不遍历 order，只打 deepseek。"""
        calls = []

        def fake_ai_chat(messages, system=None, temperature=0.3, max_tokens=2000,
                         model=None, provider=None):
            calls.append(provider)
            return "DEEPSEEK-OK" if provider == "deepseek" else None

        _set_env()
        with mock.patch("llm.client.ai_chat", side_effect=fake_ai_chat), \
             mock.patch("llm.client.provider_circuit_open", return_value=False):
            out = fo.ai_chat_failover(
                [{"role": "user", "content": "x"}], provider="deepseek")
        self.assertEqual(out, "DEEPSEEK-OK")
        self.assertEqual(calls, ["deepseek"])

    def test_disabled_is_single_source(self):
        """FAILOVER=0：等同原单源（provider=None 只打一次）。"""
        calls = []

        def fake_ai_chat(messages, system=None, temperature=0.3, max_tokens=2000,
                         model=None, provider=None):
            calls.append(provider)
            return "SINGLE"

        _set_env(enabled="0")
        with mock.patch("llm.client.ai_chat", side_effect=fake_ai_chat), \
             mock.patch("llm.client.provider_circuit_open", return_value=False):
            out = fo.ai_chat_failover([{"role": "user", "content": "x"}])
        self.assertEqual(out, "SINGLE")
        # 单源路径：只调用一次，且 provider 透传为 None
        self.assertEqual(calls, [None])

    def test_all_fail_returns_none(self):
        """全部源无响应：返回 None，且每个候选都试过。"""
        calls = []

        def fake_ai_chat(messages, system=None, temperature=0.3, max_tokens=2000,
                         model=None, provider=None):
            calls.append(provider)
            return None

        _set_env()
        with mock.patch("llm.client.ai_chat", side_effect=fake_ai_chat), \
             mock.patch("llm.client.provider_circuit_open", return_value=False):
            out = fo.ai_chat_failover([{"role": "user", "content": "x"}])
        self.assertIsNone(out)
        self.assertEqual(calls, ["baidu", "qwen"])

    def test_skips_circuit_open(self):
        """baidu 已熔断：跳过，直接打 qwen。"""

        def fake_circuit(p):
            return p == "baidu"

        def fake_ai_chat(messages, system=None, temperature=0.3, max_tokens=2000,
                         model=None, provider=None):
            return "QWEN-OK" if provider == "qwen" else None

        _set_env()
        with mock.patch("llm.client.ai_chat", side_effect=fake_ai_chat), \
             mock.patch("llm.client.provider_circuit_open", side_effect=fake_circuit):
            out = fo.ai_chat_failover([{"role": "user", "content": "x"}])
        self.assertEqual(out, "QWEN-OK")

    def test_json_failover_parses(self):
        """JSON 兜底：命中源返回 markdown 围栏 JSON，解析为 dict。"""

        def fake_ai_chat(messages, system=None, temperature=0.1, max_tokens=2000,
                         model=None, provider=None):
            return '```json\n{"flag": "x"}\n```' if provider == "qwen" else None

        _set_env()
        with mock.patch("llm.client.ai_chat", side_effect=fake_ai_chat), \
             mock.patch("llm.client.provider_circuit_open", return_value=False):
            out = fo.ai_chat_json_failover([{"role": "user", "content": "x"}])
        self.assertEqual(out, {"flag": "x"})


    def test_llm_json_wrapper_async_integration(self):
        """集成回归：llm_wrapper.llm_json 在 FAILOVER=1 时应 await 异步兜底变体，
        而非错误 await 同步函数（曾因 await 同步 def 触发 TypeError）。"""
        import asyncio

        from core import llm_wrapper as lw

        def fake_ai_chat(messages, system=None, temperature=0.3, max_tokens=2000,
                         model=None, provider=None):
            if provider == "baidu":
                return None
            if provider == "qwen":
                return '```json\n{"flag": "flag{ok}"}\n```'
            return None

        _set_env()
        with mock.patch("llm.client.ai_chat", side_effect=fake_ai_chat), \
             mock.patch("llm.client.provider_circuit_open", return_value=False), \
             mock.patch("llm.client.get_model_for_attempt", return_value="dummy"):
            out = asyncio.run(lw.llm_json("sys", "user", 0))
        self.assertEqual(out, {"flag": "flag{ok}"})

    def test_llm_text_wrapper_async_integration(self):
        """同 test_llm_json_wrapper_async_integration，但走文本兜底。"""
        import asyncio

        from core import llm_wrapper as lw

        def fake_ai_chat(messages, system=None, temperature=0.3, max_tokens=2000,
                         model=None, provider=None):
            if provider == "baidu":
                return None
            if provider == "qwen":
                return "flag{text_ok}"
            return None

        _set_env()
        with mock.patch("llm.client.ai_chat", side_effect=fake_ai_chat), \
             mock.patch("llm.client.provider_circuit_open", return_value=False), \
             mock.patch("llm.client.get_model_for_attempt", return_value="dummy"):
            out = asyncio.run(lw.llm_text("sys", "user", 0))
        self.assertEqual(out, "flag{text_ok}")


if __name__ == "__main__":
    unittest.main()
