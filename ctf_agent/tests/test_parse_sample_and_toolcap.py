"""解析失败留样 + provider 能力探针 回归（2026-10-10）。

两个交付物的测试：
1. `_redact_for_log` / `_log_unparsable_sample`：**样本要能进日志就不能带凭据**，
   且同一样本只留一次（否则日志被刷爆，等于没留）。
2. `_provider_toolcap_probe.recommend`：推荐规则必须"活着 + 零解析失败"优先，
   解析失败>0 的 provider 绝不能被推荐（那会把跑批变成基础设施失败的伪装）。
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


import llm.client as client  # noqa: E402

toolcap = _load("_provider_toolcap_probe")


class TestParseSampleRedaction(unittest.TestCase):
    def test_redacts_api_keys(self):
        out = client._redact_for_log("api_key=sk-abcdefgh12345678 and ak_0123456789xyz")
        self.assertNotIn("sk-abcdefgh", out)
        self.assertNotIn("ak_0123456789xyz", out)
        self.assertIn("REDACTED", out)

    def test_redacts_token_and_long_base64(self):
        out = client._redact_for_log("token: abcdefghijklmnopqrst " + "A" * 60)
        self.assertNotIn("abcdefghijklmnopqrst", out)

    def test_truncates_to_200_chars(self):
        self.assertLessEqual(len(client._redact_for_log("x" * 5000)), 200)

    def test_sample_is_deduped(self):
        client._UNPARSABLE_SEEN.clear()
        client._log_unparsable_sample("same bad payload", "t")
        client._log_unparsable_sample("same bad payload", "t")
        self.assertEqual(len(client._UNPARSABLE_SEEN), 1)
        client._log_unparsable_sample("another bad payload", "t")
        self.assertEqual(len(client._UNPARSABLE_SEEN), 2)


class TestToolcapRecommend(unittest.TestCase):
    def test_prefers_alive_clean_solved(self):
        rep = toolcap.recommend([
            {"provider": "a", "alive": True, "json_parse_failures": 0, "solved": 1},
            {"provider": "b", "alive": True, "json_parse_failures": 3, "solved": 1},
        ])
        self.assertEqual(rep["recommended"], "a")

    def test_falls_back_to_clean_but_unsolved(self):
        rep = toolcap.recommend([
            {"provider": "a", "alive": True, "json_parse_failures": 0, "solved": 0},
            {"provider": "b", "alive": True, "json_parse_failures": 5, "solved": 0},
        ])
        self.assertEqual(rep["recommended"], "a")

    def test_refuses_when_all_dirty(self):
        """解析失败>0 的 provider 一律不推荐——宁可说"别跑"。"""
        rep = toolcap.recommend([
            {"provider": "a", "alive": True, "json_parse_failures": 4, "solved": 0},
            {"provider": "b", "alive": False, "json_parse_failures": 0, "solved": 1},
        ])
        self.assertIsNone(rep["recommended"])
        self.assertIn("充值", rep["why"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
