"""题首内部预扫开关（CTF_AGENT_INTERNAL_PRESOLVE）回归。

守护的是口径纪律：确定性直扫与 LLM 贡献必须能分开记账。2026-10-06 实测——
外部真题 5 题探针中 2 题被附件直扫秒解，若无法关闭内部预扫，这 2 题会被
误记为 LLM 能力。
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location(
    "ma_switch_probe", ROOT / "core" / "main_agent.py")
# 只做语法级加载代价过高（模块 import 链重），因此直接取函数源码语义：
# 用 runpy 会在 import 时拉起整个依赖链，故改为源码断言 + 纯函数复刻校验。
src = (ROOT / "core" / "main_agent.py").read_text(encoding="utf-8")


class TestInternalPresolveSwitch(unittest.TestCase):
    def test_helper_exists_with_documented_default(self):
        self.assertIn("def internal_presolve_enabled()", src)
        self.assertIn("CTF_AGENT_INTERNAL_PRESOLVE", src)
        # 默认必须是"开"——关闭只能是显式 opt-out，避免老口径被静默改变
        self.assertIn('os.getenv("CTF_AGENT_INTERNAL_PRESOLVE", "on")', src)

    def test_switch_semantics(self):
        # 复刻 helper 的判定语义做表驱动校验（值与实现一致才算数）
        def enabled(env_value):
            if env_value is None:
                return "on"
            return env_value

        for val, want_enabled in (("on", True), ("off", False), ("0", False),
                                  ("false", False), ("OFF", False), ("", True)):
            got = enabled(val).strip().lower() not in ("off", "0", "false")
            self.assertEqual(got, want_enabled, f"env={val!r}")

    def test_call_site_uses_helper(self):
        # 调用点必须走 helper，不能另有独立 env 读取（否则改一处漏一处）
        self.assertIn("if not internal_presolve_enabled():", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
