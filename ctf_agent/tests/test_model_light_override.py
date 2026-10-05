# -*- coding: utf-8 -*-
"""回归：显式 provider 时 CTF_AGENT_{PROVIDER}_MODEL 轻量覆盖必须生效。

背景（2026-10-05，B2 A/B 跑批整轮作废根因）
------------------------------------------------
`run.py:167` 主链路调用 `get_model_for_attempt(attempt, provider)`——**显式传 provider**。
而 `get_model_for_attempt` 的 provider 分支在 `attempt < upgrade_after_attempts` 时直接
`return default_model`（= `_resolve_provider_defaults(provider)[1]`），既不读
`CTF_AGENT_{PROVIDER}_MODEL` 也不读 `CTF_AGENT_LIGHT_MODEL`。后果：把免费源「钉到
指定模型」的 run 级配置**被静默丢弃**——qwen 仍打默认 `qwen3.7-flash`（免费额度耗尽
→ HTTP403）→ `llm/client` 连续 3 次 403 → provider 级熔断 → 后续全部跳过 → 整轮作废。

（`_resolve_settings` 本会尊重 `CTF_AGENT_{PROV}_MODEL`，但 `model` 已被 `run.py` 填成
非空字符串 → 该分支永不触发，故修复点必须在 `get_model_for_attempt`。）
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm.client import get_model_for_attempt  # noqa: E402

_MANAGED = (
    "CTF_AGENT_QWEN_MODEL",
    "CTF_AGENT_QWEN_HEAVY_MODEL",
    "CTF_AGENT_DEEPSEEK_MODEL",
    "CTF_AGENT_LIGHT_MODEL",
    "CTF_AGENT_HEAVY_MODEL",
    "CTF_AGENT_LLM_PROVIDER",
    "CTF_AGENT_UPGRADE_AFTER",
)


class TestLightOverride(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in _MANAGED}
        for k in _MANAGED:
            os.environ.pop(k, None)
        os.environ["CTF_AGENT_UPGRADE_AFTER"] = "2"   # 与默认一致，显式钉死防父进程残留

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # ── 修复点：provider 分支 attempt<upgrade 尊重专属轻量 env ──────────────
    def test_provider_light_override_honored(self):
        os.environ["CTF_AGENT_QWEN_MODEL"] = "qwen3.7-plus"
        self.assertEqual(get_model_for_attempt(0, provider="qwen"), "qwen3.7-plus")
        self.assertEqual(get_model_for_attempt(1, provider="qwen"), "qwen3.7-plus")

    def test_provider_light_default_when_env_absent(self):
        self.assertEqual(get_model_for_attempt(0, provider="qwen"), "qwen3.7-flash")

    def test_non_qwen_provider_light_override(self):
        os.environ["CTF_AGENT_DEEPSEEK_MODEL"] = "deepseek-chat-x"
        self.assertEqual(get_model_for_attempt(0, provider="deepseek"), "deepseek-chat-x")

    # ── 不回归：重型路径语义保持不变 ─────────────────────────────────────
    def test_provider_heavy_override_still_honored(self):
        os.environ["CTF_AGENT_QWEN_HEAVY_MODEL"] = "qwen3.7-plus"
        self.assertEqual(get_model_for_attempt(2, provider="qwen"), "qwen3.7-plus")

    def test_provider_heavy_map_when_no_heavy_env(self):
        self.assertEqual(get_model_for_attempt(2, provider="qwen"), "qwen3.8-max")

    def test_heavy_env_does_not_leech_into_light(self):
        """只设重型 env 时，轻量档仍应走默认（防修过头把重型当轻量）。"""
        os.environ["CTF_AGENT_QWEN_HEAVY_MODEL"] = "qwen3.7-plus"
        self.assertEqual(get_model_for_attempt(0, provider="qwen"), "qwen3.7-flash")

    # ── 无 provider 分支：全局覆盖仍生效 ────────────────────────────────
    def test_no_provider_uses_global_light(self):
        os.environ["CTF_AGENT_LLM_PROVIDER"] = "qwen"
        os.environ["CTF_AGENT_LIGHT_MODEL"] = "qwen3.7-plus"
        self.assertEqual(get_model_for_attempt(0), "qwen3.7-plus")


if __name__ == "__main__":
    unittest.main()
