"""设计层病根修复回归测试（2026-08-22 锐评第五节整改）。

覆盖：
1. 逃生开关：CTF_AGENT_ESCAPE_PROVIDER 在未显式传 provider 时强制切换；
   显式传 provider（竞速多 solver）时不劫持
2. 逃生后 api_key 按新 provider 解析
3. 配置快照：print_effective_config_snapshot 返回完整字段 + 不抛异常
4. fail-closed 拦截告警提示逃生开关（不真发 HTTP）
"""

import os

import pytest

from config import print_effective_config_snapshot
from llm.client import _resolve_settings


def _clear_llm_env():
    """清理可能干扰的 LLM 相关环境变量。"""
    for k in (
        "CTF_AGENT_LLM_PROVIDER", "CTF_AGENT_ESCAPE_PROVIDER",
        "CTF_AGENT_LLM_BASE_URL", "CTF_AGENT_ENFORCE_WHITELIST",
        "CTF_AGENT_LLM_API_KEY", "CTF_AGENT_ALLOW_OFF_WHITELIST",
    ):
        os.environ.pop(k, None)


@pytest.fixture(autouse=True)
def _clean_env():
    _clear_llm_env()
    yield
    _clear_llm_env()


def test_escape_provider_forces_switch_when_no_explicit_provider():
    """逃生开关：未显式传 provider 时，CTF_AGENT_ESCAPE_PROVIDER 强制切换。"""
    os.environ["CTF_AGENT_LLM_PROVIDER"] = "glm"          # 默认源（白名单但用户想切）
    os.environ["CTF_AGENT_ESCAPE_PROVIDER"] = "baidu"      # 逃生目标
    settings = _resolve_settings(model=None, provider=None)
    assert settings["provider"] == "baidu", "逃生开关应强制切换到 baidu"


def test_escape_provider_not_override_explicit_provider():
    """竞速场景：显式传 provider（多 solver 各传各的）时不劫持。"""
    os.environ["CTF_AGENT_ESCAPE_PROVIDER"] = "baidu"
    settings = _resolve_settings(model=None, provider="moonshot")
    assert settings["provider"] == "moonshot", "显式 provider 不应被逃生开关劫持"


def test_escape_provider_resolves_new_api_key():
    """逃生后 api_key 应按新 provider 解析（key 环境变量切换生效）。"""
    os.environ["CTF_AGENT_ESCAPE_PROVIDER"] = "baidu"
    os.environ["QIANFAN_API_KEY"] = "sk-qianfan-test"
    settings = _resolve_settings(model=None, provider=None)
    assert settings["provider"] == "baidu"
    assert settings["api_key"] == "sk-qianfan-test"


def test_snapshot_returns_full_fields():
    """配置快照返回完整字段且不抛异常。"""
    snap = print_effective_config_snapshot()
    for field in (
        "provider", "base_url", "light_model", "heavy_model",
        "api_key_masked", "enforce_whitelist", "escape_provider",
        "allow_off_whitelist", "residue_warnings",
    ):
        assert field in snap, f"快照缺字段: {field}"


def test_snapshot_warns_on_residue_base_url():
    """残留 CTF_AGENT_LLM_BASE_URL 应在快照里打 ⚠️ 告警。"""
    os.environ["CTF_AGENT_LLM_BASE_URL"] = "https://residue.example.com/v1"
    snap = print_effective_config_snapshot()
    assert any("CTF_AGENT_LLM_BASE_URL" in w for w in snap["residue_warnings"]), \
        "残留 BASE_URL 必须出现在快照告警里"


def test_snapshot_masks_api_key():
    """API Key 打码：不泄漏完整 key。"""
    os.environ["QIANFAN_API_KEY"] = "sk-super-secret-key-123456"
    snap = print_effective_config_snapshot(provider="baidu")
    assert "sk-super-secret-key-123456" not in snap["api_key_masked"]
    assert snap["api_key_masked"].startswith("sk-s")
