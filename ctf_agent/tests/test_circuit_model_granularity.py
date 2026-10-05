# -*- coding: utf-8 -*-
"""熔断粒度回归测试：provider 级 → (provider, model) 级。

背景（2026-10-05 真实事故）：tokenhub 下 hy3（免费）本可用，但 attempt>=2 升级到付费
deepseek-v4-pro 得 402 ×3 → 原实现按 provider 熔断 → 整个 tokenhub 被判死、
后续 321 次调用被跳过、整轮作废。

修复后：故障只熔断「出事的那个模型」，同 provider 其他模型照常可用。

变异敏感性：若把熔断键退回 provider 粒度（忽略 model），
`test_free_model_survives_paid_model_failure` 等用例必红。
"""
import pytest

from llm import client


@pytest.fixture(autouse=True)
def _clean():
    client.reset_circuits()
    yield
    client.reset_circuits()


def _fail(provider, model, n=3, code=402):
    for _ in range(n):
        client._circuit_record_failure(provider, model, code)


def test_three_failures_open_only_that_model():
    _fail("tokenhub", "deepseek-v4-pro", 3)
    assert client.model_circuit_open("tokenhub", "deepseek-v4-pro") is True
    # 同 provider 的另一个模型不受影响 —— 本次修复的核心
    assert client.model_circuit_open("tokenhub", "hy3") is False


def test_free_model_survives_paid_model_failure():
    """真实事故复现：付费模型 402 不得连坐免费模型。"""
    _fail("tokenhub", "deepseek-v4-pro", 3)
    assert client.model_circuit_open("tokenhub", "hy3") is False, (
        "付费模型故障连坐了免费模型 —— 熔断粒度退化回 provider 级（回归！）"
    )


def test_threshold_below_limit_not_open():
    _fail("p", "m", 2)
    assert client.model_circuit_open("p", "m") is False
    _fail("p", "m", 1)
    assert client.model_circuit_open("p", "m") is True


def test_429_does_not_trip():
    _fail("p", "m", 5, code=429)
    assert client.model_circuit_open("p", "m") is False


def test_provider_broad_open_is_any_model():
    assert client.provider_circuit_open("p") is False
    _fail("p", "m2", 3)
    assert client.provider_circuit_open("p") is True


def test_provider_broad_isolated_between_providers():
    _fail("p1", "m", 3)
    assert client.provider_circuit_open("p1") is True
    assert client.provider_circuit_open("p2") is False


def test_success_resets_only_that_model():
    _fail("p", "m1", 3)
    _fail("p", "m2", 3)
    client._circuit_record_success("p", "m1")
    assert client.model_circuit_open("p", "m1") is False
    assert client.model_circuit_open("p", "m2") is True


def test_reset_circuits_clears_all():
    _fail("p", "m", 3)
    client.reset_circuits()
    assert client.model_circuit_open("p", "m") is False
    assert client.provider_circuit_open("p") is False


def test_circuit_summary_keyed_by_provider_and_model():
    _fail("p", "m", 3)
    summary = client.circuit_summary()
    assert "p::m" in summary
    assert summary["p::m"]["open"] is True


def test_default_model_key_uses_empty_suffix():
    """裸 provider（无 model）也要能独立熔断，且不牵连具名模型。"""
    _fail("solo", "", 3)
    assert client.model_circuit_open("solo", "") is True
    assert client.model_circuit_open("solo", "other") is False
