"""永久性 429（余额耗尽/账号停用）应触发熔断的回归测试。

背景（2026-10-06 实证）：moonshot kimi-k2.6 账号余额耗尽，网关返回
**HTTP 429 + `exceeded_current_quota_error`**，原逻辑一律把 429 当"瞬时限流"
放行 → 主 Agent 264 次 429 空转烧满 9 分钟墙钟，最终产出 `wrong_direction`
假结果（与 deepseek 402 同类 artifact）。本测试锁死：
① 纯判据 `_is_permanent_429_failure` 只认永久标记、不误伤真限流；
② `_circuit_record_failure` 对永久性 429 计入熔断、对瞬时限流不计入；
③ 401/402/403 行为不回归。
"""

import sys
from pathlib import Path

import pytest

# 允许以模块方式直接 import（与 test_extract_json_object 一致）
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from llm.client import (  # noqa: E402
    _PROVIDER_CIRCUIT_FAIL_LIMIT,
    _circuit_record_failure,
    _is_permanent_429_failure,
    model_circuit_open,
    reset_circuits,
)


@pytest.fixture(autouse=True)
def _clean_circuits():
    """每个用例前后清空熔断状态，避免跨用例污染。"""
    reset_circuits()
    yield
    reset_circuits()


# ── ① 纯判据：永久性 429 识别 ──
@pytest.mark.parametrize("body", [
    '{"error":{"message":"Your account org-xxx is suspended due to insufficient '
    'balance, please recharge","type":"exceeded_current_quota_error"}}',
    '{"error":{"message":"exceeded_current_quota_error"}}',
    '{"error":{"message":"insufficient balance"}}',
    '{"error":{"message":"account overdue"}}',
    '{"error":"Arrearage"}',
    "账户欠费，请充值",
    "余额不足",
])
def test_permanent_429_markers_detected(body):
    assert _is_permanent_429_failure(body) is True


@pytest.mark.parametrize("body", [
    '{"error":{"message":"request reached organization max RPM: 3, please try '
    'again after 1 seconds","type":"rate_limit_reached_error"}}',
    '{"error":{"message":"Too Many Requests"}}',
    "",
    None,
])
def test_transient_429_not_flagged(body):
    """真限流/空体不得判为永久——保守，宁可当瞬时也不误熔断活跃 provider。"""
    assert _is_permanent_429_failure(body) is False


# ── ② 熔断行为：永久性 429 达阈值即熔断 ──
def test_permanent_429_trips_circuit():
    body = '{"type":"exceeded_current_quota_error","message":"insufficient balance"}'
    for _ in range(_PROVIDER_CIRCUIT_FAIL_LIMIT):
        _circuit_record_failure("moonshot", "kimi-k2.6", 429, body)
    assert model_circuit_open("moonshot", "kimi-k2.6") is True


def test_permanent_429_below_threshold_not_open():
    body = '{"type":"exceeded_current_quota_error"}'
    for _ in range(_PROVIDER_CIRCUIT_FAIL_LIMIT - 1):
        _circuit_record_failure("moonshot", "kimi-k2.6", 429, body)
    assert model_circuit_open("moonshot", "kimi-k2.6") is False


def test_transient_429_does_not_trip_circuit():
    """核心不回归：真限流反复出现也不得熔断（否则会误杀限流后恢复的源）。"""
    body = '{"type":"rate_limit_reached_error","message":"max RPM: 3"}'
    for _ in range(_PROVIDER_CIRCUIT_FAIL_LIMIT * 5):
        _circuit_record_failure("moonshot", "kimi-k2.6", 429, body)
    assert model_circuit_open("moonshot", "kimi-k2.6") is False


def test_429_without_body_does_not_trip():
    """无响应体时按瞬时处理（不误熔断）——保持原 fail-open 语义。"""
    for _ in range(_PROVIDER_CIRCUIT_FAIL_LIMIT * 3):
        _circuit_record_failure("moonshot", "kimi-k2.6", 429, "")
    assert model_circuit_open("moonshot", "kimi-k2.6") is False


# ── ③ 401/402/403 不回归 ──
@pytest.mark.parametrize("status", [401, 402, 403])
def test_permanent_http_status_still_trips(status):
    for _ in range(_PROVIDER_CIRCUIT_FAIL_LIMIT):
        _circuit_record_failure("deepseek", "deepseek-chat", status, "")
    assert model_circuit_open("deepseek", "deepseek-chat") is True


def test_other_status_not_tripping():
    """500 等可恢复状态不熔断。"""
    for _ in range(_PROVIDER_CIRCUIT_FAIL_LIMIT * 3):
        _circuit_record_failure("ark", "doubao", 500, "internal error")
    assert model_circuit_open("ark", "doubao") is False


def test_circuit_key_granularity_preserved():
    """熔断只针对出事的 (provider, model)，不牵连同 provider 其他模型。"""
    body = '{"type":"exceeded_current_quota_error"}'
    for _ in range(_PROVIDER_CIRCUIT_FAIL_LIMIT):
        _circuit_record_failure("moonshot", "kimi-k2.6", 429, body)
    assert model_circuit_open("moonshot", "kimi-k2.6") is True
    assert model_circuit_open("moonshot", "kimi-k2.5") is False
