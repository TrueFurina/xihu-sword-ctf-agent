# -*- coding: utf-8 -*-
"""本地不可用（httpx 缺失 / 端点不在白名单）必须记熔断 —— 防「假绿」回归（2026-10-13）。

实证（`G_rerun_noabandon_20261013_001117`）：诊断跑误用缺 httpx 的解释器，LLM 全链路
不可用、deepseek 从未被真正调用（token 停在 1806/题兜底估值），但报告仍标
`mode=real_main_agent` + `integrity.interpretable=True` —— 「基础设施彻底不可达」
被冒充成「能力测量」。

真因：`_post_chat` 的两条「请求根本发不出」分支（httpx 缺失 / 端点不在白名单）只
`logger.warning` 后 `return None`，**不记熔断** → `provider_circuit_open` 恒 False
→ `run.py` 的熔断根因回填不命中 → 退化桶（wrong_direction/unresolved）原样进报告 →
`summarize` 判 `interpretable=True`（该报告因此可被误引用为能力率）。

修复：两条分支按「永久性故障」记熔断（本地/配置层的**确定性**不可用，与 401/402/403
同等对待——它们同样不是 Agent 能力失败）。经既有「熔断→relabel→provider_circuit_open
→TRUNCATED→interpretable=False」链收口。

变异验证：删掉任一分支的 `_circuit_record_failure(..., unconditional=True)` → 本文件必 FAIL。
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from llm import client as llm_client  # noqa: E402
from llm.client import (  # noqa: E402
    _PROVIDER_CIRCUIT_FAIL_LIMIT,
    _post_chat,
    provider_circuit_open,
)

_PROVIDER = "deepseek"
_MODEL = "deepseek-chat"


@pytest.fixture(autouse=True)
def _clean():
    llm_client.reset_circuits()
    # 防外部环境放行非白名单端点，污染白名单分支用例
    os.environ.pop("CTF_AGENT_ALLOW_OFF_WHITELIST", None)
    yield
    llm_client.reset_circuits()


def _settings(base_url: str = "https://api.deepseek.com/chat/completions") -> dict:
    return {
        "provider": _PROVIDER,
        "model": _MODEL,
        "base_url": base_url,
        "api_key": "sk-test",
        "timeout": 1.0,
    }


def _call_n(n: int, base_url: str = "https://api.deepseek.com/chat/completions") -> None:
    for _ in range(n):
        _post_chat([{"role": "user", "content": "hi"}], 0.0, 16, _settings(base_url))


def test_httpx_missing_opens_circuit(monkeypatch):
    """httpx 缺失（LLM 全链路不可用）→ 记熔断，达阈值后 provider_circuit_open=True。"""
    monkeypatch.setattr(llm_client, "httpx", None)
    _call_n(_PROVIDER_CIRCUIT_FAIL_LIMIT - 1)
    assert provider_circuit_open(_PROVIDER) is False, "未达阈值不应提前熔断"
    _call_n(1)
    assert provider_circuit_open(_PROVIDER) is True, "httpx 缺失必须记熔断（否则报告假绿）"


def test_off_whitelist_endpoint_opens_circuit(monkeypatch):
    """端点不在白名单（请求根本发不出）→ 同样记熔断。"""
    monkeypatch.setattr(llm_client, "httpx", object())  # 非 None，越过第一分支
    _call_n(_PROVIDER_CIRCUIT_FAIL_LIMIT,
            base_url="https://evil.example.com/v1/chat/completions")
    assert provider_circuit_open(_PROVIDER) is True


def test_local_unavailable_reaches_uninterpretable_report(monkeypatch):
    """全链锁：httpx 缺失 → 熔断打开 → 回填 provider_circuit_open → 报告不可解释。

    这条把「本地不可用」与报告口径直接连起来：熔断没打开则本用例断言失败。
    """
    from core.error_taxonomy import PROVIDER_CIRCUIT_OPEN, relabel_circuit_breaker

    monkeypatch.setattr(llm_client, "httpx", None)
    _call_n(_PROVIDER_CIRCUIT_FAIL_LIMIT)
    assert provider_circuit_open(_PROVIDER) is True

    # 复现 run.py:366 的根因回填：熔断已开 + Agent 退化桶 wrong_direction
    relabeled = relabel_circuit_breaker("wrong_direction", provider_circuit_open(_PROVIDER))
    assert relabeled == PROVIDER_CIRCUIT_OPEN

    from eval.benchmark import BenchmarkResult, summarize
    from eval.cases import Question

    q = Question(id="dead", title="dead", category="crypto")
    r = BenchmarkResult(q, {"error": {"category": relabeled}}, 40249, 3)
    ig = summarize([r])["integrity"]
    assert ig["truncated"] == 1
    assert ig["interpretable"] is False, "本地不可用导致的失败不得作为能力率引用"
