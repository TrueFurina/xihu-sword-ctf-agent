"""跨 provider 自动熔断兜底路由（opt-in，向后兼容，合规白名单内）。

背景：llm/client.py 已有单 provider 熔断（连续 401/402/403 达阈值打开），但 provider
熔毁后仅返回 None，依赖手动 CTF_AGENT_ESCAPE_PROVIDER 逃生开关。本模块在显式开启
CTF_AGENT_LLM_FAILOVER=1 时提供跨 provider 自动尝试：主源熔毁自动切下一存活白名单源，
避免整场空转 0 产出。

安全约束（与比赛资格强相关）：
- 仅遍历白名单 provider；每个候选仍走 llm.client.ai_chat 内部的 _check_whitelist
  合规校验，绝不发往非白名单端点（不会触发设备告警/取消比赛资格）。
- 默认关闭（FAILOVER=0）：行为与原单源路径完全一致，比赛路径零意外。
- provider 显式传入（竞速多 solver 各传各的）时不劫持，保持竞速语义。
- 失败开放原则不变：所有候选均无响应时返回 None，由调用方决定回退。
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# 默认兜底顺序（仅在未显式设 CTF_AGENT_FAILOVER_ORDER 时采用）。
# 按「免费/低成本优先 + 实测存活」排序；具体可用性取决于本机各源 key 配置。
DEFAULT_FAILOVER_ORDER = ["qwen", "tokenhub", "mimo", "deepseek", "baidu"]


def _failover_enabled() -> bool:
    return os.getenv("CTF_AGENT_LLM_FAILOVER", "0") == "1"


def _failover_order() -> list[str]:
    raw = os.getenv("CTF_AGENT_FAILOVER_ORDER", "").strip()
    if raw:
        return [p.strip().lower() for p in raw.split(",") if p.strip()]
    return list(DEFAULT_FAILOVER_ORDER)


def ai_chat_failover(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    attempt: int = 0,
) -> Optional[str]:
    """跨 provider 兜底 ai_chat。

    - provider 显式传入：保持原竞速语义，直接单源调用。
    - provider=None 且 FAILOVER=0：等同原 ai_chat（单源）。
    - provider=None 且 FAILOVER=1：按 _failover_order 依次尝试白名单源，
      跳过已熔断者，返回首个非空响应；全部失败返回 None。
    """
    from llm.client import ai_chat, get_model_for_attempt, provider_circuit_open

    # 竞速/显式 provider：不劫持，保持原语义
    if provider:
        return ai_chat(
            messages, system=system, temperature=temperature,
            max_tokens=max_tokens, model=model, provider=provider,
        )
    if not _failover_enabled():
        return ai_chat(
            messages, system=system, temperature=temperature,
            max_tokens=max_tokens, model=model, provider=provider,
        )

    order = _failover_order()
    tried: list[str] = []
    for p in order:
        if provider_circuit_open(p):
            logger.info("failover: provider=%s 已熔断，跳过", p)
            continue
        tried.append(p)
        # 保留按 attempt 升级重型的语义（per-provider 映射）
        model_for_p = model or get_model_for_attempt(attempt, provider=p)
        out = ai_chat(
            messages, system=system, temperature=temperature,
            max_tokens=max_tokens, model=model_for_p, provider=p,
        )
        if out is not None:
            logger.info("failover: provider=%s 命中（tried=%s）", p, tried)
            return out
    logger.warning("failover: 全部 %d 个候选源均无响应（tried=%s）", len(tried), tried)
    return None


def ai_chat_json_failover(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    attempt: int = 0,
) -> Optional[dict]:
    """同 ai_chat_failover，但解析 JSON 对象返回（失败开放）。"""
    content = ai_chat_failover(
        messages, system=system, temperature=temperature,
        max_tokens=max_tokens, model=model, provider=provider, attempt=attempt,
    )
    if content is None:
        return None
    import json as _json
    import re as _re

    _raw = content.strip()
    _fence = _re.search(r"```(?:json)?\s*(.*?)\s*```", _raw, _re.DOTALL)
    if _fence:
        _raw = _fence.group(1).strip()
    _s, _e = _raw.find("{"), _raw.rfind("}")
    if _s != -1 and _e != -1 and _e > _s:
        _raw = _raw[_s:_e + 1]
    try:
        return _json.loads(_raw)
    except Exception:  # noqa: BLE001 - 失败开放
        return None


def ai_chat_text_failover(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    attempt: int = 0,
) -> str:
    """同 ai_chat_failover，返回文本（无响应返回空串）。"""
    out = ai_chat_failover(
        messages, system=system, temperature=temperature,
        max_tokens=max_tokens, model=model, provider=provider, attempt=attempt,
    )
    return out or ""


# ── 异步包装（不阻塞事件循环）──────────────────────────────

async def ai_chat_failover_async(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    attempt: int = 0,
) -> Optional[str]:
    return await asyncio.to_thread(
        ai_chat_failover, messages, system, temperature, max_tokens,
        model, provider, attempt,
    )


async def ai_chat_json_failover_async(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    attempt: int = 0,
) -> Optional[dict]:
    return await asyncio.to_thread(
        ai_chat_json_failover, messages, system, temperature, max_tokens,
        model, provider, attempt,
    )


async def ai_chat_text_failover_async(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    attempt: int = 0,
) -> str:
    return await asyncio.to_thread(
        ai_chat_text_failover, messages, system, temperature, max_tokens,
        model, provider, attempt,
    )
