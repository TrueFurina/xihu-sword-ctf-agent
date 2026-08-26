"""统一 LLM 客户端封装（从 Security-Agent ai/client.py 迁移改造）。

支持 DeepSeek（默认主用）、Qwen 与通用 OpenAI 兼容端点。
设计遵循失败开放（fail-open）原则：任何错误（未配置密钥、网络异常、
HTTP 错误、响应格式异常）都返回 None，绝不向上抛出异常，
由调用方决定回退到规则引擎或默认结果。

v2.0 迁移要点：
- 配置改为从 ctf_agent/config.py 读取（不再依赖 security_agent.config）
- 默认模型改为 deepseek-v4-flash（轻量），支持按 attempt 升级 deepseek-v4-pro
- 密钥解析：DEEPSEEK_API_KEY > CTF_AGENT_LLM_API_KEY > 配置兜底

密钥解析优先级：
    1. 环境变量 DEEPSEEK_API_KEY（DeepSeek 主用）
    2. 环境变量 CTF_AGENT_LLM_API_KEY（通用备用）
    3. 回退到 config.AppConfig.llm_api_key
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from typing import Any, Optional

try:  # httpx 为可选依赖，缺失时 AI 能力自动降级为不可用
    import httpx
except ImportError:  # pragma: no cover - 依赖缺失的兜底路径
    httpx = None

from config import (
    CONNECT_TIMEOUT_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    AppConfig,
    OFFICIAL_WHITELIST_PROVIDERS,
    _resolve_provider_defaults,
    resolve_api_key,
)

logger = logging.getLogger(__name__)

# 轻量并发护栏（P0-5 配套 2026-08-21）：ai_chat 为同步调用（httpx.post），
# 多 provider/多题目并行时可能过多并发直打单 provider 爆 429。此处用线程信号量
# 将同时进行的 LLM HTTP 请求数限制为 ≤8（P0修复2026-08-21：原值4过严，
# 多模型竞速12路+多题并发时大量请求排队超时，实际解题时间被挤压）。
_LLM_HTTP_SEMAPHORE = threading.BoundedSemaphore(8)

# 最近一次成功 LLM 调用的真实 token 用量（P1-2 修复 2026-08-21）：
# 预算熔断此前用 `len(hint)//4+200` 拍脑袋估算，真实 usage 被 _extract_content
# 丢弃，导致 80000/800000 token 上限形同虚设。此处记录响应体 usage 字段，
# 供 run.py solve_once 记账（真实 prompt/completion/total tokens）。
_LAST_USAGE: dict = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


# ── Provider 故障熔断（P0 热修复 2026-08-21 17:10 赛后落地）───────────
# 正式赛深坑：deepseek 402 余额耗尽 / qwen 403 免费额度耗尽 / 千帆 401 key 失效，
# Agent 在坏 provider 上空转数小时 0 产出。此处对"永久性"故障（401/402/403）
# 连续计数，达阈值即熔断该 provider，竞速池/主求解器后续不再调用它；
# 429 限流属暂时性，不触发熔断（只让路）。失败开放原则不变：熔断后返回 None。
_PROVIDER_CIRCUIT_FAIL_LIMIT = 3  # 连续 401/402/403 达 3 次即熔断
_PROVIDER_CIRCUITS: dict[str, dict] = {}  # {provider: {"fails": int, "open": bool}}
_CIRCUIT_LOCK = threading.Lock()


def _circuit_state(provider: str) -> dict:
    with _CIRCUIT_LOCK:
        return dict(_PROVIDER_CIRCUITS.get(provider, {"fails": 0, "open": False}))


def provider_circuit_open(provider: str) -> bool:
    """该 provider 是否已熔断（401/402/403 连续失败达阈值）。"""
    return _circuit_state(provider).get("open", False)


def _circuit_record_failure(provider: str, status_code: int) -> None:
    """记录一次永久性失败（401/402/403）；达阈值打开熔断。"""
    if status_code not in (401, 402, 403):
        return  # 429/4xx 其他/5xx 不熔断（暂时性或可恢复）
    with _CIRCUIT_LOCK:
        st = _PROVIDER_CIRCUITS.setdefault(
            provider, {"fails": 0, "open": False})
        st["fails"] += 1
        if st["fails"] >= _PROVIDER_CIRCUIT_FAIL_LIMIT and not st["open"]:
            st["open"] = True
            logger.warning(
                "🔴 provider=%s 连续 %d 次永久故障(401/402/403)，已熔断——"
                "后续请求将直接跳过该源（剩余存活源自动接管）",
                provider, st["fails"],
            )


def _circuit_record_success(provider: str) -> None:
    """成功调用重置失败计数（半开恢复：后续成功即关闭熔断）。"""
    with _CIRCUIT_LOCK:
        st = _PROVIDER_CIRCUITS.get(provider)
        if st:
            st["fails"] = 0
            st["open"] = False


def reset_circuits() -> None:
    """清空全部熔断状态（赛前 preflight / 换 key 后调用）。"""
    with _CIRCUIT_LOCK:
        _PROVIDER_CIRCUITS.clear()
    logger.info("已清空全部 LLM provider 熔断状态")


def circuit_summary() -> dict:
    """熔断状态快照（供状态检查/报告）。"""
    with _CIRCUIT_LOCK:
        return {p: dict(v) for p, v in _PROVIDER_CIRCUITS.items()}



def get_last_usage() -> dict:
    """返回最近一次成功 LLM 调用的真实 token 用量（无则全 0）。"""
    return dict(_LAST_USAGE)


def _extract_usage(data: Any) -> dict:
    """从 OpenAI 兼容响应中提取 usage 字段（防御式，P1-1 记账修正用）。"""
    try:
        usage = data.get("usage") or {}
        return {
            "prompt_tokens": int(usage.get("prompt_tokens") or 0),
            "completion_tokens": int(usage.get("completion_tokens") or 0),
            "total_tokens": int(usage.get("total_tokens") or 0),
        }
    except (AttributeError, TypeError, ValueError):
        return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def _record_usage(data: Any) -> None:
    """从 OpenAI 兼容响应中提取 usage 字段，更新 _LAST_USAGE（防御式）。"""
    try:
        usage = data.get("usage") or {}
        _LAST_USAGE["prompt_tokens"] = int(usage.get("prompt_tokens") or 0)
        _LAST_USAGE["completion_tokens"] = int(usage.get("completion_tokens") or 0)
        _LAST_USAGE["total_tokens"] = int(usage.get("total_tokens") or 0)
    except (AttributeError, TypeError, ValueError):
        pass


# ── 西湖论剑官方授权 API 端点白名单（手册第三节）──────────────
# ⚠️ 未在白名单的端点会触发设备告警 → 立即取消比赛资格
# 初赛/决赛前必须确保 settings["base_url"] 命中白名单（_check_whitelist 已校验）
WHITELISTED_ENDPOINTS = {
    # DeepSeek
    "https://api.deepseek.com/chat/completions",
    "https://api.deepseek.com/v1/chat/completions",
    "https://api.deepseek.com/responses",
    "https://api.deepseek.com/anthropic/v1/messages",
    # 阿里云 Qwen（百炼）
    "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
    "https://dashscope.aliyuncs.com/compatible-mode/v1/responses",
    "https://dashscope.aliyuncs.com/apps/anthropic/v1/messages",
    "https://coding.dashscope.aliyuncs.com/v1/chat/completions",
    "https://coding.dashscope.aliyuncs.com/apps/anthropic/v1/messages",
    # 百度 文心（千帆）
    "https://qianfan.baidubce.com/v2/chat/completions",
    "https://qianfan.baidubce.com/v2/responses",
    "https://qianfan.baidubce.com/anthropic/v1/messages",
    # 字节 豆包（火山方舟）
    "https://ark.cn-beijing.volces.com/api/v3/chat/completions",
    "https://ark.cn-beijing.volces.com/api/v3/responses",
    "https://ark.cn-beijing.volces.com/api/compatible/v1/messages",
    "https://ark.cn-beijing.volces.com/api/coding/v3/chat/completions",
    "https://ark.cn-beijing.volces.com/api/coding/v3/responses",
    "https://ark.cn-beijing.volces.com/api/coding/v1/messages",
    # 智谱 GLM
    "https://open.bigmodel.cn/api/paas/v4/chat/completions",
    "https://open.bigmodel.cn/api/v1/responses",
    "https://open.bigmodel.cn/api/anthropic/v1/messages",
    "https://open.bigmodel.cn/api/coding/paas/v4/chat/completions",
    "https://api.z.ai/api/coding/paas/v4/chat/completions",
    # 腾讯 Hunyuan / TokenHub / LKEAP
    "https://api.hunyuan.cloud.tencent.com/v1/chat/completions",
    "https://tokenhub.tencentmaas.com/v1/chat/completions",
    "https://tokenhub.tencentmaas.com/v1/responses",
    "https://tokenhub.tencentmaas.com/v1/messages",
    "https://api.lkeap.cloud.tencent.com/v1/chat/completions",
    "https://api.lkeap.cloud.tencent.com/anthropic/v1/messages",
    "https://api.lkeap.cloud.tencent.com/v3/chat/completions",
    "https://api.lkeap.cloud.tencent.com/api/anthropic/v1/messages",
    "https://api.lkeap.cloud.tencent.com/coding/v3/chat/completions",
    "https://api.lkeap.cloud.tencent.com/coding/anthropic/v1/messages",
    # 月之暗面 Kimi
    "https://api.moonshot.cn/v1/chat/completions",
    "https://api.kimi.com/coding/v1/chat/completions",
    "https://api.kimi.com/coding/v1/messages",
    # 硅基流动 SiliconFlow
    "https://api.siliconflow.cn/v1/chat/completions",
    "https://api.siliconflow.cn/v1/messages",
    # MiniMax
    "https://api.minimaxi.com/v1/chat/completions",
    "https://api.minimaxi.com/v1/responses",
    "https://api.minimaxi.com/anthropic/v1/messages",
    # 小米 MiMo
    "https://api.xiaomimimo.com/v1/chat/completions",
    "https://api.xiaomimimo.com/v1/responses",
    "https://api.xiaomimimo.com/v1/messages",
    # 阶跃星辰 StepFun
    "https://api.stepfun.com/v1/chat/completions",
    "https://api.stepfun.com/v1/responses",
    "https://api.stepfun.com/v1/messages",
    # 讯飞 星火
    "https://spark-api-open.xf-yun.com/v1/chat/completions",
    # 商汤 SenseNova
    "https://api.sensenova.cn/compatible-mode/v2/chat/completions",
    # 百川智能
    "https://api.baichuan-ai.com/v1/chat/completions",
}


def _check_whitelist(base_url: str) -> bool:
    """校验 base_url 是否在官方白名单内（初赛/决赛前必查）。

    fail-closed（2026-08-21 补回被误回滚的安全修复）：默认阻断非白名单端点，
    赛时天然安全（不依赖 ENFORCE_WHITELIST 环境变量，忘了设也不会误用非白名单
    而被取消资格）。仅显式 CTF_AGENT_ALLOW_OFF_WHITELIST=1（本地开发）才放行。
    匹配规则：完整 URL 相等（含 scheme/path），忽略 query/fragment。
    """
    if not base_url:
        return False
    # 去掉末尾斜杠归一化
    norm = base_url.rstrip("/")
    if norm in {u.rstrip("/") for u in WHITELISTED_ENDPOINTS}:
        return True
    # 平台官方大模型网关（合规透明代理，参赛手册要求必须走网关）：
    # https://llm-gateway.dasctf.com/llm-gateway/proxy/e/<endpointCode>
    # endpointCode 每个渠道一个，无法枚举，按 host 前缀放行（透明代理上游仍在白名单内）
    if "llm-gateway.dasctf.com" in base_url:
        return True
    # 非白名单：fail-closed 默认阻断（违规会被取消比赛资格）
    if os.getenv("CTF_AGENT_ALLOW_OFF_WHITELIST", "0") == "1":
        logger.warning("⚠️ 端点不在白名单（本地开发显式放行）：%s", base_url)
        return True
    # 逃生开关（2026-08-22 锐评第五节整改）：fail-closed 拦截时醒目提示一键逃生。
    # CTF_AGENT_ESCAPE_PROVIDER=<白名单provider> 在 _resolve_settings 里已提前切换；
    # 到这里的 base_url 仍非白名单，说明既没设逃生也没放行——打印醒目救援提示。
    logger.error(
        "❌❌ FAIL-CLOSED 拦截（违规会被取消比赛资格）❌❌\n"
        "   端点不在白名单: %s\n"
        "   白名单见 llm/client.py WHITELISTED_ENDPOINTS 或参赛手册第三节。\n"
        "   ── 一键逃生（三选一，任选其一即恢复）──\n"
        "   ① 切白名单 provider：set CTF_AGENT_ESCAPE_PROVIDER=baidu  （决赛最快逃生）\n"
        "   ② 本地开发放行：      set CTF_AGENT_ALLOW_OFF_WHITELIST=1\n"
        "   ③ 检查残留变量：      CTF_AGENT_LLM_BASE_URL 残留会覆盖端点（快照可见）",
        base_url,
    )
    return False


# ── 对外核心 API ──────────────────────────────────────────


def ai_chat(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> Optional[str]:
    """调用统一 LLM 端点，返回模型回复文本（失败开放）。

    Args:
        messages: OpenAI 风格消息列表，如 [{"role": "user", "content": "..."}]
        system: 可选的系统提示词，插入到消息最前面
        temperature: 采样温度，默认 0.3
        max_tokens: 最大输出 token 数
        model: 显式指定模型；None 时用配置的轻量模型（deepseek-v4-flash）
        provider: 显式指定 provider（deepseek/qwen/...）；None 时读环境变量

    Returns:
        模型回复文本；任何错误均返回 None。
    """
    if not isinstance(messages, list) or not messages:
        logger.warning("ai_chat: messages 参数无效，返回 None")
        return None
    try:
        settings = _resolve_settings(model, provider=provider)
        if not settings["api_key"]:
            logger.warning(
                "未配置 LLM API Key（DEEPSEEK_API_KEY / CTF_AGENT_LLM_API_KEY），AI 能力不可用"
            )
            return None
        # P0 熔断检查（2026-08-21）：provider 已熔断则直接跳过（不空转烧时间）
        _prov = settings.get("provider", "")
        if _prov and provider_circuit_open(_prov):
            logger.warning(
                "provider=%s 已熔断（连续 401/402/403），本次调用直接跳过", _prov)
            return None
        content, _usage = _post_chat(
            _with_system(messages, system),
            temperature=temperature,
            max_tokens=max_tokens,
            settings=settings,
        )
        if content is None:
            logger.warning("LLM 返回了空内容")
        else:
            _circuit_record_success(_prov)
        return content
    except Exception as exc:  # noqa: BLE001 - 失败开放：任何异常都不外抛
        logger.warning("AI 调用失败（fail-open 返回 None）: %s", exc)
        return None


def ai_chat_with_usage(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> tuple[Optional[str], dict]:
    """同 ai_chat，额外返回本次调用的真实 token usage（P1-1 记账修正）。

    Returns:
        (文本, usage dict) —— usage = {"prompt_tokens","completion_tokens","total_tokens"}；
        任何失败返回 (None, 全 0 usage)。
    """
    _ZERO = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    if not isinstance(messages, list) or not messages:
        logger.warning("ai_chat_with_usage: messages 参数无效，返回 (None, 0)")
        return None, dict(_ZERO)
    try:
        settings = _resolve_settings(model, provider=provider)
        if not settings["api_key"]:
            logger.warning(
                "未配置 LLM API Key（DEEPSEEK_API_KEY / CTF_AGENT_LLM_API_KEY），AI 能力不可用"
            )
            return None, dict(_ZERO)
        _prov = settings.get("provider", "")
        if _prov and provider_circuit_open(_prov):
            logger.warning(
                "provider=%s 已熔断（连续 401/402/403），本次调用直接跳过", _prov)
            return None, dict(_ZERO)
        content, usage = _post_chat(
            _with_system(messages, system),
            temperature=temperature,
            max_tokens=max_tokens,
            settings=settings,
        )
        if content is not None:
            _circuit_record_success(_prov)
        return content, usage
    except Exception as exc:  # noqa: BLE001 - 失败开放：任何异常都不外抛
        logger.warning("AI 调用失败（fail-open 返回 None）: %s", exc)
        return None, dict(_ZERO)


def ai_chat_json_with_usage(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> tuple[Optional[dict], dict]:
    """同 ai_chat_json，额外返回本次调用的真实 token usage（P1-1 记账修正）。"""
    _ZERO = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    content, usage = ai_chat_with_usage(
        messages, system=system, temperature=temperature, max_tokens=max_tokens,
        model=model, provider=provider,
    )
    if content is None:
        return None, usage
    try:
        obj = _extract_json_object(content)
    except Exception as exc:  # noqa: BLE001 - 解析异常也走失败开放
        logger.warning("JSON 解析异常（fail-open 返回 None）: %s", exc)
        return None, usage
    if obj is None:
        logger.warning("LLM 返回内容无法解析为 JSON 对象")
    return obj, usage


# ── 异步包装（P0-2 修复 2026-08-21）：同步 httpx.post 放进线程池 ──
# 原 ai_chat 为同步调用，在 asyncio 事件循环内直接执行会阻塞整个循环
# （多任务伪并发，asyncio.wait_for 无法中断同步 I/O）。竞速/主 Agent
# 场景改用以下 async 版本：to_thread 拷贝当前 context 到工作线程，
# 线程信号量/熔断逻辑保持在同步函数内部，行为不变。
import asyncio as _asyncio  # noqa: E402


async def ai_chat_async(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> Optional[str]:
    """异步版 ai_chat（同步调用放线程池，不阻塞事件循环）。"""
    return await _asyncio.to_thread(
        ai_chat, messages, system=system, temperature=temperature,
        max_tokens=max_tokens, model=model, provider=provider,
    )


async def ai_chat_json_async(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> Optional[dict]:
    """异步版 ai_chat_json（同步调用放线程池，不阻塞事件循环）。"""
    return await _asyncio.to_thread(
        ai_chat_json, messages, system=system, temperature=temperature,
        max_tokens=max_tokens, model=model, provider=provider,
    )


async def ai_chat_json_async_with_usage(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> tuple[Optional[dict], dict]:
    """异步版 ai_chat_json_with_usage（真实 token 记账 + 不阻塞事件循环）。"""
    return await _asyncio.to_thread(
        ai_chat_json_with_usage, messages, system=system, temperature=temperature,
        max_tokens=max_tokens, model=model, provider=provider,
    )


def ai_chat_json(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 2000,
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> Optional[dict]:
    """调用统一 LLM 端点并解析 JSON 对象回复（失败开放）。

    自动剥离 ```json ... ``` 代码围栏，并尝试从文本中提取首个完整 JSON 对象。
    任何失败均返回 None。

    Args:
        参数含义同 ai_chat；temperature 默认 0.1 以获得更高确定性。
        provider: 显式指定 provider（deepseek/qwen/...）；None 时读环境变量
    """
    content = ai_chat(
        messages, system=system, temperature=temperature, max_tokens=max_tokens,
        model=model, provider=provider,
    )
    if content is None:
        return None
    try:
        obj = _extract_json_object(content)
    except Exception as exc:  # noqa: BLE001 - 解析异常也走失败开放
        logger.warning("JSON 解析异常（fail-open 返回 None）: %s", exc)
        return None
    if obj is None:
        logger.warning("LLM 返回内容无法解析为 JSON 对象")
    return obj


def get_model_for_attempt(attempt: int, provider: Optional[str] = None) -> str:
    """分级降级调度：attempt 0-1 轻量模型，attempt >=2 重型模型。

    v2.0 核心：替代多模型竞速，成本可控。
    P0 修复（2026-08-21）：provider 显式时此前恒返回该 provider 默认模型，
    导致多 provider 场景（run.py build_solver 显式传 provider）attempt>=2 也
    不升级重型——deepseek-reasoner 深推理永不触发（高难题解不出）。
    现在：attempt>=2 且 provider 有专属重型 env（CTF_AGENT_{PROV}_HEAVY_MODEL）
    或命中 provider→重型映射（deepseek→deepseek-reasoner、qwen→deepseek-v4-pro-0813、
    tokenhub→deepseek-v4-pro）时升级；无重型可升的 provider 维持默认（不破坏竞速）。
    """
    config = AppConfig.from_env()
    if provider:
        default_base_url, default_model = _resolve_provider_defaults(provider)
        if attempt >= config.upgrade_after_attempts:
            heavy = os.getenv(f"CTF_AGENT_{provider.upper()}_HEAVY_MODEL", "").strip()
            if heavy:
                return heavy
            # provider→重型模型映射（P0-2 修复 2026-08-21）：此前仅 deepseek 特殊
            # 处理，qwen/tokenhub 等白名单 provider 显式传入时 attempt>=2 恒返回
            # 默认轻量模型，重型深推理永不触发（高难题解不出）。
            heavy_map = {
                "deepseek": "deepseek-reasoner",   # 官方 R1：正式赛高难题深推理主源
                "qwen": "deepseek-v4-pro-0813",    # 百炼免费重型（实测 HTTP 200）
                "tokenhub": "deepseek-v4-pro",     # 腾讯 TokenHub 免费重型
            }
            if provider in heavy_map:
                return heavy_map[provider]
        return default_model
    if attempt >= config.upgrade_after_attempts:
        return config.heavy_model
    return config.light_model


# ── 配置解析 ──────────────────────────────────────────────


def _resolve_settings(model: Optional[str], provider: Optional[str] = None) -> dict:
    """按优先级解析 LLM 端点配置（每次调用实时读取，支持运行时变更）。

    Args:
        model: 显式模型名；None 时用配置的轻量模型
        provider: 显式 provider（deepseek/qwen/...）；None 时读环境变量
                  CTF_AGENT_LLM_PROVIDER（多模型竞速时两个 solver 各传不同 provider）
    """
    config = AppConfig.from_env()

    # 逃生开关（2026-08-22 锐评第五节整改）：CTF_AGENT_ESCAPE_PROVIDER=<白名单provider>
    # 强制切换——解决「fail-closed 拦截所有调用 + 无降级可用档」的致命设计：
    # 赛中任一环境变量误设导致当前 provider 全瘫时，只需设逃生变量即可一键切到
    # 已知可用白名单 provider（baidu/tokenhub/mimo…），不必重启排查残留。
    # 触发条件：显式 provider 形参传入（竞速多 solver 各传各的）时不劫持；
    #           否则只要设了逃生变量就强制切换（用户显式意图最高优先）。
    _escape_provider = os.getenv("CTF_AGENT_ESCAPE_PROVIDER", "").strip().lower()
    provider_env = os.getenv("CTF_AGENT_LLM_PROVIDER", "").strip().lower()
    if provider is None and _escape_provider:
        logger.warning("🛟 逃生开关触发：provider → %s（CTF_AGENT_ESCAPE_PROVIDER，默认源 %s）",
                       _escape_provider, provider_env or config.llm_provider)
        provider = _escape_provider
    provider = provider or provider_env or config.llm_provider
    # key 必须在逃生切换之后按最终 provider 解析（逃生到新 provider 用新 key）
    api_key = resolve_api_key(provider)

    default_base_url, default_model = _resolve_provider_defaults(provider)
    # 强制白名单模式：非白名单 provider 在解析期即置空端点，
    # 下游 _check_whitelist 会直接阻断（防误配置导致取消比赛资格）。
    # 仅当 CTF_AGENT_ENFORCE_WHITELIST=1 时生效，本地开发（未设）不受影响。
    if os.getenv("CTF_AGENT_ENFORCE_WHITELIST", "0") == "1":
        if provider and provider not in OFFICIAL_WHITELIST_PROVIDERS:
            logger.error(
                "❌ provider %s 不在官方白名单，强制模式已禁用（端点置空，请求将被阻断）",
                provider,
            )
            default_base_url = ""
    # 显式 provider 时默认端点/模型按 provider 计算（config.llm_base_url 是
    # 环境变量 provider 的，多 provider 场景会冲突——修复：只让显式环境变量覆盖）
    # P0 修复（2026-08-21 赛后）：显式 provider 时【忽略】全局 CTF_AGENT_LLM_BASE_URL！
    # 正式赛根因：父进程环境残留 CTF_AGENT_LLM_BASE_URL=https://qianfan.baidubce.com，
    # 导致 moonshot/ark 等 provider 的请求被强制打到千帆端点 → 401 invalid_iam_token，
    # 赛末 10 分钟才排查出来。显式 provider（多模型竞速必传）必须用 provider 默认端点，
    # 只有未显式指定 provider（走环境变量单一 provider）时才允许全局 base_url 覆盖。
    if provider:
        base_url = default_base_url
        # 仅当全局 base_url 与 provider 默认端点一致（罕见同端点场景）时保留显式值
        env_base = os.getenv("CTF_AGENT_LLM_BASE_URL", "").strip()
        if env_base and env_base.rstrip("/") == default_base_url.rstrip("/"):
            base_url = env_base
    else:
        base_url = (
            os.getenv("CTF_AGENT_LLM_BASE_URL", "").strip()
            or default_base_url
        )
    # 模型优先级：显式 model > provider 专属 env > provider 默认模型
    # （provider 显式时忽略全局 CTF_AGENT_LIGHT_MODEL——多 provider 场景它属于别的端点，
    #   如百炼的 qwen3.7-plus 不能打到千帆/小米端点）
    if provider:
        model = (
            model
            or os.getenv(f"CTF_AGENT_{provider.upper()}_MODEL", "").strip()
            or default_model
        )
    else:
        model = (
            model
            or os.getenv("CTF_AGENT_LIGHT_MODEL", "").strip()
            or default_model
        )
    try:
        timeout_seconds = max(int(config.llm_timeout_seconds or DEFAULT_TIMEOUT_SECONDS), 1)
        # P1 修复（2026-08-21 第五轮锐评）：重型模型 read timeout 须放宽——
        # deepseek-reasoner（R1）常态 60-300s；v4-pro 深推理亦常 >60s。
        # 60s 统一 read timeout 会掐死 attempt≥2 升级路径。
        _ml = str(model).lower()
        if "reasoner" in _ml or "v4-pro" in _ml:
            timeout_seconds = max(timeout_seconds, 300)
    except (TypeError, ValueError):
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    if httpx is not None:
        timeout = httpx.Timeout(
            connect=CONNECT_TIMEOUT_SECONDS,
            read=float(timeout_seconds),
            write=CONNECT_TIMEOUT_SECONDS,
            pool=CONNECT_TIMEOUT_SECONDS,
        )
    else:
        timeout = float(timeout_seconds)

    return {
        "api_key": api_key,
        "base_url": base_url,
        "model": model,
        "provider": provider,
        "timeout": timeout,
    }


# ── HTTP 调用 ─────────────────────────────────────────────


def _post_chat(
    messages: list[dict],
    temperature: float,
    max_tokens: int,
    settings: dict,
) -> tuple[Optional[str], dict]:
    """向 OpenAI 兼容端点发起一次 chat/completions 请求。

    Returns:
        (文本内容, usage dict)；任何失败返回 (None, 全 0 usage)。
    """
    _ZERO = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    if httpx is None:
        logger.warning("httpx 未安装，无法发起 LLM 请求")
        return None, dict(_ZERO)

    # 白名单合规校验：违规端点直接拒绝（防误配置取消比赛资格）
    if not _check_whitelist(settings.get("base_url", "")):
        return None, dict(_ZERO)

    payload = {
        "model": settings["model"],
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    # P0 热修复（2026-08-21 16:58 赛中）：moonshot kimi-k2.6 只接受 temperature=1，
    # 否则 400 invalid temperature。arks/moonshot 直连必须强制 1。
    if settings.get("provider") in ("moonshot", "ark") or "kimi" in settings.get("model", ""):
        payload["temperature"] = 1

    # DeepSeek V4/flash 等非推理模型关闭 thinking 换取速度；
    # 但 deepseek-reasoner（R1）/deepseek-r1 必须保留 thinking，否则深推理能力失效。
    # 百炼模式下 deepseek-v4-pro-0813 等模型也需关闭（provider=qwen 但 model 是 deepseek）
    _model_name = (settings.get("model", "") or "").lower()
    _is_reasoner = ("reasoner" in _model_name or "r1" in _model_name or "-r1-" in _model_name
                    or _model_name.endswith("r1"))
    if not _is_reasoner and (settings.get("provider") in ("deepseek", "mimo")
                             or _model_name.startswith("deepseek")):
        payload["thinking"] = {"type": "disabled"}
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings['api_key']}",
    }
    try:
        with _LLM_HTTP_SEMAPHORE:
            response = httpx.post(
                settings["base_url"],
                json=payload,
                headers=headers,
                timeout=settings["timeout"],
                trust_env=False,
            )
            if response.status_code == 400:
                # P0-5 降级兜底（2026-08-21）：400 通常是 payload 里有非法
                # 控制字符或超长字段（plan 附件 base64/hex 全文进上下文）。
                # 剥控制字符 + 截断超长字段后重发一次；仍 400 才走失败路径。
                degraded = _degrade_messages(messages)
                if degraded != messages:
                    logger.warning(
                        "LLM 400 响应，已做降级重试（剥控制字符+截断超长字段）| 响应体: %s",
                        response.text[:500],
                    )
                    payload["messages"] = degraded
                    response = httpx.post(
                        settings["base_url"],
                        json=payload,
                        headers=headers,
                        timeout=settings["timeout"],
                        trust_env=False,
                    )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        # 4xx/5xx：记录响应体供赛中定位（彩排暴露 400 被吞，高难题攻坚必备）
        body = ""
        try:
            body = exc.response.text[:500]
        except Exception:  # noqa: BLE001
            pass
        logger.warning(
            "LLM HTTP %s 失败：payload.model=%s messages=%d条 max_tokens=%s | 响应体: %s",
            exc.response.status_code, settings.get("model", ""),
            len(messages), max_tokens, body,
        )
        # P0 熔断（2026-08-21）：401/402/403 为永久性故障，连续计数达阈值即熔断
        _circuit_record_failure(settings.get("provider", ""), exc.response.status_code)
        return None, dict(_ZERO)
    except Exception as exc:  # noqa: BLE001 - 失败开放
        logger.warning("LLM HTTP 请求失败: %s", exc)
        return None, dict(_ZERO)
    data = response.json()
    usage = _extract_usage(data)
    _record_usage(data)  # 向后兼容：仍更新模块级 _LAST_USAGE
    return _extract_content(data), usage


def _strip_control_chars(s: str) -> str:
    """剥控制字符（保留 \\t\\n\\r），防 JSON 因非法控制字符报 400。"""
    return "".join(ch for ch in s if ch >= " " or ch in "\t\n\r")


def _degrade_messages(messages: list[dict]) -> list[dict]:
    """400 降级：剥控制字符 + 截断超长字段到 ~300 字符，用于重发一次。

    逐条净化 content（str 或多模态分片数组），超长字段截断并打标记；
    净化后与原内容一致则返回原列表（调用方据此判断是否真的降级了）。
    """
    out: list[dict] = []
    changed = False
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            clean = _strip_control_chars(content)
            if len(clean) > 300:
                clean = clean[:300] + "…[截断]"
            if clean != content:
                changed = True
            out.append({**msg, "content": clean})
        elif isinstance(content, list):
            parts = []
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    t = _strip_control_chars(part["text"])
                    if len(t) > 300:
                        t = t[:300] + "…[截断]"
                    if t != part["text"]:
                        changed = True
                    parts.append({**part, "text": t})
                else:
                    parts.append(part)
            out.append({**msg, "content": parts})
        else:
            out.append(msg)
    return out if changed else messages


def _with_system(messages: list[dict], system: Optional[str]) -> list[dict]:
    """将系统提示词插入消息开头（若已有 system 消息则覆盖其内容）。"""
    if not system:
        return messages
    if messages and messages[0].get("role") == "system":
        return [{**messages[0], "content": system}, *messages[1:]]
    return [{"role": "system", "content": system}, *messages]


def _extract_content(data: Any) -> Optional[str]:
    """从 OpenAI 兼容响应中防御性提取文本内容。

    DeepSeek V4 thinking 模式下 message.content 可能为空，推理在
    reasoning_content；此处 content 为空时回退到 reasoning_content。
    """
    try:
        message = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        return None
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        # 回退：thinking 模式的推理内容
        content = message.get("reasoning_content")
    if isinstance(content, str):
        return content.strip() or None
    if isinstance(content, list):  # 部分多模态端点以分片数组返回文本
        parts = [
            part["text"]
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        return "".join(parts).strip() or None
    return None


def _repair_json(text: str) -> str:
    """轻量 JSON 修复：去尾逗号、单引号 key→双引号、截到末个完整 }。"""
    # 1. 截到末个完整 }（丢弃尾部残缺片段/解释性文字）
    if text.count("{") > text.count("}"):
        idx = text.rfind("}")
        if idx != -1:
            text = text[: idx + 1]
    # 2. 去尾逗号（对象/数组结尾）
    text = re.sub(r",\s*}", "}", text)
    text = re.sub(r",\s*\]", "]", text)
    # 3. 单引号 key → 双引号：{ 'key': ... } 或 ,'key': ...
    text = re.sub(r"([{,]\s*)'([^']+)'\s*:", r'\1"\2":', text)
    # 4. 单引号字符串值 → 双引号：: 'val' → : "val"（key 已转，此处不会误伤）
    text = re.sub(r":\s*'([^']*)'", r': "\1"', text)
    return text


def _extract_json_object(content: str) -> Optional[dict]:
    """从 LLM 文本中提取 JSON 对象：剥离代码围栏，必要时截取首尾花括号。"""
    if not isinstance(content, str):
        return None

    text = content.strip()
    if text.startswith("```"):  # 剥离 markdown 代码围栏
        lines = [line for line in text.splitlines() if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass
        # 修复 pass（P0 顺手 2026-08-21）：尾逗号/单引号 key/残缺尾部 →
        # 轻量 repair 后再试一次；失败仍返回 None（保持原有 fail-open）。
        repaired = _repair_json(candidate)
        if repaired != candidate:
            try:
                parsed = json.loads(repaired)
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                pass

    return None
