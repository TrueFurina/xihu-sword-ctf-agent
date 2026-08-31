"""CTF-Agent 配置模块。

设计原则（对齐 v2.0 架构）：
1. 分级降级调度：attempt 0-1 用轻量模型（V4-Flash），attempt 2-3 升级重型模型（V4-Pro）
2. 失败开放（fail-open）：未配置 Key 时自动降级 Mock 模式，保证开发期链路可跑
3. 环境变量优先：每次调用实时读取，支持运行时切换

密钥解析优先级：
    1. 环境变量 DEEPSEEK_API_KEY（DeepSeek 主用）
    2. 环境变量 CTF_AGENT_LLM_API_KEY（通用备用）
    3. 回退到本配置的 llm_api_key 字段
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Optional

# 净化告警去重（同一组合只打一次，防每步 LLM 调用刷屏）
_SANITIZE_WARNED: set = set()


# ── Windows 注册表环境变量回退（setx 兼容）────────────────────────
# `setx` 写入 HKCU\Environment 后不会同步到当前进程环境变量；
# 本模块作为最底层被导入时，把注册表里已有的 CTF_AGENT_*/API KEY 同步到 os.environ，
# 这样全项目所有 os.getenv() 都能读到 setx 写入的值，避免正式赛启动时因环境变量
# 未继承而静默降级 Mock 模式。
_CTF_ENV_KEYS = (
    "CTF_AGENT_USE_REAL_LLM", "CTF_AGENT_LLM_PROVIDER", "CTF_AGENT_LLM_BASE_URL",
    "CTF_AGENT_LLM_API_KEY", "CTF_AGENT_LIGHT_MODEL", "CTF_AGENT_HEAVY_MODEL",
    "CTF_AGENT_RACE_MODELS", "CTF_AGENT_RACE_PROVIDERS", "CTF_AGENT_RACE_PROFILE",
    "CTF_AGENT_RACE_WALLCLOCK", "CTF_AGENT_UPGRADE_AFTER",
    "CTF_AGENT_MAX_CONCURRENCY", "CTF_AGENT_RATE_LIMIT", "CTF_AGENT_CIRCUIT_FAILURES",
    "CTF_AGENT_MAX_RETRIES", "CTF_AGENT_PER_Q_BUDGET", "CTF_AGENT_GLOBAL_BUDGET",
    "CTF_AGENT_DOWNGRADE_RATIO", "CTF_AGENT_MAX_RETRIES_HARD", "CTF_AGENT_SANDBOX_TIMEOUT",
    "CTF_AGENT_SANDBOX_MODE", "CTF_AGENT_LLM_TIMEOUT", "CTF_AGENT_ENFORCE_WHITELIST",
    "CTF_AGENT_SESSION_ID", "CTF_AGENT_ALLOW_HUMAN",
    "CTF_AGENT_PER_Q_WALLCLOCK", "CTF_AGENT_HARD_WALLCLOCK",
    "DASHSCOPE_API_KEY", "DEEPSEEK_API_KEY", "MIMO_API_KEY",
    "QIANFAN_API_KEY", "ZHIPU_API_KEY", "HUNYUAN_API_KEY", "XFYUN_API_KEY",
    "SILICONFLOW_API_KEY", "MOONSHOT_API_KEY", "ARK_API_KEY",
    "DASCTF_BASE_URL", "DASCTF_TOKEN", "CTF_AGENT_PLATFORM_TOKEN",
)


def _env_or_registry(name: str) -> str:
    """环境变量 + Windows 注册表回退（setx 后当前进程环境变量不刷新）。"""
    val = os.getenv(name, "").strip()
    if val:
        return val
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                value, _ = winreg.QueryValueEx(k, name)
                return str(value).strip()
        except OSError:
            pass
    return ""


def _sync_registry_to_environ() -> None:
    """模块导入时：注册表值注入 os.environ（仅填充缺失项，不覆盖已存在值）。"""
    if sys.platform != "win32":
        return
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            for name in _CTF_ENV_KEYS:
                if os.getenv(name):
                    continue
                try:
                    value, _ = winreg.QueryValueEx(k, name)
                    os.environ[name] = str(value)
                except OSError:
                    pass
    except OSError:
        pass


_sync_registry_to_environ()  # 模块加载即同步——后续所有 os.getenv 都能读到注册表值


# ── 赛时网络修复（2026-08-21 P0，代理根因）────────────────────────
# 系统 HTTP_PROXY/HTTPS_PROXY 指向未启动的本地代理（127.0.0.1:7890），
# httpx/requests 默认 trust_env=True 会走该代理导致 ConnectError 连接拒绝，
# 而 curl --noproxy 直连正常（实测 HTTP 200）。清空代理变量，强制直连。
# 影响面：平台 API (pro.dasctf.com)、LLM (deepseek)、web 靶机 (1.14.x.x) 均为直连，
# 无需外部代理。此段在 config 被导入时执行（最底层模块），覆盖全项目 httpx 调用。
for _proxy_key in (
    "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
    "ALL_PROXY", "all_proxy", "FTP_PROXY", "ftp_proxy",
):
    os.environ.pop(_proxy_key, None)

DEFAULT_TIMEOUT_SECONDS = 60  # 读取超时（P0-2 2026-08-21：120s→60s）——EASY 墙钟 120s 不被单步读超时烧穿；60s 足够 qwen3.7-plus 解题推理输出，仍防单步极慢拖死并发池
CONNECT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_CONCURRENCY = 8          # 多题并行上限（信号量）
DEFAULT_MAX_RETRIES = 3              # 校验-反馈循环最大重试次数
DEFAULT_SANDBOX_TIMEOUT = 30         # 沙盒执行超时（秒）


@dataclass
class AppConfig:
    """全局配置。所有字段可从环境变量覆盖。"""

    # ── LLM 基础 ──────────────────────────────────────────
    use_real_llm: bool = False       # CTF_AGENT_USE_REAL_LLM=1 启用真实 API
    # P1-9 修复（2026-08-21 赛后）：单一事实源——默认 provider 统一为 baidu 千帆。
    # 此前三处漂移：dataclass 默认 "deepseek" / from_env 默认 "baidu" /
    # _resolve_provider_defaults 兜底 "deepseek-v4-flash"，注释还互相矛盾。
    # 千帆 ernie-4.5-turbo 三个免费模型（2026-08-28 充值后用户指定唯一使用）：
    # ernie-4.5-turbo-32k / 128k / vl。deepseek 402 余额、qwen 额度问题为历史，已不相关。
    # 显式 provider（竞速池）
    # 不受影响；仅影响无显式 provider 的单源模式。
    llm_provider: str = "baidu"      # 默认千帆 baidu（白名单内，实测存活主源）
    llm_base_url: str = ""           # 留空则按 provider 默认
    llm_api_key: str = ""            # 兜底 Key（一般用环境变量）
    llm_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS

    # ── 分级降级调度（v2.0 核心）──────────────────────────
    # 2026-08-28：baidu 千帆充值后免费档仅 3 个 ernie-4.5-turbo 模型（用户指定唯一使用）：
    # ernie-4.5-turbo-32k（轻量快速）/ ernie-4.5-turbo-128k（大上下文强推理）/ ernie-4.5-turbo-vl（视觉）。
    light_model: str = "ernie-4.5-turbo-32k"   # attempt 0：轻量快速推理
    mid_model: str = "ernie-4.5-turbo-128k"    # 中型：pwn/reverse 起步 + attempt 1（大上下文）
    heavy_model: str = "ernie-4.5-turbo-128k"  # attempt 2-3：重型强推理（免费档仅 128k 最强）
    vision_model: str = "ernie-4.5-turbo-vl"   # 视觉：图内渲染文字 flag（xuanhun_signin 类缺口）
    upgrade_after_attempts: int = 2          # 连续失败 N 次后升级重型模型

    # ── 调度与限流 ───────────────────────────────────────
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY
    rate_limit_per_minute: int = 60          # 令牌桶：每分钟最大请求数
    circuit_breaker_failures: int = 5        # 连续失败 N 次熔断该 provider

    # ── 校验-反馈循环 ────────────────────────────────────
    max_retries: int = DEFAULT_MAX_RETRIES
    flag_pattern: str = r"flag\{[^}]+\}"     # 默认 flag 格式（可被题目覆盖）

    # ── 预算熔断（v2.0 三级保护）─────────────────────────
    per_question_token_budget: int = 80000     # 单题 token 上限（硬停，防死循环烧钱）
    global_token_budget: int = 800000          # 全局预算（硬停，防整场预算击穿）
    budget_downgrade_ratio: float = 0.5        # 单题用量超该比例→强制降级轻量模型
    max_retries_hard: int = 3                  # 单题最大重试硬上限（第三级保护）
    # ── 墙钟硬止损（2026-08-20 锐评 P0-2 整改）──────────
    # 单题墙钟上限（秒）：超过即强制 break 并标记 wallclock_timeout，
    # 防止单步 LLM 推理+工具执行过长（实测 max 1486s/题）拖死 3h 赛程的并发池。
    # 步数止损（stuck_count>=2）只防"连续失败"，防不住"单步极慢"——墙钟是第二道闸。
    per_question_wallclock: int = 300
    # HARD/VERY_HARD 分级墙钟（2026-08-21 锐评 P1-2 整改）：原 600s 高于
    # 「specialcurve2 实测 487s 深推理仍未解出」的灾难值，3h 赛制下深推超时浪费。
    # 下调至 480s（≤ 灾难依据），保留 CTF_AGENT_HARD_WALLCLOCK 环境变量可覆盖。
    hard_wallclock: int = 480

    # ── 沙盒 ─────────────────────────────────────────────
    sandbox_timeout: int = DEFAULT_SANDBOX_TIMEOUT
    sandbox_mode: str = "subprocess"         # subprocess（Docker 决赛前修复后切 docker）

    # ── 路径 ─────────────────────────────────────────────
    questions_dir: str = "data/questions"
    templates_dir: str = "data/templates"
    results_dir: str = "data/results"

    @classmethod
    def from_env(cls) -> "AppConfig":
        """从环境变量构建配置（未设置则用默认值）。"""
        # P0 修复（2026-08-21 17:22 赛后）：默认 provider 从 deepseek 改为 baidu 千帆。
        # deepseek 正式赛 402 余额耗尽——默认打它会单源空转 0 解出。
        # 千帆 ernie-3.5 为全系统最强单源（测试赛 72.4% 跑分）+ 当前实测 200 OK。
        # 显式 provider（竞速池）不受此影响；仅影响无显式 provider 的单源模式。
        provider = os.getenv("CTF_AGENT_LLM_PROVIDER", "").strip().lower() or "baidu"
        base_url, light_model, mid_model_def, heavy_model_def = _resolve_provider_defaults(provider)
        # P0 修复（2026-08-21 17:40 赛后）：模型/端点一致性净化——防父进程残留
        # CTF_AGENT_LIGHT_MODEL=deepseek-chat / HEAVY_MODEL=deepseek-reasoner 污染单源模式
        # （16:48 灾难同款根因：模型打错端点 → 404）。残留模型与 provider 默认模型不一致时
        # 自动回退默认；如需覆盖必须同时显式设置 provider（多 provider 竞速传显式 provider，
        # 走 _resolve_settings 的 provider 分支，不受此净化影响）。
        import logging as _logging
        _logger = _logging.getLogger(__name__)
        _env_light = os.getenv("CTF_AGENT_LIGHT_MODEL", "").strip()
        if _env_light and _env_light != light_model:
            _wkey = ("light", _env_light, provider)
            if _wkey not in _SANITIZE_WARNED:
                _SANITIZE_WARNED.add(_wkey)
                _logger.warning(
                    "⚠️ CTF_AGENT_LIGHT_MODEL=%s 与 provider=%s 默认模型 %s 不一致，已回退默认",
                    _env_light, provider, light_model,
                )
            _env_light = ""
        _env_heavy = os.getenv("CTF_AGENT_HEAVY_MODEL", "").strip()
        if _env_heavy and _env_heavy != heavy_model_def:
            _wkey = ("heavy", _env_heavy, provider)
            if _wkey not in _SANITIZE_WARNED:
                _SANITIZE_WARNED.add(_wkey)
                _logger.warning(
                    "⚠️ CTF_AGENT_HEAVY_MODEL=%s 与 provider=%s 默认重型模型 %s 不一致，已回退默认",
                    _env_heavy, provider, heavy_model_def,
                )
            _env_heavy = ""
        return cls(
            use_real_llm=os.getenv("CTF_AGENT_USE_REAL_LLM", "0") == "1",
            llm_provider=provider,
            llm_base_url=os.getenv("CTF_AGENT_LLM_BASE_URL", "").strip() or base_url,
            llm_api_key=os.getenv("CTF_AGENT_LLM_API_KEY", ""),
            llm_timeout_seconds=_int_env("CTF_AGENT_LLM_TIMEOUT", DEFAULT_TIMEOUT_SECONDS),
            light_model=_env_light or light_model,
            # 2026-09-01 修复：mid/heavy 随 provider 走（见 _resolve_provider_defaults），
            # 不再硬编码 ernie-4.5-turbo-128k，避免非 baidu provider 重型升级 404。
            mid_model=os.getenv("CTF_AGENT_MID_MODEL", "").strip() or mid_model_def,
            heavy_model=_env_heavy or heavy_model_def,
            vision_model=os.getenv("CTF_AGENT_VISION_MODEL", "").strip() or "ernie-4.5-turbo-vl",
            upgrade_after_attempts=_int_env("CTF_AGENT_UPGRADE_AFTER", 2),
            max_concurrency=_int_env("CTF_AGENT_MAX_CONCURRENCY", DEFAULT_MAX_CONCURRENCY),
            rate_limit_per_minute=_int_env("CTF_AGENT_RATE_LIMIT", 60),
            circuit_breaker_failures=_int_env("CTF_AGENT_CIRCUIT_FAILURES", 5),
            max_retries=_int_env("CTF_AGENT_MAX_RETRIES", DEFAULT_MAX_RETRIES),
            per_question_token_budget=_int_env("CTF_AGENT_PER_Q_BUDGET", 80000),
            global_token_budget=_int_env("CTF_AGENT_GLOBAL_BUDGET", 800000),
            budget_downgrade_ratio=_float_env("CTF_AGENT_DOWNGRADE_RATIO", 0.5),
            max_retries_hard=_int_env("CTF_AGENT_MAX_RETRIES_HARD", 3),
            per_question_wallclock=_int_env("CTF_AGENT_PER_Q_WALLCLOCK", 300),
            hard_wallclock=_int_env("CTF_AGENT_HARD_WALLCLOCK", 480),
            sandbox_timeout=_int_env("CTF_AGENT_SANDBOX_TIMEOUT", DEFAULT_SANDBOX_TIMEOUT),
            sandbox_mode=os.getenv("CTF_AGENT_SANDBOX_MODE", "subprocess"),
        )


def _float_env(name: str, default: float) -> float:
    try:
        val = float(_env_or_registry(name) or str(default))
        return max(min(val, 1.0), 0.05)
    except ValueError:
        return default


def _int_env(name: str, default: int) -> int:
    try:
        return max(int(_env_or_registry(name) or str(default)), 1)
    except ValueError:
        return default


# ── 官方授权白名单 provider（参赛手册第三节，唯一真相源）────────
# 来源：第九届西湖论剑初赛参赛手册「三、授权 API 端点白名单」逐条核对。
# 用于 ENFORCE_WHITELIST=1 时强制禁用非白名单 provider（见 llm/client._resolve_settings）。
# 注意：与 llm/client.WHITELISTED_ENDPOINTS 互为表里——端点集合是运行时闸门，
# 此 provider 集合是解析期前置闸门，两者必须一致。
OFFICIAL_WHITELIST_PROVIDERS = {
    "deepseek", "qwen", "baidu", "ark", "glm", "tencent", "tokenhub",
    "lkeap", "moonshot", "siliconflow", "minimax", "mimo", "stepfun",
    "xfyun", "sensenova", "baichuan",
}


# ── 百度千帆 ERNIE 全量模型登记表（2026-08-28 实测核对）──────────────
# 来源：百度智能云千帆官方「模型列表」(cloud.baidu.com/doc/qianfan/s/rmh4stp0j)
#       + 文心大模型「文生文模型列表」(ai.baidu.com/ai-doc/AISTUDIO/rm344erns)
#       + Agent 开发平台免费分发模型清单 (cloud.baidu.com/doc/qianfan/s/Lmh4sv69i)。
# 仅登记千帆端点（base_url=https://qianfan.baidubce.com/v2/chat/completions）可用的
# 百度原生 ERNIE 系列模型，供显式 CTF_AGENT_*_MODEL 覆盖或能力路由选择。
# ⚠️ 活跃三档默认仍只用用户指定的 3 个免费 turbo（见 AppConfig.light/mid/heavy/vision）；
#    其余标 free=False 为付费/配额档，仅在显式覆盖或充值额度充足时使用。
# 字段：ctx=上下文 token 数；free=是否免费档；vision=是否多模态视觉；family=代际。
BAIDU_QIANFAN_ERNIE_MODELS: dict[str, dict] = {
    # ── ERNIE 5.x 旗舰（付费/配额档，高能力）──
    "ernie-5.1":                     {"ctx": 128000,  "free": False, "vision": False, "family": "ernie-5"},
    "ernie-5.0":                     {"ctx": 128000,  "free": False, "vision": False, "family": "ernie-5"},
    "ernie-5.0-thinking-preview":    {"ctx": 128000,  "free": False, "vision": False, "family": "ernie-5"},
    # ── ERNIE 4.5 Turbo（用户指定唯一免费活跃档）──
    "ernie-4.5-turbo-32k":           {"ctx": 32000,   "free": True,  "vision": False, "family": "ernie-4.5-turbo"},
    "ernie-4.5-turbo-128k":          {"ctx": 128000,  "free": True,  "vision": False, "family": "ernie-4.5-turbo"},
    "ernie-4.5-turbo-vl":            {"ctx": 128000,  "free": True,  "vision": True,  "family": "ernie-4.5-turbo"},
    "ernie-4.5-turbo-vl-32k":        {"ctx": 32000,   "free": False, "vision": True,  "family": "ernie-4.5-turbo"},
    "ernie-4.5-turbo-20260402":      {"ctx": 128000,  "free": False, "vision": False, "family": "ernie-4.5-turbo"},
    # ── ERNIE X1 推理（付费/配额档）──
    "ernie-x1-turbo-32k":            {"ctx": 32000,   "free": False, "vision": False, "family": "ernie-x1"},
    # ── ERNIE 4.0 系列（付费/配额档）──
    "ernie-4.0-turbo-128k":          {"ctx": 128000,  "free": False, "vision": False, "family": "ernie-4.0"},
    "ernie-4.0-turbo-8k":            {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-4.0"},
    "ernie-4.0-8k":                  {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-4.0"},
    "ernie-4.0-8k-latest":           {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-4.0"},
    "ernie-4.0-8k-0613":             {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-4.0"},
    "ernie-4.0-8k-preview":          {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-4.0"},
    # ── ERNIE 3.5 系列（付费/配额档）──
    "ernie-3.5-128k":                {"ctx": 128000,  "free": False, "vision": False, "family": "ernie-3.5"},
    "ernie-3.5-128k-preview":        {"ctx": 128000,  "free": False, "vision": False, "family": "ernie-3.5"},
    "ernie-3.5-8k":                  {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-3.5"},
    "ernie-3.5-8k-0613":             {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-3.5"},
    "ernie-3.5-8k-preview":          {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-3.5"},
    # ── 轻量/极速系列（付费/配额档，成本低）──
    "ernie-speed-8k":                {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-speed"},
    "ernie-speed-128k":              {"ctx": 128000,  "free": False, "vision": False, "family": "ernie-speed"},
    "ernie-lite-8k":                 {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-lite"},
    "ernie-tiny-8k":                 {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-tiny"},
    "ernie-char-8k":                {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-char"},
    "ernie-char-fiction-8k":         {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-char"},
    "ernie-functions-8k":            {"ctx": 8000,    "free": False, "vision": False, "family": "ernie-functions"},
}


def list_baidu_models(free_only: bool = False, vision_only: bool = False) -> list[str]:
    """千帆 ERNIE 模型清单（按上下文从大到小）。

    free_only: 仅返回免费档（用户指定 3 个 turbo）；
    vision_only: 仅返回多模态视觉模型（图内渲染文字 flag 缺口）。
    """
    items = BAIDU_QIANFAN_ERNIE_MODELS.items()
    if free_only:
        items = [(n, m) for n, m in items if m["free"]]
    if vision_only:
        items = [(n, m) for n, m in items if m["vision"]]
    return [n for n, _ in sorted(items, key=lambda kv: kv[1]["ctx"], reverse=True)]


def _resolve_provider_defaults(provider: str) -> tuple[str, str, str, str]:
    """返回 (base_url, light_model, mid_model, heavy_model)。

    2026-09-01 修复（P1 能力突破，重型升级 404 根因）：
    此前仅返回 (base_url, light)，中型/重型模型在 from_env 里硬编码为
    ernie-4.5-turbo-128k（千帆独占）。当 provider 非 baidu（如 qwen/dashscope）时，
    main_agent 在 attempt>=2 升级重型会把 ernie 模型打到 dashscope → 404 model_not_found，
    随后判定"重型升级连续失败"直接放弃止损——crypto/reverse 等需深推理的题永远 0 解出
    （8/31 dryrun crypto+reverse 0/2 真因：heavy 打到错误端点）。现 mid/heavy 随 provider 走，
    保证重型升级端点-模型匹配。各 provider 默认模型源自参赛手册白名单 + 实测可用：
    - baidu：用户 8-28 充值后指定唯一使用的 3 个 ernie-4.5-turbo（32k 轻 / 128k 中重）。
    - qwen：qwen3.7-flash(轻) / qwen3.8-max(中重，dashscope 真实存在，非 kimi-k3)。
    - deepseek：deepseek-chat(轻) / deepseek-reasoner(R1 深推理，重型)。
    - tokenhub：hy3(轻) / deepseek-v4-pro(重型，TokenHub 免费深推理)。
    """
    mapping = {
        "deepseek": ("https://api.deepseek.com/chat/completions", "deepseek-chat", "deepseek-chat", "deepseek-reasoner"),
        "qwen": ("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", "qwen3.7-flash", "qwen3.8-max", "qwen3.8-max"),
        "baidu": ("https://qianfan.baidubce.com/v2/chat/completions", "ernie-4.5-turbo-32k", "ernie-4.5-turbo-128k", "ernie-4.5-turbo-128k"),
        "mimo": ("https://api.xiaomimimo.com/v1/chat/completions", "mimo-v2.5-pro", "mimo-v2.5-pro", "mimo-v2.5-pro"),
        "glm": ("https://open.bigmodel.cn/api/paas/v4/chat/completions", "glm-4.7", "glm-4.7", "glm-4.7"),
        "tencent": ("https://api.hunyuan.cloud.tencent.com/v1/chat/completions", "hunyuan-lite", "hunyuan-lite", "hunyuan-lite"),
        "ark": ("https://ark.cn-beijing.volces.com/api/v3/chat/completions", "doubao-seed-2-1-pro-260628", "doubao-seed-2-1-pro-260628", "doubao-seed-2-1-pro-260628"),
        "sensenova": ("https://api.sensenova.cn/compatible-mode/v2/chat/completions", "sensenova-6.8-flash-lite", "sensenova-6.8-flash-lite", "sensenova-6.8-flash-lite"),
        "tokenhub": ("https://tokenhub.tencentmaas.com/v1/chat/completions", "hy3", "hy3", "deepseek-v4-pro"),
        "xfyun": ("https://spark-api-open.xf-yun.com/v1/chat/completions", "lite", "lite", "lite"),
        "siliconflow": ("https://api.siliconflow.cn/v1/chat/completions", "Qwen/Qwen2.5-7B-Instruct", "Qwen/Qwen2.5-7B-Instruct", "Qwen/Qwen2.5-7B-Instruct"),
        "moonshot": ("https://api.moonshot.cn/v1/chat/completions", "kimi-k2.6", "kimi-k2.6", "kimi-k2.6"),
        "openai": ("https://api.openai.com/v1/chat/completions", "gpt-5.6-luna", "gpt-5.6-luna", "gpt-5.6-luna"),
    }
    if provider in mapping:
        return mapping[provider]
    # 兜底默认走千帆 baidu（P1-9 修复 2026-08-21：单一事实源，与 from_env/dataclass 一致）
    return ("https://qianfan.baidubce.com/v2/chat/completions", "ernie-3.5-8k-preview", "ernie-3.5-8k-preview", "ernie-3.5-8k-preview")


def resolve_api_key(provider: str = "") -> str:
    """按 provider 解析 API Key（显式传入优先于环境变量/配置）。

    优先级：
    - qwen provider：DASHSCOPE_API_KEY > CTF_AGENT_LLM_API_KEY > 配置兜底
    - mimo：MIMO_API_KEY > 兜底；glm/baidu/tencent/xfyun/siliconflow/moonshot/ark：对应环境变量
    - 其他（deepseek/openai）：DEEPSEEK_API_KEY > CTF_AGENT_LLM_API_KEY > 配置兜底
    """
    config = AppConfig.from_env()
    provider_env = os.getenv("CTF_AGENT_LLM_PROVIDER", "").strip().lower()
    provider = (provider or provider_env or config.llm_provider).lower()
    if provider == "qwen":
        return (
            _env_or_registry("DASHSCOPE_API_KEY")
            or _env_or_registry("CTF_AGENT_LLM_API_KEY")
            or config.llm_api_key
        )
    if provider == "mimo":
        return (
            _env_or_registry("MIMO_API_KEY")
            or _env_or_registry("CTF_AGENT_LLM_API_KEY")
            or config.llm_api_key
        )
    # 白名单免费源统一 key 映射（B 计划：注册后填对应环境变量即可）
    _key_env = {
        "baidu": "QIANFAN_API_KEY",
        "glm": "ZHIPU_API_KEY",
        "tencent": "HUNYUAN_API_KEY",
        "tokenhub": "TOKENHUB_API_KEY",
        "ark": "ARK_API_KEY",
        "grok": "GROK_API_KEY",
        "tokenrouter": "TOKENROUTER_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "sensenova": "SENSENOVA_API_KEY",
        "peezy": "PEEZY_API_KEY",
        "modelscope": "MODELSCOPE_API_KEY",
        "xfyun": "XFYUN_API_KEY",
        "siliconflow": "SILICONFLOW_API_KEY",
        "moonshot": "MOONSHOT_API_KEY",
    }
    if provider in _key_env:
        return (
            _env_or_registry(_key_env[provider])
            or _env_or_registry("CTF_AGENT_LLM_API_KEY")
            or config.llm_api_key
        )
    return (
        _env_or_registry("DEEPSEEK_API_KEY")
        or _env_or_registry("CTF_AGENT_LLM_API_KEY")
        or config.llm_api_key
    )


# ── 生效配置快照（2026-08-22 锐评第五节整改：赛前人工 5 秒核对）────────
# 设计层病根：CTF_AGENT_LLM_BASE_URL 单点变量残留即全瘫、fail-closed 拦截
# 无醒目逃生提示。快照让启动时一眼看清：provider/端点/模型/key 状态/白名单
# 状态/残留变量——残留环境变量（父进程带进来的）会在快照里打 ⚠️。
_LEGACY_RESIDUE_ENVS = (
    "CTF_AGENT_LLM_BASE_URL",       # 单点爆破：残留覆盖所有 provider 端点（显式 provider 已豁免）
    "CTF_AGENT_LIGHT_MODEL",        # 残留模型与 provider 默认不一致会打错端点
    "CTF_AGENT_HEAVY_MODEL",
)


def _mask_key(key: str) -> str:
    """API Key 打码：只显示前 4 位 + 长度，防快照日志泄密。"""
    if not key:
        return "<未设置>"
    return f"{key[:4]}…({len(key)}字符)"


def print_effective_config_snapshot(provider: Optional[str] = None) -> dict:
    """打印/返回生效配置快照（赛前人工核对用，5 秒看完）。

    覆盖：
    - 当前 provider + 端点 + 轻/重型模型（防端点-模型不匹配 404/400）
    - key 状态（打码）
    - 白名单状态（ENFORCE_WHITELIST + 端点是否在白名单）
    - 残留环境变量告警（父进程残留的 BASE_URL/MODEL 会打 ⚠️）
    - 逃生开关状态（CTF_AGENT_ESCAPE_PROVIDER / CTF_AGENT_ALLOW_OFF_WHITELIST）
    """
    import logging as _logging

    _logger = _logging.getLogger(__name__)
    cfg = AppConfig.from_env()
    prov = (provider or cfg.llm_provider or "").lower()
    base_url, light_model, _, _ = _resolve_provider_defaults(prov)
    key = resolve_api_key(prov)
    enforce = os.getenv("CTF_AGENT_ENFORCE_WHITELIST", "0") == "1"
    escape = os.getenv("CTF_AGENT_ESCAPE_PROVIDER", "").strip().lower()
    allow_off = os.getenv("CTF_AGENT_ALLOW_OFF_WHITELIST", "0") == "1"

    snap = {
        "provider": prov,
        "base_url": base_url,
        "light_model": light_model,
        "heavy_model": cfg.heavy_model,
        "api_key_masked": _mask_key(key),
        "enforce_whitelist": enforce,
        "endpoint_in_whitelist": None,  # 由调用方/下游判定（避免 import 环）
        "escape_provider": escape or None,
        "allow_off_whitelist": allow_off,
        "residue_warnings": [],
    }
    # 残留变量告警（仅在值确实存在且可能影响当前 provider 时提示）
    for _env in _LEGACY_RESIDUE_ENVS:
        _val = os.getenv(_env, "").strip()
        if _val:
            snap["residue_warnings"].append(f"{_env}={_val[:60]}")
    _logger.info(
        "┌─ 生效配置快照（2026-08-22 锐评整改，赛前 5 秒核对）────────────────"
    )
    _logger.info("│ provider      : %s", snap["provider"])
    _logger.info("│ base_url      : %s", snap["base_url"])
    _logger.info("│ light/heavy   : %s / %s", snap["light_model"], snap["heavy_model"])
    _logger.info("│ api_key       : %s", snap["api_key_masked"])
    _logger.info("│ 白名单强制     : %s", "ON" if enforce else "off")
    _logger.info("│ 逃生开关      : escape_provider=%s  allow_off_whitelist=%s",
                 snap["escape_provider"] or "-", "ON" if allow_off else "off")
    for _w in snap["residue_warnings"]:
        _logger.warning("│ ⚠️ 残留环境变量: %s", _w)
    if not key or key == "<未设置>":
        _logger.warning("│ ⚠️ API Key 未设置——真实 LLM 请求将失败/降级 Mock")
    _logger.info("└────────────────────────────────────────────────────────────")
    return snap
