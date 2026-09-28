"""G6 · 模型路由注册表（¥0 抽象，轨道 A）。

差异分析（2027-prep/差异分析-SOTA对比-20260928.md）指出本仓「模型路由广度」窄
（仅 deepseek/baidu/qwen/tokenhub 等白名单 provider），而 SOTA（CAI）用 LiteLLM 接
300+ 模型。本模块提供一个**可扩展的模型注册表抽象**，把现有 provider 白名单 +
模型登记表收敛为统一接口，并为将来接入 LiteLLM（300+ 模型）预留后端注入点。

设计约束（防注水 / 防自欺）：
- 纯数据结构 + 查询逻辑，**不读 KPI / 账本、不碰 presolve 闸门**。
- 不启任何网络 / 不消耗 token；LiteLLM 后端以可注入 callable 形式存在，默认 None。
- `from_config()` 仅在能安全 import 项目 config 时加载真实登记表，否则返回空注册表
  （失败开放，不阻断开发期链路）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class ModelMeta:
    """单一模型的元数据。"""

    name: str
    provider: str
    kind: str = "chat"            # chat / reasoner / coder / mt / ocr / video
    ctx: int = 0                  # 上下文窗口 token 数
    free: bool = False            # 是否免费档
    vision: bool = False          # 是否多模态视觉
    vendor: Optional[str] = None  # 底层厂商（如 dashscope 上的 deepseek）

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "provider": self.provider,
            "kind": self.kind,
            "ctx": self.ctx,
            "free": self.free,
            "vision": self.vision,
            "vendor": self.vendor,
        }


# 内置官方授权白名单 provider（与 config.OFFICIAL_WHITELIST_PROVIDERS 同源，
# 此处复制一份使 ModelRegistry 自包含、不强制依赖 config）。
DEFAULT_WHITELIST_PROVIDERS = frozenset({
    "deepseek", "qwen", "baidu", "ark", "glm", "tencent", "tokenhub",
    "lkeap", "moonshot", "siliconflow", "minimax", "mimo", "stepfun",
    "xfyun", "sensenova", "baichuan",
})


class ModelRegistry:
    """可扩展的模型路由注册表。

    用法：
        reg = ModelRegistry()
        reg.register("baidu", "ernie-4.5-turbo-128k",
                     ModelMeta(name="ernie-4.5-turbo-128k", provider="baidu",
                               ctx=128000, free=True))
        meta = reg.lookup("ernie-4.5-turbo-128k")
        if reg.is_whitelisted("deepseek"):
            ...
        # 将来接入 LiteLLM：
        reg.lite_llm_backend = my_litellm_router
        models = reg.list_models(free_only=True)
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelMeta] = {}
        self._whitelist: set[str] = set(DEFAULT_WHITELIST_PROVIDERS)
        # LiteLLM 后端注入点（默认 None = 未接，零 token）。
        self.lite_llm_backend: Optional[Callable[[str], Any]] = None

    # ── 注册 ──
    def register(self, provider: str, name: str,
                 meta: Optional[ModelMeta] = None) -> ModelMeta:
        if meta is None:
            meta = ModelMeta(name=name, provider=provider)
        else:
            meta.provider = provider
            meta.name = name
        self._models[name] = meta
        return meta

    def register_bulk(self, provider: str, models: dict[str, dict]) -> int:
        """批量注册。models: {name: {kind/ctx/free/vision/vendor}}。"""
        count = 0
        for name, spec in models.items():
            self.register(provider, name, ModelMeta(
                name=name,
                provider=provider,
                kind=spec.get("kind", "chat"),
                ctx=spec.get("ctx", 0),
                free=spec.get("free", False),
                vision=spec.get("vision", False),
                vendor=spec.get("vendor"),
            ))
            count += 1
        return count

    # ── 查询 ──
    def lookup(self, name: str) -> Optional[ModelMeta]:
        return self._models.get(name)

    def is_whitelisted(self, provider: str) -> bool:
        return provider.lower() in self._whitelist

    def add_whitelist_provider(self, provider: str) -> None:
        """扩展白名单（为 LiteLLM 新增 provider 预留）。"""
        self._whitelist.add(provider.lower())

    def list_models(self, provider: Optional[str] = None,
                    free_only: bool = False,
                    vendor: Optional[str] = None) -> list[ModelMeta]:
        out: list[ModelMeta] = []
        for m in self._models.values():
            if provider is not None and m.provider != provider:
                continue
            if free_only and not m.free:
                continue
            if vendor is not None and m.vendor != vendor:
                continue
            out.append(m)
        return out

    def providers(self) -> set[str]:
        return {m.provider for m in self._models.values()}

    # ── 从现有 config 加载真实登记表（失败开放）──
    @classmethod
    def from_config(cls) -> "ModelRegistry":
        """加载项目 config 的真实登记表。import config 安全（仅读环境变量/注册表，无网络）。

        若 config 不可用（如测试隔离环境），返回空注册表，不抛异常（fail-open）。
        """
        reg = cls()
        try:
            import config as _cfg  # 延迟导入，避免顶层循环依赖
            for p in getattr(_cfg, "OFFICIAL_WHITELIST_PROVIDERS", set()):
                reg.add_whitelist_provider(p)
            reg.register_bulk("baidu", getattr(_cfg, "BAIDU_QIANFAN_ERNIE_MODELS", {}))
            reg.register_bulk("dashscope", getattr(_cfg, "DASHSCOPE_FREE_MODELS", {}))
        except Exception:
            # fail-open：任何导入 / 解析错误都返回空注册表
            pass
        return reg
