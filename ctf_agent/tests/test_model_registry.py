from __future__ import annotations

import sys
import types

from core.model_registry import ModelRegistry, ModelMeta, DEFAULT_WHITELIST_PROVIDERS


def test_register_and_lookup():
    reg = ModelRegistry()
    reg.register("baidu", "ernie-x",
                 ModelMeta(name="ernie-x", provider="baidu", ctx=128000, free=True))
    m = reg.lookup("ernie-x")
    assert m is not None
    assert m.provider == "baidu"
    assert m.free is True
    assert m.ctx == 128000


def test_register_bulk_and_lookup_vendor():
    reg = ModelRegistry()
    n = reg.register_bulk("dashscope", {
        "deepseek-r1": {"kind": "reasoner", "vendor": "deepseek", "free": True},
        "qwen3.7-flash": {"kind": "chat", "vendor": "qwen", "free": True},
    })
    assert n == 2
    assert reg.lookup("deepseek-r1").vendor == "deepseek"
    ds = reg.list_models(vendor="deepseek")
    assert len(ds) == 1 and ds[0].name == "deepseek-r1"


def test_is_whitelisted_builtin_and_extend():
    reg = ModelRegistry()
    assert reg.is_whitelisted("deepseek")
    assert reg.is_whitelisted("baidu")
    assert not reg.is_whitelisted("openai")  # 非白名单
    reg.add_whitelist_provider("openai")
    assert reg.is_whitelisted("openai")


def test_list_models_filters():
    reg = ModelRegistry()
    reg.register_bulk("baidu", {
        "ernie-free": {"free": True, "ctx": 128000},
        "ernie-paid": {"free": False, "ctx": 8000},
    })
    free = reg.list_models(free_only=True)
    assert len(free) == 1 and free[0].name == "ernie-free"
    baidu = reg.list_models(provider="baidu")
    assert len(baidu) == 2


def test_lite_llm_backend_injection():
    reg = ModelRegistry()
    reg.lite_llm_backend = lambda name: {"model": name, "via": "litellm"}
    assert reg.lite_llm_backend("gpt-4o") == {"model": "gpt-4o", "via": "litellm"}


def test_from_config_fail_open_or_load():
    reg = ModelRegistry.from_config()
    assert isinstance(reg, ModelRegistry)
    # 内置白名单始终可用（不依赖 config 加载成败）
    assert reg.is_whitelisted("deepseek")
    assert reg.is_whitelisted("baidu")
    # 失败开放：无论如何不抛异常，返回合法注册表
    assert reg.providers() is not None


def test_from_config_loads_injected_config(monkeypatch):
    """验证 from_config 真的会读取 config 登记表（用注入的假 config 隔离环境）。"""
    fake = types.ModuleType("config")
    fake.OFFICIAL_WHITELIST_PROVIDERS = {"deepseek", "baidu"}
    fake.BAIDU_QIANFAN_ERNIE_MODELS = {"ernie-test": {"ctx": 8000, "free": True}}
    fake.DASHSCOPE_FREE_MODELS = {"qwen-test": {"kind": "chat", "vendor": "qwen", "free": True}}
    monkeypatch.setitem(sys.modules, "config", fake)

    reg = ModelRegistry.from_config()
    assert reg.is_whitelisted("deepseek")
    assert reg.lookup("ernie-test") is not None
    assert reg.lookup("qwen-test").vendor == "qwen"
