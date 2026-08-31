"""赛前白名单合规预检（2026-08-20 锐评 P0-3 整改）。

核对当前环境实际启用的全部 provider 是否落在官方白名单内，
非白名单 provider 赛前必须禁用（违规会被取消比赛资格）。

用法：
    python scripts/_preflight_whitelist.py
    # 退出码 0=全合规，1=有非白名单 provider 被启用或强制开关未开

检查项：
1. CTF_AGENT_LLM_PROVIDER（主 provider）
2. CTF_AGENT_RACE_PROVIDERS（竞速池，逗号分隔）
3. CTF_AGENT_ENFORCE_WHITELIST 是否=1（强制阻断开关）
4. 每个 provider 的 base_url 二次核对 llm.client.WHITELISTED_ENDPOINTS
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# 权威白名单 provider 集合（config.OFFICIAL_WHITELIST_PROVIDERS，
# 来源：参赛手册第三节「授权 API 端点白名单」逐条核对）。
# 与 llm.client.WHITELISTED_ENDPOINTS 互为表里；以它为唯一判定依据，
# 不再依赖易过期的手写禁用清单（曾误将 sensenova 标为禁用，已纠正）。


def _env(name: str, default: str = "") -> str:
    val = os.getenv(name, default).strip()
    if val:
        return val
    # Windows 注册表回退（与 config._env_or_registry 一致）
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                v, _ = winreg.QueryValueEx(k, name)
                return str(v).strip()
        except OSError:
            pass
    return ""


def collect_active_providers() -> list[str]:
    """收集当前环境实际启用的全部 provider。"""
    providers: list[str] = []
    main = _env("CTF_AGENT_LLM_PROVIDER", "baidu").lower()
    if main:
        providers.append(main)
    race = _env("CTF_AGENT_RACE_PROVIDERS", "")
    if race:
        for p in race.split(","):
            p = p.strip().lower()
            if p and p not in providers:
                providers.append(p)
    return providers


def check() -> int:
    from config import _resolve_provider_defaults, OFFICIAL_WHITELIST_PROVIDERS
    try:
        from llm.client import WHITELISTED_ENDPOINTS
    except Exception as exc:  # noqa: BLE001
        print(f"❌ 无法加载 llm.client.WHITELISTED_ENDPOINTS：{exc}")
        return 1

    wl_set = {u.rstrip("/") for u in WHITELISTED_ENDPOINTS}

    print("=" * 64)
    print("西湖论剑 CTF-Agent 白名单合规预检")
    print("=" * 64)

    # 1. 强制阻断开关
    enforce = _env("CTF_AGENT_ENFORCE_WHITELIST", "0")
    print(f"\n[1] CTF_AGENT_ENFORCE_WHITELIST = {enforce!r}")
    if enforce != "1":
        print("  ⚠️ 未设为 1：非白名单端点只警告不阻断——赛前必须 set CTF_AGENT_ENFORCE_WHITELIST=1")
    else:
        print("  ✅ 强制阻断已开启")

    # 2. 启用的 provider
    active = collect_active_providers()
    print(f"\n[2] 当前启用 provider（{len(active)}）：{active or '(空)'}")

    # 3. 逐个核对（以 OFFICIAL_WHITELIST_PROVIDERS 为唯一判定依据）
    violations: list[str] = []
    print("\n[3] 逐 provider 核对：")
    for p in active:
        base_url, _model, _, _ = _resolve_provider_defaults(p)
        in_wl = p in OFFICIAL_WHITELIST_PROVIDERS
        url_in_wl = base_url.rstrip("/") in wl_set
        if not in_wl or not url_in_wl:
            print(f"  ❌ {p:14s} base={base_url}  (provider合规={in_wl}, 端点命中={url_in_wl})")
            violations.append(p)
        else:
            print(f"  ✅ {p:14s} base={base_url}")

    # 4. 默认竞速池合规性（锐评 P0-3 关注点：多模型竞速是否全白名单）
    print("\n[4] 默认竞速池 provider 合规：")
    race_defaults = ("baidu", "mimo", "deepseek", "tokenhub", "glm", "ark", "moonshot", "xfyun")
    race_violations = []
    for p in race_defaults:
        bu, _, _, _ = _resolve_provider_defaults(p)
        ok = p in OFFICIAL_WHITELIST_PROVIDERS and bu.rstrip("/") in wl_set
        print(f"  {'✅' if ok else '❌'} race:{p:10s} base={bu}")
        if not ok:
            race_violations.append(p)
    if race_violations:
        print(f"  (竞速池违规 provider：{race_violations})")

    # 5. 结论
    print("\n" + "=" * 64)
    all_violations = violations + race_violations
    if all_violations:
        print(f"❌ 合规失败：非白名单 provider 被启用/竞速：{all_violations}")
        print("   赛前必须禁用（删除对应 env 或改 provider），否则违规取消资格。")
        if enforce != "1":
            print("   且 CTF_AGENT_ENFORCE_WHITELIST 未设为 1，阻断开关未开。")
        return 1
    if enforce != "1":
        print("⚠️ provider 全在白名单，但强制阻断开关未开——建议 set CTF_AGENT_ENFORCE_WHITELIST=1")
        return 1
    print("✅ 全合规：所有启用 provider + 默认竞速池均在白名单内，强制阻断开关已开。")
    return 0


if __name__ == "__main__":
    sys.exit(check())
