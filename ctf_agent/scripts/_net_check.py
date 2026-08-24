# -*- coding: utf-8 -*-
"""赛前网络三查（锐评 C1：宿主环境着火是初赛漏诊的第三层根因）。

2026-08-21 初赛复盘盲区：所有根因都盯着代码/配置，没有一层看"代码跑在哪台机器上"。
本机已知病灶：Chromium 系 Network service crashed、Clash 死后 git 全局代理
http://127.0.0.1:7890 变死代理、WSL 卡 StartPending。靶机 HTTP 000 / 429 风暴 /
LLM 多源 401 中，至少一部分可以由本地网络故障解释——但赛前没人查过。

本脚本三查（纯可达性探测，不发 LLM 请求、不烧 token）：
  ① 代理 127.0.0.1:7890 存活？（git 全局代理指向它；死代理会让 git/部分 HTTP 直连失败）
  ② 各 LLM 白名单端点直连可达？（trust_env=False 绕过系统代理，直连验证）
  ③ 平台 DASCTF_BASE_URL 直连可达？

判定：收到任何 HTTP 响应（含 401/404）= 可达；连接失败/超时 = 不可达。
退出码：0 = 关键项全可达；1 = 存在不可达（--strict 时阻断）；2 = 平台未配置。

用法：
  .venv/Scripts/python.exe scripts/_net_check.py           # 诊断模式（setup.sh 默认接入）
  .venv/Scripts/python.exe scripts/_net_check.py --strict  # 任一关键项不可达即 exit 1
  .venv/Scripts/python.exe scripts/_net_check.py --only baidu,deepseek,platform
"""
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROXY_HOST, PROXY_PORT = "127.0.0.1", 7890
TIMEOUT = 5.0


def _proxy_alive() -> bool:
    try:
        with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=2.0):
            return True
    except OSError:
        return False


def _probe_direct(url: str) -> tuple[bool, str]:
    """直连探测（绕过系统/代理环境变量）；任何 HTTP 响应都算可达。"""
    import httpx

    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=False, trust_env=False) as c:
            r = c.get(url, headers={"User-Agent": "ctf-net-check/1.0"})
            return True, f"HTTP {r.status_code}"
    except httpx.TimeoutException:
        return False, f"超时 >{TIMEOUT:.0f}s"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {str(exc)[:80]}"


def _platform_base_url() -> str:
    from scripts._race_start import _get_base_url

    return _get_base_url() or ""


def _llm_targets() -> list[tuple[str, str]]:
    """返回 [(provider, base_url)]：只查有 key 的白名单 provider。"""
    from config import OFFICIAL_WHITELIST_PROVIDERS, _resolve_provider_defaults, resolve_api_key

    out = []
    for prov in sorted(OFFICIAL_WHITELIST_PROVIDERS):
        try:
            key = resolve_api_key(prov)
        except Exception:  # noqa: BLE001
            key = ""
        if not key:
            continue
        base, _model = _resolve_provider_defaults(prov)
        if base:
            out.append((prov, base))
    return out


def main() -> int:
    strict = "--strict" in sys.argv
    only = None
    for a in sys.argv:
        if a.startswith("--only="):
            only = {x.strip() for x in a.split("=", 1)[1].split(",") if x.strip()}

    t0 = time.monotonic()
    print(f"=== 网络三查（锐评 C1，strict={strict}，直连 trust_env=False）===")

    # ① 代理存活
    alive = _proxy_alive()
    if alive:
        print(f"  ① 代理 {PROXY_HOST}:{PROXY_PORT}  ✅ 存活")
    else:
        print(f"  ① 代理 {PROXY_HOST}:{PROXY_PORT}  ❌ 死亡")
        print("     git 全局代理指向此地址（git config --global http.proxy）——git push/pull 会失败；")
        print("     临时绕过：git -c http.proxy= -c https.proxy= <cmd>，或修复 Clash 后重启。")
    proxy_fail = not alive

    # ② LLM 端点直连
    llm_targets = _llm_targets()
    if only:
        llm_targets = [(p, u) for p, u in llm_targets if p in only]
    llm_fail = 0
    if llm_targets:
        print(f"  ② LLM 端点直连（{len(llm_targets)} 个有 key 的白名单 provider）:")
        for prov, url in llm_targets:
            ok, detail = _probe_direct(url)
            mark = "✅" if ok else "❌"
            print(f"     {mark} {prov:<12} {url}  ({detail})")
            llm_fail += 0 if ok else 1
    else:
        print("  ② LLM 端点直连：⚠️ 无可解析 key（注册表/环境变量均未命中），跳过")

    # ③ 平台直连
    base = _platform_base_url()
    platform_fail = 0
    if only and "platform" in only or not only:
        if base:
            ok, detail = _probe_direct(base)
            mark = "✅" if ok else "❌"
            print(f"  ③ 平台直连        {mark} {base}  ({detail})")
            platform_fail = 0 if ok else 1
        else:
            print("  ③ 平台直连        ⚠️ DASCTF_BASE_URL 未配置，跳过")

    # 汇总
    dt = time.monotonic() - t0
    fatal = llm_fail > 0 or platform_fail > 0
    print(f"\n  耗时 {dt:.1f}s")
    if fatal:
        if strict:
            print("❌ --strict 模式：存在不可达端点——机器着火，不允许开战")
            print("   处置：修 Clash/代理 → 重启；git 操作用 -c http.proxy= 直连；")
            print("   LLM 全灭时改走平台官方网关（llm-gateway.dasctf.com）或手动切换存活源。")
            return 1
        print(f"⚠️ 存在不可达端点（LLM {llm_fail} / 平台 {platform_fail}，代理死亡={proxy_fail}）——诊断模式不阻断；")
        print("   开战前请处理，或 `--strict` 强制阻断。")
        return 1 if (llm_fail or platform_fail) else 0
    if proxy_fail and strict:
        print("⚠️ 代理死亡但关键端点直连全可达——仅影响 git 操作（可用 -c http.proxy= 绕过）")
    print("✅ 网络三查通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
