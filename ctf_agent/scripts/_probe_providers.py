#!/usr/bin/env python
"""批量探测白名单 provider 可用性（跑基准前必做，防白等 17 分钟）。

用法：.venv/Scripts/python.exe scripts/_probe_providers.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402
from config import resolve_api_key, _resolve_provider_defaults  # noqa: E402

# 白名单 provider（AGENTS/作战手册登记）
PROVIDERS = [
    "deepseek", "qwen", "baidu", "glm", "tencent", "ark",
    "tokenhub", "xfyun", "siliconflow", "moonshot",
    "minimax", "stepfun", "baichuan",
]


def probe(provider: str):
    """探测单个 provider，返回 (状态, 详情)。"""
    try:
        key = resolve_api_key(provider) or ""
    except Exception as exc:  # noqa: BLE001
        return "NOKEY", f"resolve失败 {type(exc).__name__}"
    if not key:
        return "NOKEY", "无 key"
    try:
        defaults = _resolve_provider_defaults(provider)
        base = defaults[0]
        models = [m for m in defaults[1:] if m]
        model = models[0] if models else "gpt-4o-mini"
    except Exception as exc:  # noqa: BLE001
        return "CFG_ERR", str(exc)[:60]

    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "say OK"}],
        "max_tokens": 10,
    }
    try:
        r = httpx.post(base, headers=headers, json=payload, timeout=20)
        if r.status_code == 200:
            return "OK", f"{model} 200"
        body = r.text[:110].replace("\n", " ")
        return f"HTTP{r.status_code}", body
    except Exception as exc:  # noqa: BLE001
        return "EXC", f"{type(exc).__name__}: {str(exc)[:60]}"


def main():
    print(f"{'provider':<14} {'status':<10} detail")
    print("-" * 90)
    ok = []
    for p in PROVIDERS:
        st, detail = probe(p)
        mark = "  <== 可用" if st == "OK" else ""
        print(f"{p:<14} {st:<10} {detail}{mark}")
        if st == "OK":
            ok.append(p)
    print("-" * 90)
    if ok:
        print(f"✅ 可用 provider: {', '.join(ok)}")
        return 0
    print("❌ 无任何可用 provider —— 跑任何真跑基准都会是 presolve-only 假数据")
    return 1


if __name__ == "__main__":
    sys.exit(main())
