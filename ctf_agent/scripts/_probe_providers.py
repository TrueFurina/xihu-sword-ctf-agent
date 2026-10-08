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
    rows = []
    for p in PROVIDERS:
        st, detail = probe(p)
        mark = "  <== 可用" if st == "OK" else ""
        print(f"{p:<14} {st:<10} {detail}{mark}")
        rows.append({"provider": p, "status": st, "detail": detail})
        if st == "OK":
            ok.append(p)
    print("-" * 90)
    # 结论必须落盘（2026-10-08）：「哪几个源活着」此前只存在于人写的注释里，
    # 随余额/欠费漂移后注释必然过期，而跑批默认值照它配——同一故障第四次复发。
    # 落盘后任何「谁活着」的判断一律经 `_llm_pool_status` 读快照，不许手写。
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from _llm_pool_status import write_record

        path = write_record(rows, source="scripts/_probe_providers.py")
        print(f"📝 探测快照已写入: {path}（后续判定以快照为准，勿手抄进注释）")
    except Exception as exc:  # noqa: BLE001 - 落盘失败不影响本次探测结论，但必须报出来
        print(f"⚠️ 快照落盘失败（本次结论无法被后续门禁复用）: {type(exc).__name__}: {exc}")
    if ok:
        print(f"✅ 可用 provider: {', '.join(ok)}")
        return 0
    print("❌ 无任何可用 provider —— 跑任何真跑基准都会是 presolve-only 假数据")
    return 1


if __name__ == "__main__":
    sys.exit(main())
