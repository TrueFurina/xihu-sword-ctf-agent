"""无损 LLM 健康探针：逐个 provider 真实打一发，报告 HTTP 状态/内容/错误。

不触碰正在跑的 race 进程，仅用项目自身 config + llm.client 做一次探测。
用于赛中定位"LLM 失效"根因（哪个 provider 的 key/端点/模型名有问题）。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm.client import ai_chat, _resolve_settings  # noqa: E402


# (label, provider, model) —— 覆盖赛时矩阵各路
PROBES = [
    ("deepseek(deepseek-chat)", "deepseek", None),
    ("deepseek(reasoner)", "deepseek", "deepseek-reasoner"),
    ("qwen(qwen3.7-plus)", "qwen", "qwen3.7-plus"),
    ("qwen(glm-4.7 via 百炼)", "qwen", "glm-4.7"),
    ("glm(智谱 bigmodel)", "glm", "glm-4.7"),
    ("xfyun(lite)", "xfyun", "lite"),
    ("tokenhub(deepseek-v4-pro)", "tokenhub", "deepseek-v4-pro"),
]


def probe(label, provider, model):
    t0 = time.time()
    try:
        settings = _resolve_settings(model, provider=provider)
        key_mask = ("<有key>" if settings.get("api_key") else "<无KEY>")
        url = settings.get("base_url", "")
        # 直接发一次最小请求，绕开 ai_chat 的 fail-open 吞错，拿到真实状态
        import httpx
        payload = {
            "model": settings["model"],
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 16,
            "temperature": 0.1,
        }
        if settings.get("provider") in ("deepseek", "mimo") or str(settings.get("model", "")).startswith("deepseek"):
            payload["thinking"] = {"type": "disabled"}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings['api_key']}",
        }
        r = httpx.post(url, json=payload, headers=headers,
                      timeout=settings["timeout"], trust_env=False)
        dt = time.time() - t0
        body = r.text[:160].replace("\n", " ")
        return f"[{label}] {r.status_code} | {key_mask} | {url} | {dt:.1f}s | {body}"
    except Exception as exc:  # noqa: BLE001
        dt = time.time() - t0
        return f"[{label}] EXC {type(exc).__name__}: {exc} | {dt:.1f}s"


if __name__ == "__main__":
    print("=== LLM 健康探针 (赛中无损) ===")
    for label, provider, model in PROBES:
        print(probe(label, provider, model))
    print("=== 探针结束 ===")
