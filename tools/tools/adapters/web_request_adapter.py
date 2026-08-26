"""Web HTTP 请求适配器：httpx 发包 + 输出过滤（替代 sqlmap 等重量级工具）。

本机无 sqlmap 时可先用本适配器做基础探测（GET/POST、header 检查、payload 尝试），
输出过滤：只送状态码/关键响应头/截断 body，不送全量页面进 LLM。
"""

from __future__ import annotations

import re
from typing import Optional

from tools.base import ToolAdapter, ToolOutput


class WebRequestAdapter(ToolAdapter):
    """Web HTTP 请求适配器（httpx）。

    v2.1 会话保持（2026-08-21 实战演练发现）：原每次新建 client，cookie 不跨请求，
    导致「登录→利用」类多步 web 题无法会话保持（登录态丢失，后续注入/越权全部失效）。
    现按 question.id 隔离维护 cookie jar：请求时注入、响应时更新、支持 reset 清空。
    """

    name = "http_request"
    categories = ["web"]

    def __init__(self, sandbox=None, timeout: float = 15.0) -> None:
        super().__init__(sandbox)
        self.timeout = timeout
        # 会话 cookie：{question_id: {name: value}}，跨请求保持（多步攻击关键）
        self._cookies: dict[str, dict] = {}

    async def run(self, params: dict) -> ToolOutput:
        url = str(params.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            return ToolOutput(text=f"URL 无效: {url}", ok=False)

        import httpx

        method = str(params.get("method") or "GET").upper()
        headers = dict(params.get("headers") or {})
        data = params.get("data")
        json_body = params.get("json")
        # 会话隔离 key：每题独立 cookie，避免多题并行时 cookie 串题
        qid = str(getattr(params.get("question"), "id", "default"))
        # reset：显式清空该题会话（换靶机/重开时用）
        if params.get("reset"):
            self._cookies.pop(qid, None)
        # 注入已保持的会话 cookie（显式 headers 优先）
        jar = self._cookies.setdefault(qid, {})
        if jar and not any(k.lower() == "cookie" for k in headers):
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        # 默认浏览器 UA（防裸 requests 被 WAF 拦）
        headers.setdefault("User-Agent",
                           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, trust_env=False) as client:
                if json_body is not None:
                    resp = await client.request(method, url, headers=headers, json=json_body)
                else:
                    resp = await client.request(method, url, headers=headers, data=data)
        except Exception as exc:  # noqa: BLE001 - 网络异常兜底
            return ToolOutput(text=f"[请求失败] {type(exc).__name__}: {exc}", ok=False)

        # 更新会话 cookie（set-cookie 合并进 jar）
        for c in resp.cookies:
            jar[c.name] = c.value

        # ── 输出过滤（关键信息，不送全量）──
        body = resp.text
        key_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() in ("server", "content-type", "set-cookie", "x-powered-by", "location")
        }
        lines = [
            f"状态码: {resp.status_code}",
            f"关键响应头: {key_headers}",
        ]
        # flag 特征
        m = re.search(r"flag\{[^}]+\}", body)
        if m:
            lines.append(f"发现 flag: {m.group(0)}")
        # 关键片段：title / 表单 / 注释（裁剪）
        title = re.search(r"<title[^>]*>([^<]{1,80})</title>", body, re.I)
        if title:
            lines.append(f"页面标题: {title.group(1)}")
        # 报错/提示信息优先（SQL 报错回显是注入的关键信号，不能截断）
        err = re.search(r"(error|warning|notice|exception|fatal)[^\n<]{0,200}", body, re.I)
        if err:
            lines.append(f"报错信息: {err.group(0)[:200]}")
        body_snippet = re.sub(r"\s+", " ", body)[:800]
        lines.append(f"页面片段: {body_snippet}")
        return ToolOutput(text="\n".join(lines), raw=body, ok=True)
