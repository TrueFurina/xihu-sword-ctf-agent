"""兜底脚本模块（上帝模块拆分——main_agent 兜底脚本职责独立）。

从 main_agent 提取：build_crypto_fallback_script / build_misc_fallback_script /
build_web_fallback_script / build_reverse_fallback_script。
模块级函数接收 ctx（AgentContext 鸭子类型），逻辑与 main_agent 原实现一致
（提取不重构）。已与题目描述解耦（附件特征嗅探/委托 toolkit——去本地题库过拟合）。

背景（2026-08-20 锐评整改）：main_agent 按职责拆——提示词归 prompts.py、
兜底脚本归本模块、主循环/LLM/校验留 main_agent。
"""

from typing import Optional


def build_crypto_fallback_script(ctx) -> Optional[str]:
    """Crypto 兜底：委托 CryptoToolkit 按附件内容嗅探构造攻击脚本。

    旧版按题目描述关键词选模板，是对本地题库的过拟合（决赛代码审查风险项）；
    现改为只嗅探附件本身的参数行/哈希/字符集特征，与题目描述解耦。
    """
    attach = getattr(ctx.question, "attachments", None)
    if not attach:
        return None
    try:
        from agents.crypto_toolkit import CryptoToolkit
    except Exception:  # noqa: BLE001
        return None
    # 多附件完整性：首附件 path + 其余 extra_paths（ezrsa 参数在 output 附件）
    paths = [str(a) for a in attach]
    return CryptoToolkit.build_fallback_script(paths[0], extra_paths=paths[1:])


def build_misc_fallback_script(ctx) -> Optional[str]:
    """Misc 兜底：委托 MiscToolkit 按附件魔数/字符集构造取证脚本。

    同 crypto：与题目描述解耦，只看附件字节特征（ZIP/PNG 魔数、
    base64/摩斯/Brainfuck/DNS 流量字符集）。
    """
    attach = getattr(ctx.question, "attachments", None)
    if not attach:
        return None
    try:
        from agents.misc_toolkit import MiscToolkit
    except Exception:  # noqa: BLE001
        return None
    return MiscToolkit.build_fallback_script(str(attach[0]))


def build_web_fallback_script(ctx) -> Optional[str]:
    """Web 兜底：提取靶机 URL 后委托 WebToolkit 发包探测。

    payload 模板统一维护在 agents/web_toolkit（决赛代码审查：核心调度
    文件不内联漏洞利用代码）；描述关键词是题目自带的漏洞方向提示，属合法信号。
    URL 提取：优先题库 extra.target_url，否则取描述中第一个 http(s) URL。
    """
    import re

    q = ctx.question
    desc = str(getattr(q, "description", "") or "")
    url = ""
    extra = getattr(q, "extra", None) or {}
    if isinstance(extra, dict) and extra.get("target_url"):
        url = str(extra["target_url"])
    else:
        m = re.search(r"https?://[^\s，。；]+", desc)
        if m:
            url = m.group(0).rstrip("/.,;")
    if not url:
        return None
    try:
        from agents.web_toolkit import WebToolkit
    except Exception:  # noqa: BLE001
        return None
    return WebToolkit.build_fallback_script(url, desc)


def build_reverse_fallback_script(ctx) -> Optional[str]:
    """Reverse 兜底：从附件（strings 提取/反编译源码）定位硬编码 flag。

    场景（按附件内容特征，通用 strings 定位）：
    - 任意附件：读全文 + 正则提取 flag{...}（覆盖字符串比较、反编译源码等）
    - 若附件含 pyc/字节码/反编译关键词：同样全文搜索
    """
    q = ctx.question
    attach = getattr(q, "attachments", None)
    if not attach:
        return None
    # 多附件完整性（2026-08-21 攻坚修复）：reverse_js 真 flag 在第二个附件
    # index.html 注释里——只扫 attach[0] 会漏。构造 paths 列表逐一读取拼接。
    paths = [str(a) for a in attach]

    # 通用：读全部附件全文 + strings 提取 flag{...}（覆盖 strings 输出/反编译源码/二进制/HTML注释）
    payload = (
        "import re\n"
        f"paths = {paths!r}\n"
        "# 读全部附件（兼容文本与部分二进制，errors 容错）\n"
        "text = ''\n"
        "for path in paths:\n"
        "    try:\n"
        "        with open(path, 'rb') as f:\n"
        "            data = f.read()\n"
        "        text += data.decode('utf-8', errors='ignore') + '\\n'\n"
        "    except Exception:\n"
        "        pass\n"
        "# strings 定位：提取可打印字符串，正则搜 flag\n"
        "strings = re.findall(r'[ -~]{4,}', text)\n"
        "_hits = []\n"
        "for s in strings:\n"
        "    m = re.search(r'(?:flag|ctf|DASCTF)\\{[^}\\s]+\\}', s)\n"
        "    if m and m.group(0) not in _hits:\n"
        "        _hits.append(m.group(0))\n"
        "        print(m.group(0))\n"
        "for m in re.finditer(r'(?:flag|ctf|DASCTF)\\{[^}\\s]+\\}', text):\n"
        "    if m.group(0) not in _hits:\n"
        "        _hits.append(m.group(0))\n"
        "        print(m.group(0))\n"
        "# 分离前缀+花括号模式（省赛 reverse_2 经验：printf(\"flag\") 与 {xxx} 分开存放）\n"
        "# .data 段常见：'flag' 与 '{hacking_for_fun}' 独立字符串 → 拼接恢复\n"
        "_braces = [s.strip() for s in strings if s.strip().startswith('{') and s.strip().endswith('}') and len(s.strip()) > 3]\n"
        "_pre = [s.strip() for s in strings if re.fullmatch(r'(?:flag|ctf|DASCTF)', s.strip())]\n"
        "for _b in _braces:\n"
        "    for _p in _pre:\n"
        "        _full = _p + _b\n"
        "        if _full not in _hits:\n"
        "            _hits.append(_full)\n"
        "            print(_full)\n"
    )
    return payload
