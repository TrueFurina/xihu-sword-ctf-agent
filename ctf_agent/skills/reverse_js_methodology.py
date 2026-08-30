"""reverse_js_methodology skill：JS 逆向方法论（2026-08-30）。

来源：借鉴 JS Reverse MCP / hello_js_reverse_skill 的方法论（格式化→定位→反混淆→
动态执行验证），适配项目 reverse_js 真题场景。

目标：real_reverse_js 等 JS 逆向题——前端加密参数/混淆代码还原。
纯 Python + 文本处理（无外部依赖）：beautify 逻辑用内置 tokenize/re 简化实现，
Node 动态执行仅在有 node 时尝试（无则降级为静态分析提示）。
"""

import os
import re


def _read_js(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _basic_beautify(code: str) -> str:
    """简易 JS 美化：分号/花括号换行（完整 beautifier 需 js-beautify，此处轻量）。"""
    code = re.sub(r";\s*", ";\n", code)
    code = re.sub(r"\{\s*", "{\n", code)
    code = re.sub(r"\}\s*", "\n}\n", code)
    return code


def _locate_suspicious(code: str) -> list:
    """定位可疑加密/校验点：eval/atob/charCodeAt/异或/自定义函数。"""
    patterns = [
        (r"\beval\s*\(", "动态执行 eval"),
        (r"\batob\s*\(", "Base64 解码 atob"),
        (r"charCodeAt|fromCharCode", "字符编码处理"),
        (r"\^\s*0x|\^", "异或运算（加密特征）"),
        (r"String\.fromCharCode", "字符还原"),
        (r"btoa\s*\(", "Base64 编码"),
        (r"function\s+[_a-zA-Z][_a-zA-Z0-9]*\s*\([^)]*\)\s*\{[^}]{20,}", "大自定义函数"),
    ]
    hits = []
    for pat, desc in patterns:
        for m in re.finditer(pat, code):
            line = code.count("\n", 0, m.start()) + 1
            hits.append({"line": line, "pattern": desc, "snippet": code[m.start():m.start()+60]})
            if len(hits) >= 10:
                return hits
    return hits


def _try_node_exec(path: str, code: str) -> dict:
    """尝试 node 动态执行（无 node 时降级提示）。"""
    node = os.popen("where node 2>nul").read().strip() if os.name == "nt" else None
    if not node:
        return {"executed": False, "reason": "node 未安装——降级为静态分析（无则加勉）"}
    # 谨慎：不执行未知脚本，仅报告 node 可用
    return {"executed": False, "reason": "node 可用但脚本含未知逻辑，需人工确认后执行（防注入）"}


def run(params: dict) -> dict:
    """JS 逆向方法论：格式化 → 定位加密/校验点 → 反混淆思路 → 动态执行提示。

    params: {'path': JS 文件路径, 'question_id'?: 题目id}
    """
    path = params.get("path", "")
    code = _read_js(path)
    if not code:
        return {"solved": False, "flag": None, "reason": f"无法读取 JS：{path}"}

    beautified = _basic_beautify(code)
    hits = _locate_suspicious(code)
    exec_info = _try_node_exec(path, code)

    # 尝试直接提取 flag 明文（如 flag{...} 或 base64 特征）
    flag = None
    m = re.search(r"flag\{[^}]+\}", code, re.I)
    if m:
        flag = m.group(0)

    return {
        "solved": bool(flag),
        "flag": flag,
        "reason": f"定位 {len(hits)} 个可疑点；{exec_info['reason']}",
        "methodology": (
            "JS 逆向 4 步："
            "1) 美化格式化（_basic_beautify）→ 2) 定位 eval/atob/charCodeAt/异或等加密特征"
            "→ 3) 反混淆（变量名还原/字符串数组解密/控制流平坦化）"
            "→ 4) node 动态执行验证（本机 node 未装时降级静态分析）"
        ),
        "suspicious_hits": hits[:10],
        "beautified_sample": beautified[:500],
    }


if __name__ == "__main__":
    # 自检
    import tempfile
    sample = 'var enc="a2V5";function chk(){var x=eval("atob(enc)");return x;}var flag="flag{js_test_demo}";'
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False, encoding="utf-8") as f:
        f.write(sample)
        p = f.name
    r = run({"path": p})
    print(f"solved={r['solved']} flag={r['flag']!r} hits={len(r['suspicious_hits'])}")
    print(r["reason"])
    os.unlink(p)
