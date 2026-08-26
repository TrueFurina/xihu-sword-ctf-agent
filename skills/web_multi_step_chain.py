"""web_multi_step_chain skill：web 多步利用链组合。

场景（决赛 web 难度升级）：单漏洞不足以拿 flag，需组合多个漏洞点成链：
- 上传 → 包含/解析 → RCE（上传 webshell + LFI 包含触发）
- SSRF → 内网 → 未授权接口 → flag
- 任意文件写 → .htaccess/webshell → getshell
- 反序列化 → 触发点 → RCE（入口参数 + gadget）

流程：识别可组合漏洞点 → 排序依赖（前步输出 = 后步输入）→ 构造完整链。
"""

import re


# 常见漏洞点 → 可组合的下游
_COMBO = {
    "upload": ["lfi", "include", "parse", "xxe"],
    "lfi": ["include", "read", "phar"],
    "ssrf": ["internal", "redis", "meta", "file"],
    "unserialize": ["rce", "pop", "gadget"],
    "write_file": ["htaccess", "webshell", "cron"],
    "sqli": ["dump", "file_read", "into_outfile"],
    "ssti": ["rce", "os_popen"],
    "xxe": ["file_read", "ssrf"],
}


def build_chain(known_vulns: list) -> list:
    """根据已知漏洞点，枚举可组合链（BFS 一层即可——通常 2-3 步链）。"""
    chains = []
    for v in known_vulns:
        vk = v.lower()
        for downstream in _COMBO.get(vk, []):
            if downstream in [x.lower() for x in known_vulns]:
                chains.append([vk, downstream])
        # 常见完整链
        if vk == "upload":
            chains.append(["upload", "lfi/include", "RCE"])
        if vk == "ssrf":
            chains.append(["ssrf", "internal_service", "flag"])
        if vk == "unserialize":
            chains.append(["unserialize", "gadget_chain", "RCE"])
        if vk == "ssti":
            chains.append(["ssti", "os_popen", "RCE"])
    return chains


# 描述识别：中英文关键词 → 漏洞点（vuln key）
_DESC_KEYWORDS = {
    "upload": ["upload", "上传", "文件上传"],
    "lfi": ["lfi", "include", "包含", "文件包含", "路径穿越", "traversal"],
    "ssrf": ["ssrf", "内网", "url参数", "代理"],
    "unserialize": ["unserialize", "反序列化", "serialize", "deserialize"],
    "write_file": ["write_file", "任意文件写", "文件写"],
    "sqli": ["sqli", "sql", "注入", "数据库"],
    "ssti": ["ssti", "模板注入", "模板渲染", "jinja", "freemarker"],
    "xxe": ["xxe", "xml实体", "xml 实体"],
}


def web_multi_step_chain(params: dict) -> dict:
    """skill 入口。"""
    chain = params.get("chain") or []
    vulns = params.get("vulns") or []
    desc = params.get("description", "")

    if not chain and vulns:
        chain = build_chain(vulns)
    elif not chain and desc:
        # 从描述自动识别漏洞关键词（中英文）
        found = []
        for vk, kws in _DESC_KEYWORDS.items():
            if any(re.search(k, desc, re.I) for k in kws):
                found.append(vk)
        if found:
            chain = build_chain(found)
            vulns = found

    if not chain:
        return {"ok": True, "note": "未识别到可组合漏洞点；请提供已知漏洞列表（vulns）或题目描述",
                "common_chains": [
                    "上传→LFI 包含→RCE", "SSRF→内网服务→flag",
                    "反序列化→gadget→RCE", "任意文件写→webshell→getshell",
                    "SQLi→into outfile→webshell",
                ]}

    return {
        "ok": True,
        "identified_vulns": vulns,
        "chains": chain,
        "guidance": "多步链执行要点：① 每步的输出是下一步的输入，先验证单步可行再组合 "
                    "② 前步 payload 与后步触发点要匹配（如上传文件名 = LFI 参数值）"
                    "③ 链中任一步失败即回退重试，避免在单点卡死",
    }


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return web_multi_step_chain(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="web 多步利用链")
    parser.add_argument("--vulns", default="", help="已知漏洞点，逗号分隔（upload,lfi,ssrf...）")
    args = parser.parse_args()
    import json

    vulns = [v.strip() for v in args.vulns.split(",") if v.strip()]
    print(json.dumps(web_multi_step_chain({"vulns": vulns}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
