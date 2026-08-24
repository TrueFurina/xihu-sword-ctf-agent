"""java_deserialization_flow skill：Java 反序列化题标准流程范式（prompt 知识型）。

流程：javap MethodParameters 找参数名（大小写敏感）→ 识别 readObject 入口 →
找 classpath gadget（commons-collections）→ 无回显外带（Nashorn/XXE/写文件）。

本 skill 为提示词范式型：run() 返回流程指引（供 SkillManager 加载后注入上下文）。
"""

import os


def _flow(desc: str = "") -> dict:
    return {
        "ok": True,
        "flow": [
            "1. jar/class 用 javap 反编译（javap -v -p），参数名看 MethodParameters 表（注意大小写，如 Fate）",
            "2. 识别入口：ObjectInputStream.readObject() / XMLDecoder 等反序列化点",
            "3. 找 classpath 内 gadget：commons-collections（CC1/CC6 链）、snakeyaml、jackson 等",
            "4. 生成 payload（CC6Gen/java 序列化 base64）→ POST 到入口参数",
            "5. 无回显时外带优先序：Nashorn/ScriptEngine 反射改响应字符串 → XXE 文件读 → 写 web 可访问路径",
        ],
        "key_notes": [
            "参数名来自 MethodParameters 表，Spring @RequestParam 无 name 时按编译参数名匹配（大小写敏感）",
            "commons-collections 3.1 → CC6 链（fake 链触发 + 反射替换真链，exec 用 String[] 防 split）",
            "Java 17 无 Nashorn：用 ScriptEngine('nashorn') 需 nashorn-core 依赖，或反射 String.value 改写",
        ],
        "source": desc,
    }


def run(params):
    """SkillManager 统一入口。"""
    return _flow(params.get("description", "") if isinstance(params, dict) else str(params))


def main() -> None:
    import json

    print(json.dumps(_flow(), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
