"""pyc_decompile skill：Python 字节码反编译（正式赛高难题——pyc 题一键反编译）。

场景：reverse 题附件是 .pyc（Python 编译产物）——flag/校验逻辑在字节码里。
流程：
1. 识别 pyc（magic number 0x0d0d0a / 版本头）
2. uncompyle6 反编译（完整还原源码——校验逻辑/flag 直接可见）
3. 反编译失败（版本过新/混淆）→ 提取 co_consts 字符串/常量（flag 常在常量里）

依赖：uncompyle6（2026-08-21 已装成功）。
"""

import dis
import marshal
import os
import sys
import types


def _pyc_version_info(path: str) -> str:
    """识别 pyc 的 Python 版本（magic number）。"""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        for ver in (311, 310, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 27):
            # Python magic: 3.11=0xa1d0d0d 等——简化用头两个字节判断
            pass
        m = int.from_bytes(magic[:2], "little")
        ver_map = {0x61: "3.11", 0x4d: "3.10", 0x42: "3.9", 0x35: "3.8",
                   0x33: "3.7", 0x16: "3.6", 0x0d: "3.4", 0x0a: "3.3", 0x09: "3.2"}
        return ver_map.get(m, f"unknown({magic.hex()})")
    except Exception:  # noqa: BLE001
        return "unknown"


def _extract_const_strings(path: str) -> list:
    """提取 pyc 字节码 code object 的 co_consts 字符串（flag 常在常量里）。"""
    strings = []
    try:
        with open(path, "rb") as f:
            # 跳过 pyc 头（16 字节：magic+flags+timestamps）或 12 字节（旧版）
            data = f.read()
        # 尝试多种头长度解析 code object
        for header_len in (16, 12):
            try:
                code = marshal.loads(data[header_len:])
                if isinstance(code, types.CodeType):
                    break
            except Exception:  # noqa: BLE001
                continue
        else:
            return strings

        def _walk(co):
            for const in co.co_consts:
                if isinstance(const, str) and len(const) >= 3:
                    strings.append(const)
                elif isinstance(const, types.CodeType):
                    _walk(const)

        _walk(code)
    except Exception:  # noqa: BLE001
        pass
    return strings


def pyc_decompile(params: dict) -> dict:
    """skill 入口：pyc 反编译（uncompyle6 → 常量提取兜底）。"""
    path = params.get("path", "")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": "pyc 路径不存在"}

    result = {"ok": True, "path": path, "pyc_version": _pyc_version_info(path)}

    # 1. uncompyle6 反编译
    source = ""
    try:
        import io

        from uncompyle6.main import decompile_file

        buf = io.StringIO()
        try:
            decompile_file(path, buf)
            source = buf.getvalue()
        except Exception:  # noqa: BLE001 - 反编译失败（版本/混淆）走兜底
            source = ""
    except Exception:  # noqa: BLE001 - uncompyle6 不可用走兜底
        source = ""
    if source:
        result["source"] = source
        result["method"] = "uncompyle6"
    else:
        # 2. 常量/字符串提取兜底（flag 常在 co_consts）
        consts = _extract_const_strings(path)
        result["const_strings"] = consts
        result["method"] = "const_extract"
        result["note"] = "uncompyle6 反编译失败（版本过新/混淆）——已提取字节码常量字符串"

    # 3. 无论哪种方法，flag 命中即标出
    import re

    all_text = source or "\n".join(_extract_const_strings(path))
    flags = re.findall(r"(?:flag|ctf|DASCTF|UNCTF)\{[^}\s]{3,}\}", all_text)
    result["flags"] = list(dict.fromkeys(flags))
    return result


def run(params: dict) -> dict:
    """SkillManager 统一入口（2026-08-21 补——正式赛 skill 自动加载约定）。"""
    return pyc_decompile(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="pyc 反编译")
    parser.add_argument("--path", required=True, help="pyc 文件路径")
    args = parser.parse_args()
    import json

    print(json.dumps(pyc_decompile({"path": args.path}), ensure_ascii=False, indent=1)[:600])


if __name__ == "__main__":
    main()
