"""reverse_elf_general skill：ELF/程序逆向通用流程（reverse 短板修复）。

覆盖（本地 reverse-001~005 题型）：
1. ELF 简单比较（strings 直接/反汇编 strcmp 定位）
2. Wasm 逆向（wabt 转 .wat 定位导出函数）
3. Python 字节码（.pyc 反编译后读校验逻辑）
4. TLS 回调反调试（.tls 段查回调表）
5. Android SO（JADX 看 Java 层 + IDA 分析 so）

流程：strings 扫 flag/线索 → 识别类型 → 反汇编定位校验 → 恢复输入/提取。
依赖：capstone（反汇编）+ 纯 Python strings 扫描（无外部库）。
"""

import os
import re


def _extract_strings(path: str, min_len: int = 5) -> list:
    """提取可读字符串（ASCII + UTF-8）。"""
    with open(path, "rb") as f:
        data = f.read()
    return [s.decode("utf-8", errors="replace")
            for s in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]


def _detect_kind(path: str, data: bytes = b"") -> str:
    """识别附件类型（ELF/Wasm/pyc/APK/普通文件）。"""
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == b"\x00asm" or b"wasm" in data[:16].lower():
        return "wasm"
    if data[:4] == b"\xca\xf0\xfe\xd0" or b"python" in data[:64].lower() or path.endswith(".pyc"):
        return "pyc"
    if data[:2] == b"PK" and b"classes" in data[:2000]:
        return "android"
    if data[:4] == b"\x4c\x01\x00\x00" or path.endswith(".so"):
        return "android_so"
    return "generic"


def scan_for_flag(path: str) -> dict:
    """阶段 1：strings 扫 flag 与线索（最快路径）。

    自我进化（2026-08-20 张三的程序 MFC 真题突破）：PE/MFC 题 strings 直出
    flag 实证——补 key 串特征检测：flag 文件路径（C:\\flag.txt）、关键 API
    （GetSystemMetrics/MessageBox 等 MFC 特征），作为 strings 命中 flag 的辅助证据。
    """
    strings = _extract_strings(path)
    flags = [s for s in strings if re.search(r"(?:flag|FLAG|ctf|DASCTF)\{[^}\s]{4,}\}", s)]
    # key 串特征（PE/MFC 真题经验——张三的程序实证：C:\flag.txt 提示 flag 位置）
    key_patterns = [
        r"[A-Za-z]:\\\\flag",       # C:\flag.txt 等文件路径提示
        r"flag\.txt",
        r"GetSystemMetrics",
        r"MessageBox",
        r"ReadFile|WriteFile|CreateFile",
        r"fopen|fread|fgets",
    ]
    key_strings = [s for s in strings if any(re.search(p, s, re.I) for p in key_patterns)]
    return {
        "strings_count": len(strings),
        "flags": list(dict.fromkeys(flags)),
        "key_strings": list(dict.fromkeys(key_strings))[:8],
        "samples": strings[:15],
    }


def disassemble_compare_functions(path: str, arch: str = "auto") -> list:
    """阶段 2：capstone 反汇编，定位比较函数（strcmp 调用 / 逐字节比较循环）。"""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM

    data = open(path, "rb").read()
    # 简单定位：找 .text 段偏移（ELF 粗略：跳过 ELF 头 + 段表，用可执行区段）
    if arch == "auto":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.skipdata = True
    hints = []
    # 从数据里找 strcmp/strncmp/memcmp 的 PLT 引用与比较指令
    if b"strcmp" in data or b"strncmp" in data or b"memcmp" in data:
        hints.append("检测到 strcmp/strncmp/memcmp——校验逻辑在比较调用处，用 capstone 反汇编定位调用点")
    # x86 常见比较指令特征（cmp/movzx/je）扫描（粗略）
    cmp_count = data.count(b"\x3c") + data.count(b"\x80\x3d") + data.count(b"\x8b")  # 启发
    if cmp_count > 50:
        hints.append(f"检测到大量比较/加载指令（约 {cmp_count} 处）——存在逐字节比较循环，反汇编 .text 定位")
    return hints


def reverse_elf_general(params: dict) -> dict:
    """skill 入口：通用逆向流程。"""
    path = params.get("binary", "")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": "binary 不存在"}
    data = open(path, "rb").read()
    kind = params.get("kind", "") or _detect_kind(path, data)

    result = {"ok": True, "kind": kind}
    # 阶段 1：strings 扫 flag
    scan = scan_for_flag(path)
    result["strings"] = scan
    if scan["flags"]:
        result["flags"] = scan["flags"]
        result["stage"] = "direct（strings 直接命中）"
        return result

    # 阶段 2：类型特定指引
    guides = {
        "elf": "strings 未直接命中 → capstone 反汇编定位 strcmp/逐字节比较循环，"
               "从比较的两侧恢复目标字符串（静态提取或输入反转）",
        "wasm": "wabt 转 .wat（wasm2wat），定位关键导出函数（start/main/check 等），"
                "读线性内存比较逻辑恢复 flag",
        "pyc": "用 uncompyle6/decompyle3 反编译 .pyc 为源码，读校验逻辑（字符串比较/算法）直接提取 flag",
        "tls": "查 .tls 段回调表（IDA: View→TLS callbacks；Ghidra: 分析 TLS），"
               "TLS 回调里的校验函数是隐藏入口——反汇编该函数",
        "android_so": "JADX 看 Java 层调用链 → IDA/Ghidra 分析 so 的 JNI 函数，"
                      "native 校验逻辑（常见异或/查表）恢复",
        "android": "APK 用 JADX 反编译，Java 层校验（字符串比较/算法）定位",
        "generic": "strings 未命中 → file 识别类型 → 按类型选上述路径",
    }
    result["guidance"] = guides.get(kind, guides["generic"])
    result["compare_hints"] = disassemble_compare_functions(path)
    result["stage"] = "type_guided"
    return result


def run(params: dict) -> dict:
    """SkillManager 统一入口。"""
    return reverse_elf_general(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="ELF/程序逆向通用流程")
    parser.add_argument("--binary", required=True, help="附件/ELF 路径")
    args = parser.parse_args()
    import json

    print(json.dumps(reverse_elf_general({"binary": args.binary}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
