"""reverse_obfuscation skill：reverse 混淆处理范式（ollvm/反调试/VM 壳）。

场景：正式赛 reverse 可能升级为 ollvm 平坦化、反调试（ptrace）、VM 壳。
流程：① 检测反调试（ptrace/时间戳/文件检测）② 定位关键校验函数
     ③ 字符串解密/控制流分析 ④ 提取 flag。

用法：
    params = {'binary': ELF 路径, 'kind': 'ollvm|antidebug|vm|strings'}
    result = reverse_obfuscation(params)
"""

import os
import re


_ANTIDEBUG_PATTERNS = {
    "ptrace": [rb"ptrace", rb"\x48\x8b\x05.*\x50\x00\x00\x00", rb"PTRACE"],
    "time_check": [rb"time\(", rb"clock_gettime", rb"gettimeofday"],
    "file_check": [rb"/proc/self", rb"stat\(", rb"access\("],
    "int3": [rb"\xcc", rb"int3"],
    "sigaction": [rb"sigaction", rb"signal\("],
    # ── Windows 反调试/加密特征（SnowGuard 实战暴露，2026-08-20 补）──
    "is_debugger": [rb"IsDebuggerPresent", rb"CheckRemoteDebuggerPresent", rb"NtQueryInformationProcess"],
    "debug_output": [rb"OutputDebugStringA", rb"OutputDebugStringW", rb"DebugActiveProcess"],
    "crypto_api": [rb"BCryptImportKeyPair", rb"BCryptDecrypt", rb"BCryptEncrypt",
                   rb"BCryptOpenAlgorithmProvider", rb"CryptDecrypt", rb"CryptEncrypt"],
}


def _scan_binary(path: str) -> dict:
    """扫描 ELF/JS/HTML 中的反调试/混淆特征与 flag 线索。"""
    if not os.path.exists(path):
        return {"error": "binary 不存在"}
    data = open(path, "rb").read()
    found = {}
    for kind, pats in _ANTIDEBUG_PATTERNS.items():
        hits = []
        for p in pats:
            if re.search(p, data):
                hits.append(p.decode("utf-8", errors="replace"))
        if hits:
            found[kind] = hits[:3]
    # 字符串区（可读字符串，flag 常在）
    strings = [s.decode("utf-8", errors="replace")
               for s in re.findall(rb"[\x20-\x7e]{6,}", data)]
    flags = [s for s in strings if re.search(r"(?:DASCTF|flag|ctf)\{[^}\s]{4,}\}", s, re.I)]
    # JS/HTML 前端注释 flag 泄露（Where-is-flag 实战：<!-- flag{...} -->）
    if path.endswith((".js", ".html", ".htm")):
        text = data.decode("utf-8", errors="replace")
        for m in re.finditer(r"<!--\s*(flag|ctf|DASCTF)\{[^}\s]{4,}\}\s*-->", text, re.I):
            flags.append(m.group(0).strip("<!-- -->").strip())
        # 编码函数（ROT13 等）识别：synt{ -> flag{ 是 ROT13 特征
        if "synt{" in text or re.search(r"charCodeAt\(\).*13", text):
            found["rot13"] = ["synt{ 前缀（flag 的 ROT13）或 charCodeAt±13 编码函数"]
    return {"antidebug": found, "strings_count": len(strings), "flags": list(dict.fromkeys(flags)),
            "string_samples": strings[:20]}


def reverse_obfuscation(params: dict) -> dict:
    """skill 入口。"""
    binary = params.get("binary", "")
    kind = params.get("kind", "")
    if not binary or not os.path.exists(binary):
        return {"ok": False, "error": "binary 不存在"}

    scan = _scan_binary(binary)
    result = {"ok": True, "scan": scan}

    k = (kind or "").lower()
    if k == "antidebug" or scan["antidebug"]:
        result["advice"] = (
            "检测到反调试特征：① ptrace → 用 LD_PRELOAD 劫持 ptrace 返回 0，"
            "或 patchelf 改 ptrace 调用 ② time_check → 冻结时间/patchelf nop 掉检查 "
            "③ 静态分析优先（IDA/Ghidra 不触发反调试）"
        )
    if k == "ollvm":
        result["advice"] = (
            "ollvm 平坦化：① 用 angr 符号执行（deflat.py 脚本）恢复原控制流 "
            "② 或找输入校验的等价条件（数学化简）③ 动态插桩（Frida）对比输入输出"
        )
    if k == "vm":
        result["advice"] = (
            "VM 壳：① 定位 VM dispatcher（取指-分派循环）② 还原 opcode 表 "
            "③ 模拟执行或脚本翻译 ④ 关键在 handler 识别"
        )
    if k == "strings" or not k:
        result["advice"] = "先看可读字符串（可能直接含 flag 或提示），再定位校验函数反推输入"
    return result


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return reverse_obfuscation(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="reverse 混淆分析")
    parser.add_argument("--binary", required=True, help="ELF/APK 路径")
    parser.add_argument("--kind", default="", help="ollvm|antidebug|vm|strings")
    args = parser.parse_args()
    import json

    print(json.dumps(reverse_obfuscation({"binary": args.binary, "kind": args.kind}),
                     ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
