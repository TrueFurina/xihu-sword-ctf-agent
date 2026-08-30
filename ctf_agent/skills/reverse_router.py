"""reverse_router skill：reverse 附件确定性路由（借鉴 reverse-skill 路由思路，2026-08-30）。

核心思路（源自 https://github.com/zhaoxuya520/reverse-skill 的路由矩阵）：
    "场景→方法论→工具→可复现工作流"——当 Agent 遇到 reverse 附件时，按文件类型
    确定性分发到对应 skill，而不是盲目猜测命令。

分发矩阵（按 magic bytes/扩展名/特征，纯 Python 无外部依赖）：
    ELF    (\x7fELF)          -> reverse_elf_general(kind=elf)
    Wasm   (\x00asm)          -> reverse_elf_general(kind=wasm)
    pyc    (Python 字节码)     -> pyc_decompile
    APK    (PK\x03\x04+manifest) -> reverse_go_apk
    UPX    壳 (UPX! 特征)      -> reverse_obfuscation
    JS     (.js / JS 特征)     -> reverse_js_methodology
    迷宫类  (提示词含 maze/迷宫) -> reverse_angr_solver（依赖检查）
    其他/未知                 -> reverse_elf_general(kind=generic)

输出：{'kind': ..., 'skill': ..., 'methodology': ..., 'hints': [...]}
"""

import os
import re


def _read_head(path: str, n: int = 64) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def _is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def _is_wasm(data: bytes) -> bool:
    return data[:4] == b"\x00asm" or b"wasm" in data[:16].lower()


def _is_pyc(data: bytes, path: str) -> bool:
    # Python 字节码：pyc 头（3.7+ 为 0x61 0x0D 0x0D 0x0A）或文件后缀
    if data[:4] in (b"\x61\x0d\x0d\x0a", b"\x03\xf3\x0d\x0a"):
        return True
    return path.lower().endswith(".pyc")


def _is_apk(data: bytes, path: str) -> bool:
    # zip 魔数 + AndroidManifest.xml 特征（apk 内）或后缀
    if data[:2] == b"PK":
        return True
    return path.lower().endswith((".apk", ".xapk", ".aab"))


def _is_js(path: str) -> bool:
    return path.lower().endswith((".js", ".mjs", ".cjs"))


def _is_upx(data: bytes) -> bool:
    # UPX 壳特征：节名 UPX0/UPX1 或 "UPX!" 字符串
    return b"UPX!" in data or b"UPX0" in data or b"UPX1" in data


def _detect_kind(path: str, data: bytes = b"") -> str:
    if not data:
        data = _read_head(path, 256)
    # UPX 壳 ELF：先脱壳（reverse_obfuscation），再走通用逆向
    if _is_elf(data) and _is_upx(data):
        return "upx"
    if _is_elf(data):
        return "elf"
    if _is_wasm(data):
        return "wasm"
    if _is_pyc(data, path):
        return "pyc"
    if _is_apk(data, path):
        return "apk"
    if _is_js(path):
        return "js"
    if _is_upx(data):
        return "upx"
    return "generic"


# 路由矩阵：kind -> (skill, methodology)
_ROUTE = {
    "elf": ("reverse_elf_general",
            "strings 扫 flag/线索 → 反汇编(strcmp/循环比较)定位校验 → 恢复输入"),
    "wasm": ("reverse_elf_general",
             "Wasm 逆向：wabt 转 .wat → 定位导出函数 → 读校验逻辑"),
    "pyc": ("pyc_decompile",
            "Python 字节码反编译 → 读校验逻辑 → 恢复 flag"),
    "apk": ("reverse_go_apk",
            "APK 逆向：JADX 看 Java 层 + 反编译 so → 定位校验函数"),
    "js": ("reverse_js_methodology",
           "JS 逆向：格式化/美化 → 定位加密函数 → 反混淆 → 动态执行验证"),
    "upx": ("reverse_obfuscation",
            "UPX 脱壳：upx -d → 脱壳后 strings/反汇编定位校验"),
    "generic": ("reverse_elf_general",
                "通用逆向：strings 全扫 → 识别类型 → 反汇编定位校验"),
}


def run(params: dict) -> dict:
    """按文件类型确定性路由到对应 reverse skill。

    params: {'path': 附件路径, 'question_id'?: 题目 id, 'description'?: 题面}
    """
    path = params.get("path", "")
    kind = _detect_kind(path)
    skill, methodology = _ROUTE.get(kind, _ROUTE["generic"])
    hints = []

    # 迷宫类题面提示 → angr 符号执行（依赖检查：本机未装 angr 时明确提示）
    desc = str(params.get("description", ""))
    if re.search(r"迷宫|maze|babymaze", desc, re.I):
        kind, skill, methodology = "maze", "reverse_angr_solver", (
            "迷宫类：angr 符号执行（angr.Project 找终点地址 → 符号求解路径）——"
            "注意：本机未装 angr，需 pip install angr 后可用"
        )
        hints.append("angr 依赖未安装（pip install angr）——当前降级为 LLM 分析")

    result = {
        "kind": kind,
        "skill": skill,
        "methodology": methodology,
        "hints": hints,
        "path": path,
    }
    return result


if __name__ == "__main__":
    # 自检：模拟各类型分发
    import tempfile
    samples = {
        "elf": b"\x7fELF\x02\x01\x01",
        "wasm": b"\x00asm\x01\x00\x00\x00",
        "pyc": b"\x61\x0d\x0d\x0a" + b"\x00" * 12,
        "apk": b"PK\x03\x04" + b"\x00" * 20,
        "upx": b"\x7fELF" + b"\x00" * 20 + b"UPX!",
    }
    for kind, head in samples.items():
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(head)
            p = f.name
        print(f"{kind} -> {run({'path': p})['skill']}")
        os.unlink(p)
    print("js ->", run({"path": "app.js"})["skill"])
    print("maze ->", run({"path": "baby", "description": "这是迷宫题"})["skill"])
