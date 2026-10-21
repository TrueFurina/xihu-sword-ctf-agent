"""rea_probe：把 REA（Reverse Engineer Anything 6.5.0）的**无引擎**静态分析接成工具。

为什么需要它
------------
CTF reverse 题最常见的三件事是「.NET 里找 ldstr 的 flag」「Go 二进制看依赖与构建信息」
「PE 看资源/节表」。本机没有 Ghidra / IDA / Hopper / Jadx（`rea doctor` 全 missing），
但 REA 的纯解析通道是**不需要**这些引擎的，实测可用。

实测边界（2026-10-20，Windows 11 / Node 22 / 无分析引擎）：
  ✅ inspect-managed-members      .NET 元数据 809 方法 / #US 字面量 403 条（与独立解析 403/403 一致）
  ✅ inspect-managed-artifact     .NET 程序集身份
  ✅ inspect-go-binary            Go 构建信息 + 142 条带 h1 校验和的依赖
  ✅ inspect-pe-resources         PE 资源（单文件 ≤ 64 MiB，超限报 resource_constraint）
  ✅ inspect-with-objdump         GNU objdump 原始文本（是"带证据外壳的管道"，不是结构化反汇编）
  ❌ inspect-wasm-artifact        需 REA_WABT_BIN_DIRECTORY（REA 不自带 WABT 二进制）
  ❌ inspect-pcap-capture         需 tshark / capinfos
  ❌ inspect-evm-interface        仅 Linux x64（evmole 预编译档）
  ❌ inspect-binary-layout        仅 Linux x64（pwntools profile）
  ❌ inspect-firmware-regions     仅 Linux + binwalk
  ❌ instructions / decompile     需分析引擎

两个必须记住的坑（都是实测踩出来的）
--------------------------------------
1. **数据在 `normalized_result`，`raw_result` 多数为 null。**
   2026-10-19 曾因只看 `raw_result` 误判「REA 对 Go 二进制返回空」，实际
   `normalized_result.build_info.module_text` 里 14,136 字节的完整模块清单一直在。
2. **`user_strings.literals[].offset` 指向 #US 堆记录的起始（压缩长度前缀），
   不是 UTF-16 载荷起点。** 按 offset 直接按 UTF-16 读会整体错位 1 字节。

沙盒约束
--------
`sandbox/subprocess_executor` 的 AST 白名单禁掉 subprocess/os.system，
所以本工具**只能在 agent 层（tools/adapters）跑**，不能下沉成 skills/ 下的 skill。

用法
----
    registry.run("rea_probe", {"path": "chall.dll"})
    registry.run("rea_probe", {"path": "chall.exe", "lane": "go"})
    python -m tools.adapters.rea_probe <path>     # 手工验证
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

from tools.base import ToolAdapter, ToolOutput
from tools.adapters.flag_scan_adapter import FLAG_PATTERNS

logger = logging.getLogger(__name__)

# ── REA 定位（可用环境变量覆盖，便于换机器）─────────────────────────
_DEFAULT_NODE = r"C:\Users\Lenovo\.workbuddy\binaries\node\versions\22.22.2-6\node.exe"
_DEFAULT_MJS = r"C:\Users\Lenovo\WorkBuddy\2026-10-17-01-34-31\.rea-probe\node_modules\rea-agents\scripts\rea.mjs"

_NODE = os.environ.get("REA_NODE", _DEFAULT_NODE)
_REA_MJS = os.environ.get("REA_MJS", _DEFAULT_MJS)

#: Ghidra 与 JDK 21 的默认位置（decompile 通道依赖）。
#: 必须在这里注入 —— agent 进程自身不会带这两个环境变量，
#: 而 REA 只认环境变量：GHIDRA_INSTALL_DIR 缺失则整套反编译不可用，
#: JAVA_HOME 指向 JDK<21 则 Ghidra 12.x 直接拒绝启动（doctor 仍报 healthy）。
_DEFAULT_GHIDRA = os.environ.get("REA_GHIDRA_DIR", r"E:\Program\ghidra_12.1.4_PUBLIC")
_DEFAULT_JAVA = os.environ.get("REA_JAVA_HOME", r"E:\Program\jdk-21.0.12.1+1")

#: 单次命令硬超时（秒）——REA 的 objdump 反汇编在 12.9MB 样本上约 40s
_TIMEOUT = int(os.environ.get("REA_TIMEOUT", "240"))
#: 单条输出上限（字节）——超过视为失控，不解析（objdump 反汇编实测 7.2MB）
_MAX_BYTES = int(os.environ.get("REA_MAX_BYTES", str(24 * 1024 * 1024)))
#: PE 资源检查的硬上限（REA 自身 64 MiB 限制，抄下来提前判定，省一次失败往返）
_PE_RESOURCE_LIMIT = 64 * 1024 * 1024
#: 通道嗅探时允许全文件扫描的上限（Go buildinfo 可能在 89MB 二进制的尾部）
_SNIFF_MAX = 256 * 1024 * 1024

# ── 批量反编译（analyzeHeadless 单 JVM 生命周期）─────────────────────
#: Ghidra 自带 headless 入口与后置脚本目录。
_GHIDRA_HEADLESS = os.path.join(_DEFAULT_GHIDRA, "support", "analyzeHeadless.bat")
#: 本仓库的 Ghidra 脚本目录（相对本文件 → tools/ghidra_scripts）。
_GHIDRA_SCRIPTS = os.environ.get(
    "REA_GHIDRA_SCRIPTS",
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "ghidra_scripts")),
)
#: 批量通道总超时（秒）。首次 import 要建项目 + 全量自动分析，远高于单函数 40s。
_BATCH_TIMEOUT = int(os.environ.get("REA_BATCH_TIMEOUT", "900"))
#: Ghidra 单文件自动分析上限（秒）。超大样本交给它自己中断并标注 partial，
#: 不要靠外部 kill —— kill 掉的项目目录不完整，反而更难排查。
_BATCH_ANALYSIS_TIMEOUT = int(os.environ.get("REA_BATCH_ANALYSIS_TIMEOUT", "600"))


#: 合法通道集合。用于拒绝拼错的 lane，而不是静默回退到 pe 通道。
_KNOWN_LANES = {
    "auto", "managed", "go", "pe", "elf", "unknown",
    "decompile", "decompile_batch", "batch_decompile", "decompile-all",
}


def _rea_available() -> tuple[bool, str]:
    if not os.path.exists(_NODE):
        return False, f"node 不存在: {_NODE}（设 REA_NODE）"
    if not os.path.exists(_REA_MJS):
        return False, f"rea.mjs 不存在: {_REA_MJS}（设 REA_MJS）"
    return True, ""


def _rea_env() -> dict[str, str]:
    """构造子进程环境：强制注入 Ghidra 与 JDK 21+，不信任调用者的 JAVA_HOME。

    为什么要覆盖而不是 setdefault：本机 JAVA_HOME 指向 JDK 17，而 Ghidra 12.x
    要求 JDK 21+。用 setdefault 会把「已设但版本不够」的情况漏过去，表现为
    decompile 静默失败。
    """
    env = os.environ.copy()
    if _DEFAULT_GHIDRA and os.path.isdir(_DEFAULT_GHIDRA):
        env["GHIDRA_INSTALL_DIR"] = _DEFAULT_GHIDRA
    if _DEFAULT_JAVA and os.path.isdir(_DEFAULT_JAVA):
        env["JAVA_HOME"] = _DEFAULT_JAVA
        env["PATH"] = os.path.join(_DEFAULT_JAVA, "bin") + os.pathsep + env.get("PATH", "")
    return env


def _run_rea(args: list[str]) -> tuple[int, str, str]:
    """调用 REA CLI，返回 (rc, stdout, stderr)。绝不抛异常。"""
    cmd = [_NODE, _REA_MJS, *args]
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_TIMEOUT,
            encoding="utf-8",
            errors="replace",
            cwd=os.path.dirname(_REA_MJS),
            env=_rea_env(),
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {_TIMEOUT}s"
    except Exception as exc:  # noqa: BLE001 - 工具层不因外部进程崩
        return 127, "", f"{type(exc).__name__}: {exc}"


def _call(op: str, path: str, *extra: str) -> dict:
    """跑一条 rea 命令并解析 JSON。失败时返回统一错误字典。"""
    ok, why = _rea_available()
    if not ok:
        return {"_error": "rea_unavailable", "_message": why}
    rc, out, err = _run_rea([op, path, *extra, "--format", "json"])
    if len(out) > _MAX_BYTES:
        return {
            "_error": "output_too_large",
            "_message": f"{op} 输出 {len(out):,} B 超过上限 {_MAX_BYTES:,} B；"
                        f"该命令无结构化分页，改用 --filter-output 或换更窄的操作",
        }
    if not out.strip():
        return {"_error": "empty_output", "_message": (err or f"rc={rc}")[:300]}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"_error": "bad_json", "_message": out[:300]}


def _sniff_lane(path: str) -> str:
    """按字节判定通道：managed / go / pe。只读文件，不执行。

    判定顺序：.NET CLI 头优先（.NET 里也可能嵌 Go 字样），再 Go buildinfo，最后按 PE。
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(4096)
            if _is_elf(head):
                return "elf"
            if head[:2] != b"MZ":
                return "unknown"
            if len(head) < 0x40:
                return "unknown"
            pe = int.from_bytes(head[0x3C:0x40], "little")
            if pe <= 0 or pe + 0x18 > 0x10000:
                return "unknown"
            if pe + 0x18 + 120 > len(head):
                f.seek(pe + 0x18)
                opt = f.read(240)
            else:
                opt = head[pe + 0x18: pe + 0x18 + 240]
            magic = int.from_bytes(opt[0:2], "little") if len(opt) >= 2 else 0
            dd = 96 if magic == 0x10B else 112
            if len(opt) >= dd + 14 * 8 + 4:
                cli = int.from_bytes(opt[dd + 14 * 8: dd + 14 * 8 + 4], "little")
                if cli:
                    return "managed"
            # Go 的 buildinfo 常在文件尾部数据段，必须全扫；上限防呆
            if size <= _SNIFF_MAX:
                f.seek(0)
                if b"\xff Go buildinf:" in f.read():
                    return "go"
    except OSError:
        return "unknown"
    return "pe"


# ── 宽召回裸扫 ────────────────────────────────────────────
# 结构化提取（#US 堆）是精确的，但会漏：.NET 的 EmbeddedResource、#Strings/#Blob、
# .rdata 常量都能藏 flag，而 REA 没有托管资源命令（inspect-pe-resources 查的是
# Win32 资源，不是 ManifestResource）。CTF 里漏 flag 是致命的，所以另开一条
# 「全文件裸扫」通道做召回兜底，再按区回标来源。
_FLAG_BYTES = [
    # str 正则默认带 re.UNICODE(32)，bytes 模式不接受，必须显式剥掉
    re.compile(p.pattern.encode("ascii"), (p.flags & ~re.UNICODE) | re.IGNORECASE)
    for p in FLAG_PATTERNS
]

#: 裸扫读取上限；超出的部分不扫，并在出口如实标注 truncated
_RAWSCAN_MAX = 256 * 1024 * 1024


def _u16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 2], "little")


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


def _pe_sections(data: bytes) -> tuple[int, list[tuple[int, int, int]]]:
    """返回 (image_base, [(节虚拟地址, 有效长度, 文件偏移)]); 非 PE 返回 (0, [])。"""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return 0, []
    pe = _u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        return 0, []
    nsec, opt_size = _u16(data, pe + 6), _u16(data, pe + 20)
    opt = pe + 24
    image_base = _u32(data, opt + 28) if _u16(data, opt) == 0x10B else int.from_bytes(
        data[opt + 24:opt + 32], "little")
    secs = []
    so = opt + opt_size
    for i in range(nsec):
        s = so + i * 40
        va, vsize = _u32(data, s + 12), _u32(data, s + 8)
        raw_size, raw_ptr = _u32(data, s + 16), _u32(data, s + 20)
        secs.append((va, max(vsize, raw_size), raw_ptr))
    return image_base, secs


def _rva2off(rva: int, secs: list[tuple[int, int, int]]) -> int | None:
    for va, size, ptr in secs:
        if va <= rva < va + size:
            return ptr + (rva - va)
    return None


#: 常见加壳器在 PE 节名上留下的指纹。命中即视为「结构化分析只覆盖解压存根」。
_PACKER_SECTIONS: dict[str, tuple[str, ...]] = {
    "UPX": ("UPX0", "UPX1", "UPX2", "UPX!"),
    "ASPack": (".ASPACK", ".ADATA"),
    "Themida / WinLicense": (".THEMIDA", ".WINLICE"),
    "VMProtect": (".VMP0", ".VMP1", ".VMP2"),
    "Enigma Protector": (".ENIGMA1", ".ENIGMA2"),
    "MPRESS": (".MPRESS1", ".MPRESS2"),
    "PECompact": ("PECOMPACT",),
    "NSPack": (".NSP0", ".NSP1", ".NSP2"),
    "Petite": (".PETITE",),
}


def _pe_section_names(data: bytes) -> list[str]:
    """取 PE 节名（latin-1 解码，去尾部 NUL）。非 PE 返回空列表。"""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return []
    pe = _u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        return []
    nsec, opt_size = _u16(data, pe + 6), _u16(data, pe + 20)
    so = pe + 24 + opt_size
    names: list[str] = []
    for i in range(nsec):
        s = so + i * 40
        raw = data[s:s + 8]
        names.append(raw.split(b"\0")[0].decode("latin-1", "replace").strip())
    return names


# ── ELF ────────────────────────────────────────────────────────────
# 2026-10-20 由真题触发：HTB Cyber Apocalypse 2024 的三道 reverse 全是 Linux
# ELF64，而本适配器此前只认 MZ/PE，一律返回「无法识别」。真实赛场的 reverse
# 以 ELF 为主（pwn 更是全部 ELF），这条缺口等于反向通道在真题上直接失效。
_ELF_MACHINE = {
    3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM",
    42: "SuperH", 50: "IA-64", 62: "x86-64", 183: "AArch64", 243: "RISC-V",
}
_ELF_TYPE = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN(PIE/so)", 4: "CORE"}


def _is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def _elf_info(data: bytes) -> dict:
    """读 ELF 头与节表：位数、架构、类型、节名。

    节表可能被剥空（`e_shnum=0`）——UPX 压过的 ELF 正是这样，实测 packedaway
    的 `packed`：`shnum=0`、无节名、只剩 `UPX!` 标记。所以「节名为空」本身
    就是一条加壳线索，不能当作「解析失败」丢掉。

    解析失败必须**说出来**（`parseError` 字段）：ELF 头是后面所有结论的地基，
    地基静默失效会让上层把「没读到」渲染成「读到了但为空」。
    """
    info = {"class": 0, "machine": "?", "type": "?", "sections": [],
            "sectionHeaders": 0, "parseError": None}
    if len(data) < 0x40 or not _is_elf(data):
        return info
    cls = data[4]
    # int.from_bytes 只认 'little'/'big'，不认 '<'/'>' —— 传 '<' 会抛 ValueError。
    # 这里的 except 以前把异常咽掉，结果 class 读到了、machine/type 全是 '?'，
    # 上层照样渲染成「ELF64 ? ?」，看起来像「读到了但值为空」而不是「解析失败」。
    order = "little" if data[5] == 1 else "big"
    info["class"] = 32 if cls == 1 else 64
    try:
        e_type = int.from_bytes(data[16:18], order)
        e_mach = int.from_bytes(data[18:20], order)
        info["type"] = _ELF_TYPE.get(e_type, f"type{e_type}")
        info["machine"] = _ELF_MACHINE.get(e_mach, f"machine{e_mach}")
        if cls == 2:
            shoff = int.from_bytes(data[0x28:0x30], order)
            shentsize = int.from_bytes(data[0x3A:0x3C], order)
            shnum = int.from_bytes(data[0x3C:0x3E], order)
            shstrndx = int.from_bytes(data[0x3E:0x40], order)
            stroff_off, width = 0x18, 8
        else:
            shoff = int.from_bytes(data[0x20:0x24], order)
            shentsize = int.from_bytes(data[0x2E:0x30], order)
            shnum = int.from_bytes(data[0x30:0x32], order)
            shstrndx = int.from_bytes(data[0x32:0x34], order)
            stroff_off, width = 0x10, 4
        info["sectionHeaders"] = shnum
        if not shoff or not shnum or shstrndx >= shnum or shentsize < 0x28:
            return info
        stroff_pos = shoff + shstrndx * shentsize + stroff_off
        if stroff_pos + width > len(data):
            info["parseError"] = "节字符串表超出已读范围（只读了文件头部）"
            return info
        stroff = int.from_bytes(data[stroff_pos:stroff_pos + width], order)
        names = []
        for i in range(min(shnum, 512)):     # 上限防呆：畸形 shnum 不会打爆循环
            p = shoff + i * shentsize
            if p + 4 > len(data):
                info["parseError"] = "节头表超出已读范围（只读了文件头部）"
                break
            nm = int.from_bytes(data[p:p + 4], order)
            s = data.find(b"\0", stroff + nm)
            names.append(data[stroff + nm:s].decode("latin-1", "replace")
                         if s > 0 else "")
        info["sections"] = names
    except (IndexError, ValueError) as exc:
        info["parseError"] = f"{type(exc).__name__}: {exc}"
    return info


def _elf_section_names(data: bytes) -> list[str]:
    return [n for n in _elf_info(data)["sections"] if n]


def _elf_info_file(path: str) -> dict:
    """按文件取 ELF 信息。

    节表在文件**尾部**：只读 0x2000 头部的信息里 `parseError` 会是「超出已读范围」，
    上层会据此如实降级，而不是把「没读到的节」报成「没有节」。
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size <= _PACKER_FULL_READ:
                return _elf_info(f.read())
            return _elf_info(f.read(0x2000))
    except OSError:
        return _elf_info(b"")



def _packer_hint(data: bytes) -> str | None:
    """按节名判定已知加壳器，返回壳名或 None。

    为什么必须做：UPX 压过的 pip.exe 实测 **274 函数 → 3 函数**（输出 402,891 B →
    8,913 B），而 Ghidra 没有任何提示——它只是老实分析了它看到的那层存根。
    如果适配器照实报 complete，下游就会把「3 个函数」读成「这个程序只有 3 个函数、
    已经分析完整」。这是比漏报更糟的错报：结论方向正好相反。

    节名匹配是加壳器自己留下的元数据，比熵值/入口点启发式更不容易误判，
    所以只用节名，不猜。
    """
    names = [n.upper() for n in _pe_section_names(data)]
    if not names:
        # ELF 也要判：真题 packedaway 的 `packed` 是节表被剥空的 ELF（shnum=0），
        # 只剩 `UPX!` 标记 —— 旧实现到 `return None` 就结束了，等于对 ELF 完全不设防。
        names = [n.upper() for n in _elf_section_names(data)]
    for packer, sigs in _PACKER_SECTIONS.items():
        for sig in sigs:
            if any(n == sig or n.startswith(sig) for n in names):
                return packer
    # UPX 的 `UPX!` 标记还可能出现在节名之外（ELF 常把节表整个剥掉时只剩它）；
    # 节名被改掉时也靠它兜底。放在节名判定之后，因为节名更具体。
    if b"UPX!" in data[:0x2000]:
        return "UPX"
    return None


#: ELF 加壳判定需要整读的上限。PE 的节表在头部附近（0x2000 足够），
#: ELF 的节表在**文件尾部**，只读头部永远看不到 —— 而整读 1 GB 的样本更糟，
#: 所以大文件退化为只看头部（此时仅 `UPX!` 标记兜底，节名判定不可用）。
_PACKER_FULL_READ = 64 * 1024 * 1024

#: 超过这个大小的 ELF 不再提示「升级 decompile_batch」：全量导出的时间与
#: 函数数成正比（实测 flecks 1.09MB / 1557 函数 ≈ 90s，再大就进入分钟级），
#: 提示会变成误导。小文件（绝大多数 CTF rev 题）才值得升级。
_ELF_HINT_MAX_BYTES = 8 * 1024 * 1024

#: CRT / 运行时 / 模板库符号前缀。判「有没有自定义函数」时先把它们剔掉：
#: flecs 的 1557 个函数里 1550 个是模板库，不滤的话升级提示永远在刷屏，
#: 真正的信号（rand_pos / operator()）反而被埋掉。判据是**前缀**不是全名 ——
#: mangled 名（_ZN5flecs…/_ZSt…）只有前缀是稳定的。
_CRT_SYM_PREFIXES = (
    "_init", "_fini", "_start", "_edata", "_end", "__bss_start",
    "__libc", "__gmon", "__cxa", "__cxx", "_ITM_", "_GLOBAL__sub_I_",
    "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux",
    "frame_dummy", "completed", "__dso_handle", "__stack_chk",
    "_ZSt", "_ZNSt", "_ZNKSt", "_ZNSs", "_ZN5flecs", "_ZN6flecs",
    "_Znwm", "_ZdlPv", "_ZdaPv", "_Unwind", "__gxx_personality",
    "register_tm", "atexit", "__errno", "call_weak_fn",
)


def _is_crt_symbol(name: str) -> bool:
    """这个符号是不是 CRT/运行时/模板库的（而非题目自带逻辑）。"""
    n = name.split("@")[0]          # 去掉 version 后缀：foo@GLIBC_2.34
    if "@plt" in name:
        return True                 # PLT 桩：导入的库函数，不是本题逻辑
    base = n.rsplit(".", 1)[0] if "." in n and not n.startswith("_Z") else n
    for pfx in _CRT_SYM_PREFIXES:
        if n.startswith(pfx) or base.startswith(pfx):
            return True
    # .constprop.N / .part.N / .cold 是 GCC 克隆后缀，保留基名再判一次
    for suffix in (".constprop.0", ".constprop.1", ".part.0", ".isra.0", ".cold"):
        if n.endswith(suffix):
            return _is_crt_symbol(n[: -len(suffix)])
    return False


def _packer_hint_file(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            head = f.read(0x2000)
            if _is_elf(head) and os.path.getsize(path) <= _PACKER_FULL_READ:
                f.seek(0)
                return _packer_hint(f.read())
        return _packer_hint(head)
    except OSError:
        return None


# ── UPX 脱壳（只脱 UPX，别的一律如实拒）──────────────────────────────
#: upx 可执行文件位置；环境变量优先，其次 PATH。实测 5.2.1 才能脱 4.x 压的样本。
_DEFAULT_UPX = os.environ.get("REA_UPX", r"E:\Program\tools\upx-5.2.1-win64\upx.exe")
_UNPACK_TIMEOUT = int(os.environ.get("REA_UNPACK_TIMEOUT", "180"))


def _upx_exe() -> str | None:
    for cand in (_DEFAULT_UPX, shutil.which("upx")):
        if cand and os.path.isfile(cand):
            return cand
    return None


def _unpack_upx(path: str) -> tuple[str | None, dict]:
    """把 path **复制到临时目录**再用 `upx -d` 脱壳；返回 (副本路径, 证据)。

    为什么要做：加壳样本的静态分析只能看到解压存根（实测 UPX 压 pip.exe：
    274 函数 → 3 函数），此前适配器只能诚实地报 degraded，等于把「壳」这个
    最常见的第一层挡在门外。upx -d 是确定性操作，能把这一层直接拆掉。

    四条硬约束（每条都对应一种会出错的方式）：
    1. **绝不改原文件**：只在 `tempfile.mkdtemp()` 的副本上脱壳。用户原始题目
       文件必须字节不变，这里在测试里用 sha256 前后比对守住。
    2. **成功要复核**：`upx` 退出码 0 不算数，还要再查节名表里壳签名是否消失。
       只信退出码就会把「报成功但没变」当成脱壳成功。
    3. **只脱 UPX**：ASPack/MPRESS/自研壳一律 rc!=0，此时返回 None + 原因，
       调用方继续用原文件并保持 degraded —— 不假装脱过。
    4. **失败不清理副本**：路径写进证据，便于人工复查；临时目录交给系统回收。
    """
    ev: dict = {"tool": "upx", "source": path}
    exe = _upx_exe()
    if not exe:
        ev.update(ok=False, reason="未找到 upx（可用 REA_UPX 指定，或加入 PATH）")
        return None, ev
    ev["exe"] = exe
    try:
        size_before = os.path.getsize(path)
        out_dir = tempfile.mkdtemp(prefix="rea_unpack_")
        dst = os.path.join(out_dir, os.path.basename(path))
        shutil.copyfile(path, dst)
    except OSError as exc:
        ev.update(ok=False, reason=f"复制到临时目录失败：{exc}")
        return None, ev

    t0 = time.time()
    try:
        proc = subprocess.run(
            [exe, "-d", "-q", dst],
            capture_output=True, text=True, timeout=_UNPACK_TIMEOUT,
        )
        rc = proc.returncode
        msg = ((proc.stderr or "") + (proc.stdout or "")).strip()
    except subprocess.TimeoutExpired:
        ev.update(ok=False, reason=f"upx -d 超时（>{_UNPACK_TIMEOUT}s）", unpacked=dst)
        return None, ev
    except OSError as exc:
        ev.update(ok=False, reason=f"upx 启动失败：{exc}")
        return None, ev

    ev.update(rc=rc, ms=int((time.time() - t0) * 1000), message=msg[:300],
              sizeBefore=size_before, sizeAfter=os.path.getsize(dst), unpacked=dst)
    if rc != 0:
        ev.update(ok=False, reason=f"upx -d rc={rc}：{msg[:200] or '(无输出)'}")
        return None, ev
    still = _packer_hint_file(dst)
    if still:
        ev.update(ok=False,
                  reason=f"upx 报成功但节名仍见 {still} 签名，不采信（未脱净）")
        return None, ev
    ev["ok"] = True
    return dst, ev


def _pe_regions(data: bytes) -> dict[str, tuple[int, int]]:
    """定位 PE/CLI 关键区的（文件偏移, 长度）：#US/#Strings/#Blob/CLI 资源区。

    只做定位不做语义解析；结构不合法时返回 {}，退化成无标注裸扫。
    """
    try:
        if data[:2] != b"MZ":
            return {}
        pe = _u32(data, 0x3C)
        if data[pe:pe + 4] != b"PE\0\0":
            return {}
        opt = pe + 24
        magic = _u16(data, opt)
        dd = opt + (96 if magic == 0x10B else 112)
        cli_rva = _u32(data, dd + 14 * 8)
        if not cli_rva:
            return {}

        _, secs = _pe_sections(data)
        rva2off = lambda r: _rva2off(r, secs)  # noqa: E731

        cli = rva2off(cli_rva)
        if cli is None:
            return {}
        out: dict[str, tuple[int, int]] = {}

        # CLI header +24: Resources RVA / Size（托管资源区，ManifestResource 指向它）
        res_rva, res_size = _u32(data, cli + 24), _u32(data, cli + 28)
        if res_rva and res_size:
            off = rva2off(res_rva)
            if off is not None:
                out["CLI 资源区"] = (off, res_size)

        md_rva = _u32(data, cli + 8)
        md = rva2off(md_rva)
        if md is None or _u32(data, md) != 0x424A5342:
            return out
        vlen = _u32(data, md + 12)
        # version string（含终止符）后 4 字节对齐，再是 Flags(2) + Streams(2)
        p = (md + 16 + vlen + 3) & ~3
        nstreams = _u16(data, p + 2)
        p += 4
        label = {"#US": "#US 堆", "#Strings": "#Strings 堆", "#Blob": "#Blob 堆"}
        for _ in range(nstreams):
            soff, ssize = _u32(data, p), _u32(data, p + 4)
            p += 8
            end = data.index(b"\0", p)
            name = data[p:end].decode("ascii", "replace")
            p = (end + 1 + 3) & ~3
            if name in label and ssize:
                out[label[name]] = (md + soff, ssize)
        return out
    except Exception:  # noqa: BLE001 - 定位失败不该影响主流程
        return {}


def _region_of(off: int, regions: dict[str, tuple[int, int]]) -> str:
    for name, (start, length) in regions.items():
        if start <= off < start + length:
            return name
    return "未归类区"


def _plausibility(value: str) -> str:
    """给命中打置信分级。不过滤——CTF 里漏真 flag 的代价远大于误报。

    实战背景：DASCTF 每题提交次数有上限，把 `flag{...}` 占位符当真 flag 提交
    会直接烧配额，所以必须让 agent 一眼看出哪条值得交。
    """
    inner = value.split("{", 1)[1].rstrip("}") if "{" in value else value
    if "{" in inner or re.search(r"%[sdx]|\$\{|\{\{", value):
        return "模板"
    # 纯符号判定必须排在长度之前：`flag{...}` 只有 3 个点，否则会被判成「过短」
    if re.fullmatch(r"[.\-_*?xX\s]+", inner):
        return "占位符"
    if len(inner) < 4:
        return "过短"
    # 正文含控制字节/非 ASCII → 二进制噪声，不是 flag。
    # 2026-10-20 实测：1 MB 的 flecks（C++ ECS 二进制）上有 4 条这样的命中被
    # 打成 ★，全是 x86 指令流里偶然出现的 `H{...}`/`o{...}` 形状。真实 flag 的
    # 字符集恒为可打印 ASCII；非打印字节是「这是代码不是字符串」的强信号。
    # 注意只降级不删除：UPX 反 strings 混淆（helloupx11）会把 \x91\xe6\xff\xff
    # 插进真 flag 中间，那种情况由 flag_scan 的 cleaned 逻辑剥，不能在这里一刀切。
    if any(ord(c) < 0x20 or ord(c) > 0x7E for c in inner):
        return "二进制噪声"
    if re.fullmatch(r"[0-9a-fA-F]{16,}", inner):
        return "疑似哈希"
    return "★"


def _rawscan(path: str) -> tuple[list[dict], dict]:
    """全文件裸扫 flag，三路覆盖：明文 / UTF-16 偶数对齐 / UTF-16 奇数对齐。

    UTF-16 的低字节恒定落在同一奇偶位上，因此按步长切片后直接跑 ASCII 字节正则
    即可，无需逐字符解码 —— 16MB 文件也在百毫秒级。

    为什么只标"对齐"不标 LE/BE：对纯 ASCII 载荷，LE@偶 与 BE@奇 切片后的字节流
    完全相同，编码不可判定。硬标 utf16le/utf16be 等于陈述没有的信息，所以只报
    该字符串落在哪种对齐上。代价是只认 ASCII 载荷（CTF flag 字符集恒为 ASCII）。
    """
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        data = f.read(_RAWSCAN_MAX)
    regions = _pe_regions(data)
    # (标签, 字节流, 步长, 基址)：data[k::2][j] 对应文件偏移 2j+k
    lanes = (
        ("utf8", data, 1, 0),
        ("utf16@偶", data[0::2], 2, 0),
        ("utf16@奇", data[1::2], 2, 1),
    )
    hits: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for enc, blob, stride, base in lanes:
        for pat in _FLAG_BYTES:
            for m in pat.finditer(blob):
                off = m.start() * stride + base
                val = m.group(0).decode("ascii", "replace")
                key = (val.lower(), off)
                if key in seen:
                    continue
                seen.add(key)
                hits.append({
                    "value": val,
                    "encoding": enc,
                    "offset": off,
                    "region": _region_of(off, regions),
                    "plausibility": _plausibility(val),
                })
    # 子串吞并：DASCTF{x} 里也匹配得 CTF{x}，保留最长的那条
    kept: list[dict] = []
    for h in sorted(hits, key=lambda x: (-len(x["value"]), x["offset"])):
        low = h["value"].lower()
        if any(low in k["value"].lower() and low != k["value"].lower() for k in kept):
            continue
        kept.append(h)
    kept.sort(key=lambda h: h["offset"])
    return kept, {
        "size": size,
        "scanned": len(data),
        "truncated": size > len(data),
        "regions": sorted(regions),
    }


def _flags_in(values) -> list[str]:
    """从字符串集合里提 flag 候选（与 flag_scan 同一套正则，含 UPX 混淆清洗）。

    去重按「子串吞并」：`CTF{...}` 是 `DASCTF{...}` 的后缀，两者都会命中，
    只保留更长的那个，避免同一 flag 报两个前缀。
    """
    hits: list[str] = []
    seen: set[str] = set()
    for v in values:
        if not isinstance(v, str) or not v:
            continue
        for pat in FLAG_PATTERNS:
            for m in pat.finditer(v):
                raw = m.group(0)
                cleaned = re.sub(r"[^\x20-\x7e]", "", raw)
                for cand in (cleaned, raw):
                    if cand and cand not in seen:
                        seen.add(cand)
                        hits.append(cand)
    return [h for h in hits if not any(h != o and h in o for o in hits)]


def _contract(*, authority: str, status: str, truncated: bool = False,
              omitted: int = 0, degraded: bool = False, reason: str | None = None,
              limitations: list[str] | None = None, evidence: dict | None = None) -> dict:
    """出口契约：与 SecAutoMind 的 `_contract` 同形，跨项目可读同一套字段。"""
    return {
        "authority": authority,
        "coverage": {"status": status, "truncated": truncated, "omittedCount": omitted},
        "degraded": degraded,
        "degradationReason": reason,
        "limitations": limitations or [],
        "evidence": evidence or {},
    }


# ── 反编译渲染（PE 与 ELF 共用）────────────────────────────────────
#: 伪代码单次注入上下文的字符上限。REA 的 decompile 返回的是整函数伪代码，
#: 大函数能到几万字符；原样塞进 prompt 会把上下文吃光，而截断必须**说出来**。
_DECOMPILE_LIMIT = int(os.environ.get("REA_DECOMPILE_LIMIT", "6000"))

#: 批量导出的代码内联上限。实测：13 函数的 crush 是 4,271 字符；848 函数的
#: 12.3MB 样本是 400 KB 量级，全塞进去会把上下文吃光。默认 24K 字符约等于
#: 6K token，够覆盖中小题目的全部真实逻辑。
_BATCH_INLINE_CHARS = int(os.environ.get("REA_BATCH_INLINE_CHARS", "24000"))

#: 每个 ELF/PE 都有的 CRT 脚手架，函数体基本是空转。内联时先剔掉，
#: 否则前 40 个函数名额全被它们占满（实测 crush 13 个函数里 8 个是这类）。
_CRT_BOILERPLATE = {
    "_init", "_start", "_fini", "processEntry _start", "deregister_tm_clones",
    "register_tm_clones", "__do_global_dtors_aux", "frame_dummy",
    "__libc_csu_init", "__libc_csu_fini", "__libc_csu_init", "_dl_relocate_static_pie",
}


def _inline_decompiled(out_c: str, funcs: list, limit: int) -> tuple[str, dict]:
    """把 ExportAllDecompiled 的 C 文件按函数块内联，返回 (文本, 统计)。

    规则：
    1. 按 `// ==== FUNC <va> <name> size=<n> ====` 标记切块；
    2. 剔掉 CRT 脚手架（每个二进制都有，且几乎无信息量）；
    3. `main` 排在最前 —— 赛题逻辑几乎都从 main 出发；
    4. 其余按地址序，累计到 limit 为止，超了就说清少了多少。
    """
    stats = {"chars": 0, "total": 0, "funcs": 0, "omittedFuncs": 0, "error": None}
    try:
        with open(out_c, encoding="utf-8", errors="replace") as f:
            src = f.read()
    except OSError as exc:
        stats["error"] = f"{type(exc).__name__}: {exc}"
        return "", stats
    stats["total"] = len(src)

    parts = re.split(r"(?m)^(// ==== FUNC .+?====)\s*$", src)
    blocks: list[tuple[str, str, str]] = []      # (va, name, body)
    for i in range(1, len(parts) - 1, 2):
        marker, body = parts[i], parts[i + 1]
        m = re.match(r"// ==== FUNC (\S+) (\S+) size=\d+ ====", marker)
        if not m:
            continue
        blocks.append((m.group(1), m.group(2), marker + "\n" + body.rstrip() + "\n"))

    kept = [b for b in blocks if b[1] not in _CRT_BOILERPLATE]
    dropped = len(blocks) - len(kept)
    kept.sort(key=lambda b: (b[1] != "main", b[0]))     # main 优先，其余按地址

    out: list[str] = []
    used = 0
    for va, nm, body in kept:
        if used + len(body) > limit and out:
            break
        out.append(body)
        used += len(body)
    stats["chars"] = used
    stats["funcs"] = len(out)
    stats["omittedFuncs"] = len(kept) - len(out)
    if dropped:
        stats["droppedBoilerplate"] = dropped
    return "\n".join(out), stats


def _render_decompile(j: dict, sel: str, note: str, lane: str = "decompile") -> tuple[str, dict]:
    """把 REA decompile 的 JSON 渲染成 (文本, 契约)。

    PE 与 ELF 都走这里：两者的差别只在**怎么定位函数**（PE 按节表换算成文件偏移、
    ELF 直传分析地址），拿到伪代码之后的呈现与契约完全一致，所以只写一份。
    """
    if "_error" in j:
        return f"[rea_probe] 反编译不可用：{j['_error']} —— {j['_message']}", j
    code = j.get("normalized_result")
    if not isinstance(code, str):
        code = json.dumps(code, ensure_ascii=False) if code else ""
    detail = (j.get("details") or {})
    if not code:
        return (f"[rea_probe] 反编译返回空（{detail.get('code') or 'no pseudo-code'}）"
                f"{('：' + str(detail.get('message'))[:160]) if detail.get('message') else ''}",
                _contract(authority="unknown", status="unknown",
                          limitations=["Ghidra 未返回伪代码，目标可能是数据或未识别的代码"]))

    shown = code[:_DECOMPILE_LIMIT]
    head_lines = [
        f"[rea_probe] lane={lane}  selector={sel}",
        f"  解析：{note or '按函数名直传'}",
        f"  伪代码 {len(code):,} 字符"
        + (f"（此处仅列前 {_DECOMPILE_LIMIT:,}，完整内容用 --format json 取 "
           f"normalized_result）" if len(code) > _DECOMPILE_LIMIT else ""),
    ]
    contract = _contract(
        authority="observed",
        status="partial" if len(code) > _DECOMPILE_LIMIT else "complete",
        truncated=len(code) > _DECOMPILE_LIMIT,
        limitations=[
            "Ghidra 冷启动 + 自动分析约 40s/次，且 --snapshot 实测不加速（每次都重新分析）",
            "迁移到递归下降失败的区域可能是数据而非代码；未做动态验证",
        ],
        evidence={
            "tool": "rea.decompile",
            "evidenceId": j.get("evidence_id"),
            "sha256": ((j.get("subject") or {}).get("digest") or {}).get("sha256"),
            "ghidraVersion": ((j.get("provider") or {}).get("version")),
        },
    )
    return "\n".join(head_lines) + "\n" + "-" * 60 + "\n" + shown, contract


class ReaProbeAdapter(ToolAdapter):
    """REA 无引擎静态分析：.NET 元数据/字符串、Go 构建信息、PE 资源、objdump 反汇编。"""

    name = "rea_probe"
    categories = ["reverse", "misc"]
    #: plan 可透传参数（主链按此白名单转发，见 core/action_executor.py）
    param_spec = {
        "lane": "auto|managed|go|pe|elf|decompile|decompile_batch",
        "selector": "函数名/地址（decompile 用）",
        "max_funcs": "导出上限，0=全量（batch 用）",
        "name_filter": "按名过滤（batch；逗号/空格分隔多词=OR；无符号二进制基本无效）",
        "unpack": "auto|off：auto（默认）检测到 UPX 壳就在副本上脱壳再分析；off 只分析存根层",
    }

    def __init__(self, sandbox=None) -> None:
        super().__init__(sandbox=sandbox)

    @property
    def description(self) -> str:
        return (
            "REA 静态分析（.NET/Go/PE/反编译四条通道，任何通道都会附带全文件 flag 裸扫）："
            "lane=managed 取类型/方法/#US 字符串；lane=go 取构建信息与依赖；"
            "lane=pe 取资源与 objdump 反汇编；lane=decompile 定点反编译（需 selector=函数名或地址，"
            "内部自动把 VA 换算成 REA 要的文件偏移，单次约 40s）；"
            "lane=decompile_batch 一次 JVM 生命周期批量导出全部函数（首次约 40s 分析 + 每函数约 15ms，"
            "输出 C 文件路径，可配 max_funcs / name_filter 控制规模）。检测到 UPX 壳时自动在临时副本上"
            "upx -d 脱壳再分析（unpack=off 关闭，原文件不改）。传 path，"
            "可选 lane=auto|managed|go|pe|decompile|decompile_batch"
        )

    # ── 各通道 ────────────────────────────────────────────

    def _lane_managed(self, path: str) -> tuple[str, dict]:
        j = _call("inspect-managed-members", path)
        if "_error" in j:
            return f"[rea_probe] .NET 元数据不可用：{j['_error']} —— {j['_message']}", j
        nr = j.get("normalized_result") or {}
        us = (nr.get("user_strings") or {})
        lits = us.get("literals") or []
        values = [l.get("value", "") for l in lits]
        flags = _flags_in(values)
        meta = nr.get("metadata") or {}
        lim = j.get("limitations") or []
        cov = nr.get("coverage") or {}

        lines = [
            f"[rea_probe] lane=managed  {os.path.basename(path)}",
            f"  类型 {len(nr.get('types') or [])} / 方法 {len(nr.get('methods') or [])}"
            f" / #US 字面量 {len(lits)}（state={us.get('state')}）",
        ]
        if flags:
            lines.append("  ★ flag 候选：" + " | ".join(flags[:6]))
        # 高价值字面量：含 sql/select/password/key/cmd/http 之类只按需给前 10 条
        hot = [v for v in values if v and 3 <= len(v) <= 80][:10]
        if hot:
            lines.append("  字面量样例：" + " ⋮ ".join(hot))
        lines.append(f"  覆盖：{cov.get('state', 'unknown')}（issues={len(cov.get('issues') or [])}）")
        if lim:
            lines.append("  局限：" + lim[0][:160])

        # 「一个都没读到」和「读到一部分」是两件事。mscorlib.dll（5.4MB，官方
        # 程序集）实测就返回 0/0/0 + `CLI metadata could not be admitted`，
        # 若还标 partial，下游会以为拿到了一部分真数据。整体不可用必须降级。
        empty = (not (nr.get("types") or []) and not (nr.get("methods") or []) and not lits)
        if empty and lim:
            lines.append("  ⚠ 本通道整体不可用：不是『程序集为空』，是元数据被拒。"
                         "换成 lane=pe 或裸扫取证，勿以本条下结论")
            status, authority, degraded = "not_applicable", "unknown", True
        elif cov.get("state") == "complete":
            status, authority, degraded = "complete", "observed", False
        else:
            status, authority, degraded = "partial", "observed", False

        text = "\n".join(lines)
        contract = _contract(
            authority=authority,
            status=status,
            degraded=degraded,
            reason=(lim[0][:200] if degraded and lim else None),
            limitations=lim[:3],
            evidence={
                "tool": "rea.inspect-managed-members",
                "evidenceId": j.get("evidence_id"),
                "sha256": ((j.get("subject") or {}).get("digest") or {}).get("sha256"),
            },
        )
        return text, contract

    def _lane_go(self, path: str) -> tuple[str, dict]:
        j = _call("inspect-go-binary", path)
        if "_error" in j:
            return f"[rea_probe] Go 构建信息不可用：{j['_error']} —— {j['_message']}", j
        nr = j.get("normalized_result") or {}
        bi = nr.get("build_info") or {}
        module_text = bi.get("module_text") or ""
        lines_out = [l.split("\t") for l in module_text.splitlines() if l.strip()]
        deps = [l for l in lines_out if l and l[0] == "dep"]
        mods = [l for l in lines_out if l and l[0] == "mod"]
        main = mods[0] if mods else None
        # 依赖里最值得报的：非 Google/AWS/Azure 的"自己的"私有依赖
        interesting = [d[1] for d in deps if len(d) > 1 and not d[1].startswith(
            ("google.golang.org", "cloud.google.com", "github.com/Azure",
             "github.com/aws", "github.com/google"))]
        text = "\n".join([
            f"[rea_probe] lane=go  {os.path.basename(path)}  {bi.get('go_version')}",
            f"  主模块：{main[1] + ' ' + (main[2] if len(main) > 2 else '') if main else '(未声明)'}",
            f"  依赖 {len(deps)} 条（其中非云厂商 {len(interesting)} 条）",
            ("  依赖样例：" + " ⋮ ".join(interesting[:8])) if interesting else "",
            f"  buildinfo 偏移：{bi.get('header_offset')}（{bi.get('encoding')}）",
        ]).strip()
        # 无 build_info 时硬判 complete 等于宣称「这是 Go 程序且信息完整」，
        # 而真实情况往往是「它根本不是 Go 程序」或「strip 掉了」。分开表述。
        has_info = bool((module_text or "").strip())
        if not has_info:
            text += ("\n  ⚠ 未取到 build_info：要么不是 Go 二进制，要么构建信息被 strip。"
                     "本条不能证明『依赖为空』")
        contract = _contract(
            authority="observed" if has_info else "unknown",
            status="complete" if has_info else "not_applicable",
            degraded=not has_info,
            reason=None if has_info else "未取到 build_info：非 Go 二进制或构建信息被 strip",
            limitations=(j.get("limitations") or [])[:2],
            evidence={
                "tool": "rea.inspect-go-binary",
                "evidenceId": j.get("evidence_id"),
                "sha256": ((j.get("subject") or {}).get("digest") or {}).get("sha256"),
            },
        )
        return text, contract

    # ── ELF 通道 ────────────────────────────────────────────────────
    # 2026-10-20：HTB Cyber Apocalypse 2024 的三道 reverse 全是 ELF64。
    # REA 的 `inspect-with-objdump` 对 ELF 直接返回 invalid_request（实测），
    # 所以这条通道不经过 REA，直接调本机 binutils：拿到的是同一份 objdump 事实，
    # 但少了 REA 的 Evidence 包装 —— 这一点写进 limitations，不假装有。
    _OBJDUMP_CANDIDATES = (
        os.environ.get("REA_OBJDUMP", ""),
        r"D:\miniconda3_new\Library\mingw-w64\bin\objdump.exe",
        r"C:\Program Files\Git\usr\bin\objdump.exe",
        r"D:\msys64\mingw64\bin\objdump.exe",
        r"D:\msys64\usr\bin\objdump.exe",
        r"C:\mingw64\bin\objdump.exe",
    )

    def _objdump_exe(self) -> str | None:
        for c in self._OBJDUMP_CANDIDATES:
            if c and os.path.isfile(c):
                return c
        found = shutil.which("objdump")
        return found if found else None

    def _objdump(self, exe: str, args: list[str]) -> tuple[int, str, str]:
        """跑一次 objdump。stdout/stderr 合并交给调用方判读，不在这里猜。"""
        p = subprocess.run([exe, *args], capture_output=True, text=True,
                           timeout=_TIMEOUT, encoding="utf-8", errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""

    def _elf_name_for_addr(self, path: str, sel: str) -> str | None:
        """把地址选择器反查成符号表里的真名（ELF 定点反编译的回退路径）。

        带符号 ELF 的函数在 Ghidra 里有真名（add_char_to_map），按地址过滤
        （FUN_ 命名）必然零命中。objdump -t 同时给出地址和真名，反查即可。
        地址按十六进制解释（objdump 输出即裸 hex）；查不到返回 None。
        """
        exe = self._objdump_exe()
        if not exe:
            return None
        try:
            want = int(str(sel).lower().removeprefix("0x"), 16)
        except ValueError:
            return None
        try:
            rc, so, _ = self._objdump(exe, ["-t", path])
        except subprocess.TimeoutExpired:
            return None
        for ln in so.splitlines():
            t = ln.split()
            if len(t) >= 5 and t[2] == "F" and t[1] != "UND":
                try:
                    if int(t[0], 16) == want:
                        return t[-1]
                except ValueError:
                    continue
        return None

    def _lane_elf(self, path: str) -> tuple[str, dict]:
        size = os.path.getsize(path)
        try:
            with open(path, "rb") as f:
                head = f.read(0x2000)
        except OSError as exc:
            return f"[rea_probe] 读取失败：{exc}", _contract(
                authority="unknown", status="fail", limitations=[str(exc)])

        info = _elf_info_file(path)
        sec_count = info["sectionHeaders"]
        sec_names = [n for n in info["sections"] if n]
        head_line = (f"[rea_probe] lane=elf  {os.path.basename(path)}  {size:,} B  "
                     f"ELF{info['class']} {info['machine']} {info['type']}")
        lines = [head_line]
        # 2026-10-21 ruff F821 修复：原实现先 append 后定义 lines（NameError 只在
        # parseError 分支触发——ELF 节头表在 0x2000 读窗之外/解析不完整时）。
        if info.get("parseError"):
            lines.append(f"  ⚠ ELF 头解析不完整：{info['parseError']}")
        contract_parts: list[dict] = []

        exe = self._objdump_exe()
        if not exe:
            lines.append("  objdump：不可用（本机没有 binutils objdump；"
                         "设 REA_OBJDUMP 指向它）。仅做 ELF 头解析")
            contract_parts.append(_contract(
                authority="derived", status="partial", degraded=True,
                reason="objdump 缺失，只解析 ELF 头",
                limitations=["objdump 不可用：节表/符号/动态段均未读取，"
                     "此处结论不代表二进制内容"],
                evidence={"tool": "builtin.elf-header", "sectionCount": sec_count},
            ))
        else:
            lines.append(f"  objdump：{os.path.basename(exe)}")

        # 节表（ELF 的节表可能被剥空，这本身是加壳线索）
        if sec_names:
            shown = " ".join(sec_names[:12]) + (" …" if len(sec_names) > 12 else "")
            lines.append(f"  节 {sec_count} 个：{shown}")
        elif sec_count == 0:
            lines.append("  节表：e_shnum=0（节头被剥/未保留 —— 常见于加壳或做过 strip 的 ELF）")
        else:
            lines.append(f"  节表：无法解析（声明 {sec_count} 个节，字符串表不可达）")

        if exe:
            # 1) 文件头：格式 / 架构 / 入口
            try:
                rc, so, se = self._objdump(exe, ["-f", path])
                fmt = next((ln.split("file format")[-1].strip() for ln in so.splitlines()
                            if "file format" in ln), "")
                entry = next((ln.split("start address")[-1].strip() for ln in so.splitlines()
                              if "start address" in ln), "")
                flags = next((ln.split("flags")[-1].strip() for ln in so.splitlines()
                              if "flags" in ln), "")
                if fmt:
                    lines.append(f"  格式：{fmt}  入口 {entry or '?'}  标志 {flags or '?'}")
                contract_parts.append(_contract(
                    authority="observed", status="complete" if fmt else "partial",
                    evidence={"tool": "objdump -f", "format": fmt,
                              "entry": entry, "flags": flags},
                    limitations=[] if fmt else ["objdump -f 未回显 file format 行"],
                ))
            except subprocess.TimeoutExpired:
                lines.append("  objdump -f：超时")

            # 2) 符号表：函数名是 decompile 选择器的直接来源；strip 程度必须说清
            #    objdump -t 的行形如：
            #      0000000000001040 g     F .text	0000000000000015	main
            #      0000000000000000  w   F *UND*	0000000000000030	printf
            #    = addr / flags / type / section / size / **name**。
            #    早先取 p_[3] 拿到的是节名，于是每一行都渲染成 `.text` ——
            #    看起来「符号表读到了」，实际函数名一个都没拿到。
            try:
                def _func_syms(blob: str) -> list[tuple[str, str]]:
                    out = []
                    for ln in blob.splitlines():
                        t = ln.split()
                        if len(t) >= 5 and t[2] == "F" and t[1] != "UND":
                            out.append((t[-1], t[0]))
                    return out

                rc, so, se = self._objdump(exe, ["-t", path])
                funcs = _func_syms(so)
                dyn_only = False
                if not funcs:
                    rc2, so2, _ = self._objdump(exe, ["-T", path])
                    funcs = _func_syms(so2)
                    dyn_only = bool(funcs)
                if funcs:
                    tag = "仅动态符号（.symtab 已剥）" if dyn_only else "静态符号表"
                    lines.append(f"  函数 {len(funcs)} 个（{tag}）")
                    lines.append("    名称：" + " ".join(n for n, _ in funcs[:10]))
                    lines.append("    地址：" + " ".join(a for _, a in funcs[:10]))
                else:
                    lines.append("  函数 0 个（动态+静态符号都没有 —— strip 过或符号被抹除；"
                                 "decompile 只能按地址选函数）")
                # 升级提示（2026-10-21）：lane=elf 只给结构+裸扫，看不到逻辑。
                # 实测真题 crushing：agent 连续 4 次调 lane=auto 后被死循环闸止损，
                # 从未升级到 decompile_batch —— 不是模型不会，是没人告诉它该升级。
                # 判据（两个都必须成立，避免对系统库刷屏）：
                #   ① 有非 CRT/非模板库的自定义函数名（题面逻辑的载体）；
                #   ② 文件不大（decompile_batch 全量导出的时间与函数数成正比）。
                _custom = [n for n, _ in funcs
                           if not _is_crt_symbol(n)][:8]
                if _custom and size <= _ELF_HINT_MAX_BYTES:
                    shown = "/".join(_custom[:4])
                    lines.append(
                        f"  ↑ 升级提示：检测到 {len(_custom)} 个自定义函数（如 {shown}）。"
                        f"若上方裸扫未出 flag，逻辑大概率在这些函数里 —— "
                        f"改用 lane=decompile_batch name_filter=<函数名>（本机约 15–90s）")
                contract_parts.append(_contract(
                    authority="observed", status="complete",
                    evidence={"tool": "objdump -t", "funcs": len(funcs),
                              "dynOnly": dyn_only,
                              "customFuncs": len(_custom)},
                    limitations=[] if funcs else ["无任何函数符号：反编译只能按地址定位"],
                ))
            except subprocess.TimeoutExpired:
                lines.append("  objdump -t：超时")

            # 3) 动态段：NEEDED 说明依赖，PIE/RPATH 影响执行面
            try:
                rc, so, se = self._objdump(exe, ["-p", path])
                needed = [ln.split()[-1] for ln in so.splitlines()
                          if ln.strip().startswith("NEEDED")]
                rpath = []
                for ln in so.splitlines():
                    if "RPATH" in ln or "RUNPATH" in ln:
                        rpath.append(ln.split(None, 1)[-1].strip())
                if needed:
                    lines.append(f"  NEEDED：{' '.join(needed)}")
                if rpath:
                    lines.append(f"  RUNPATH/RPATH：{' '.join(rpath)}")
                contract_parts.append(_contract(
                    authority="observed", status="complete",
                    evidence={"tool": "objdump -p", "needed": needed, "runpath": rpath},
                    limitations=["仅读动态段元数据，未解析依赖的符号版本"],
                ))
            except (subprocess.TimeoutExpired, Exception):  # noqa: BLE001 - RPATH 行形态多变
                pass

        merged = _contract(
            authority="observed" if contract_parts else "derived",
            status="complete" if contract_parts else "partial",
            degraded=not contract_parts,
            reason=None if contract_parts else "无可用 ELF 通道（objdump 缺失）",
            limitations=sum((c["limitations"] for c in contract_parts), [])[:3],
            evidence={"parts": [c["evidence"] for c in contract_parts],
                      "elfClass": info["class"], "elfMachine": info["machine"],
                      "elfType": info["type"]},
        )
        return "\n".join(lines), merged

    def _lane_pe(self, path: str) -> tuple[str, dict]:
        size = os.path.getsize(path)
        parts: list[str] = [f"[rea_probe] lane=pe  {os.path.basename(path)}  {size:,} B"]
        contract_parts: list[dict] = []
        if size <= _PE_RESOURCE_LIMIT:
            j = _call("inspect-pe-resources", path)
            if "_error" in j:
                parts.append(f"  资源：不可用（{j['_error']}）")
            else:
                nr = j.get("normalized_result") or {}
                res = nr.get("resources") or nr.get("entries") or []
                parts.append(f"  资源：{len(res)} 项（REA {j.get('operation')}）")
                contract_parts.append(_contract(
                    authority="observed", status="complete",
                    limitations=(j.get("limitations") or [])[:1],
                    evidence={"tool": "rea.inspect-pe-resources", "evidenceId": j.get("evidence_id")},
                ))
        else:
            parts.append(f"  资源：跳过（{size:,} B > REA 64 MiB 上限）")

        j2 = _call("inspect-with-objdump", path, "file_headers")
        if "_error" in j2:
            parts.append(f"  objdump：不可用（{j2['_error']}）")
        else:
            nr2 = j2.get("normalized_result") or {}
            so = (nr2.get("stdout") or "")
            fmt = next((ln.strip() for ln in so.splitlines() if "file format" in ln), "未声明格式")
            parts.append(f"  objdump：{fmt}（{len(so):,} B 原始文本）")
            contract_parts.append(_contract(
                authority="observed", status="complete",
                limitations=["objdump 通道返回原始文本而非结构化指令，需自行解析"],
                evidence={"tool": "rea.inspect-with-objdump", "evidenceId": j2.get("evidence_id")},
            ))
        merged = _contract(
            authority="observed" if contract_parts else "unknown",
            status="complete" if contract_parts else "partial",
            degraded=not contract_parts,
            reason=None if contract_parts else "无可用 PE 通道（尺寸超限或工具缺失）",
            limitations=sum((c["limitations"] for c in contract_parts), [])[:3],
            evidence={"parts": [c["evidence"] for c in contract_parts]},
        )
        return "\n".join(parts), merged

    # ── 入口 ──────────────────────────────────────────────

    async def run(self, params: dict) -> ToolOutput:
        path = str(params.get("path") or params.get("file") or "")
        lane = str(params.get("lane") or "auto").lower()
        selector = str(params.get("selector") or params.get("procedure") or params.get("address") or "")
        try:
            max_funcs = int(params.get("max_funcs") or params.get("limit") or 0)
        except (TypeError, ValueError):
            max_funcs = 0
        name_filter = str(params.get("name_filter") or params.get("filter") or "")
        unpack = str(params.get("unpack") or "auto").lower()
        # 与 lane 同一条纪律：拼错的开关必须报错，不能静默当成默认值
        if unpack not in ("auto", "off"):
            return ToolOutput(
                text=f"[rea_probe] 未知 unpack={unpack!r}；合法值：auto|off",
                ok=False,
            )
        # 必须绝对化：_run_rea 会把子进程 cwd 切到 rea-agents 目录，相对路径在那里
        # 失效；而 REA 对「文件不存在」不报错，只返回空的 normalized_result，
        # 于是会被误读成「目标是数据 / 未识别代码」。实测：相对路径 2.2s 空返回，
        # 同一地址绝对路径 30.3s 正常反编译。
        if path:
            path = os.path.abspath(path)
        if not path or not os.path.isfile(path):
            return ToolOutput(
                text=f"[rea_probe] 目标不存在：{path or '(空)'}（not_applicable）",
                ok=False,
            )
        return await asyncio.to_thread(
            self._run_sync, path, lane, selector, max_funcs, name_filter, unpack)

    def _lane_decompile(self, path: str, selector: str) -> tuple[str, dict]:
        """定点反编译。selector 可为函数名或地址（VA/RVA）。

        PE 路径：地址统一换算成「VA → RVA → 节表 → 文件偏移」再走
        `--file-offset`（偏移是唯一不依赖 REA 内部映射策略的确定量，
        只认 `0x` 十六进制，传十进制 `1024` 直接 rc=1）；函数名直传 `--procedure`。

        ELF 路径（2026-10-21）：REA 的 decompile provider **拒收 ELF**，
        实测只回空 pseudo-code（契约还报 unknown，静默失败）。所以 ELF 不调
        REA，改走自建 analyzeHeadless（_lane_decompile_batch）：名字选择器当
        name_filter，地址选择器归一成裸 hex 匹配 Ghidra 的 FUN_<hex> 命名。
        """
        sel = (selector or "").strip()
        if not sel:
            return ("[rea_probe] decompile 需要 selector（函数名或地址）；"
                    "先用 lane=pe 看结构，或用 objdump 通道拿函数表",
                    _contract(authority="unknown", status="not_applicable",
                              limitations=["未指定 selector，未执行反编译"]))
        try:
            with open(path, "rb") as f:
                head = f.read(_SNIFF_MAX)
        except OSError as exc:
            return f"[rea_probe] 读取失败：{exc}", _contract(
                authority="unknown", status="fail", limitations=[str(exc)])

        if _is_elf(head):
            # ELF：REA 自带的 decompile provider **拒收 ELF**（实测返回空 pseudo-code，
            # 契约报 unknown —— 静默失败）。改走自建 analyzeHeadless 批量通道：
            #   · 名字选择器 → 直接当 name_filter（支持逗号/空格多词 OR）；
            #   · 地址选择器 → 归一成裸 hex 匹配 Ghidra 的 FUN_<hex> 自动命名
            #     （带符号时函数有真名，地址过滤会零命中，输出会明说，
            #      让调用方回退 lane=elf 拿真名或 lane=decompile_batch 全量）。
            # 为什么不按 PE 口径把地址换算成文件偏移：Ghidra 对 ELF 的分析地址
            # 就等于 ELF VA，换算反而落到任意字节上。
            is_addr = bool(re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", sel))
            flt = sel
            note = "ELF：按函数名走自建 analyzeHeadless（REA decompile 拒收 ELF）"
            if is_addr:
                bare = sel.lower().removeprefix("0x").lstrip("0") or "0"
                flt = bare
                note = (f"ELF：地址 {sel} → 裸 hex {bare} 匹配 Ghidra FUN_ 命名"
                        f"（带符号二进制零命中时请改用 lane=elf 给出的真名）")
            text, contract = self._lane_decompile_batch(path, 10, flt)
            # 地址选择器在**带符号**二进制上会零命中（函数有真名，没有 FUN_ 名）。
            # 回退：用 objdump 符号表把地址反查成真名再按名过滤 —— 常见 CTF 场景
            # （elf lane 输出里地址和真名都给了，agent 很可能直接抄地址）。
            if is_addr and "导出 0 个函数" in text:
                real = self._elf_name_for_addr(path, sel)
                if real:
                    text2, contract2 = self._lane_decompile_batch(path, 10, real)
                    if "导出 0 个函数" not in text2:
                        note = (f"ELF：地址 {sel} 反查符号表得 {real}，按名过滤")
                        text, contract = text2, contract2
            head = (f"[rea_probe] lane=decompile(ELF→batch)  selector={sel}\n"
                    f"  {note}\n") + text
            return head, contract
        image_base, secs = _pe_sections(head)
        resolved, note = sel, ""
        is_addr = False
        if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", sel):
            # 歧义必须处理：Ghidra/objdump 打印地址习惯是「无 0x 前缀的十六进制」
            # （如 140001000），而用户和 agent 也可能真给十进制。按十进制硬解会把
            # 140001000 算成 1.4 亿，落到映像外，然后误报「不在任何节内」。
            # 所以两种解释都试，以「能否映射到已加载节」为准，并标注用了哪种。
            if sel.lower().startswith("0x"):
                candidates = [(int(sel, 16), "hex")]
            else:
                candidates = [(int(sel, 10), "dec"), (int(sel, 16), "hex")]
            found = None
            for v, base in candidates:
                if image_base and v >= image_base:
                    rva = v - image_base
                    conv = f"VA {v:#x} − base {image_base:#x} → RVA {rva:#x}（按 {base} 解析）"
                else:
                    rva = v
                    conv = f"按 RVA {rva:#x} 解释（{base} 解析）"
                off_try = _rva2off(rva, secs) if secs else None
                if off_try is not None:
                    found = (v, base, rva, off_try, conv)
                    break
            if found is None:
                tried = "、".join(f"{b}={v:#x}" for v, b in candidates)
                return (f"[rea_probe] 地址 {sel} 不在任何已加载节内"
                        f"（image_base={image_base:#x}，节 {len(secs)} 个；"
                        f"已试 {tried}）—— 先核对映射，别猜偏移",
                        _contract(authority="unknown", status="not_applicable",
                                  limitations=["地址无法映射到文件偏移"]))
            _, base_used, _rva, off, note = found
            resolved = f"0x{off:X}"
            is_addr = True
            note += f"；Δ文件偏移 0x{off:X}"
            if base_used == "hex" and not sel.lower().startswith("0x"):
                note += "；⚠ 无 0x 前缀且十进制不可映射，故按十六进制处理"

        # 取参语义必须对齐 REA 的文档：`--procedure` 是「函数名或分析地址」，
        # `--file-offset` 才是「源文件字节偏移」。以前把偏移塞给 --procedure，
        # 在 .text（rva 0x1000 / rawoff 0x400）这种错位节上只是靠 Ghidra 的
        # RVA 容错碰巧命中，换一个节就静默失败。另外 --file-offset 只认 0x 十六进制
        # （实测传 1024 直接 rc=1）。
        if is_addr:
            j = _call("decompile", path, "--file-offset", resolved)
        else:
            j = _call("decompile", path, "--procedure", resolved)

        return _render_decompile(j, sel, note, lane="decompile")

    # ── 批量反编译：一次 JVM 生命周期导出全部函数 ──────────────

    def _lane_decompile_batch(self, path: str, max_funcs: int, name_filter: str) -> tuple[str, dict]:
        """批量反编译。为什么要有这条通道：

        REA 的 `decompile --procedure` 每次调用都是一个完整的 Ghidra 进程 ——
        冷启动 + 项目创建 + 全量自动分析，实测 40s/次。想反编译 100 个函数
        就是 100×40s ≈ 67 分钟，赛场上完全不可用。而 `analyzeHeadless` 把
        「启动+分析」和「反编译」解耦：分析只做一次，之后每函数约 15ms
        （实测 274 函数 4.2s，摊薄约 290 倍）。

        代价：这是**全量**导出，不做选择。所以用 max_funcs 与 name_filter
        把输出规模压到可读范围，而不是拿 400KB 的 C 文件去喂 LLM。
        """
        if not os.path.isfile(_GHIDRA_HEADLESS):
            return (f"[rea_probe] analyzeHeadless 不存在：{_GHIDRA_HEADLESS}"
                    f"（设 REA_GHIDRA_DIR 指向 Ghidra 根目录）",
                    _contract(authority="unknown", status="not_applicable",
                              limitations=["Ghidra headless 入口缺失，未执行"]))
        script = os.path.join(_GHIDRA_SCRIPTS, "ExportAllDecompiled.java")
        if not os.path.isfile(script):
            return (f"[rea_probe] Ghidra 脚本不存在：{script}",
                    _contract(authority="unknown", status="not_applicable",
                              limitations=["批量导出脚本缺失，未执行"]))

        work = tempfile.mkdtemp(prefix="rea_batch_")
        t_wall = time.time()
        proj_dir = os.path.join(work, "proj")
        out_c = os.path.join(work, "decompiled.c")
        os.makedirs(proj_dir, exist_ok=True)
        # 项目名不能带空格/中文，固定一个短名即可（目录已是唯一的）
        proj_name = "reaBatch"
        flt = (name_filter or "").strip() or "*"
        # 逗号/分号/竖线一律换成空格（2026-10-21）：analyzeHeadless.bat 的参数
        # 循环把 `,` `;` 当**批处理参数分隔符**，`a,b,c` 到 Java 侧只剩 `a`
        # （实测：四词过滤只导出 1 个函数，其余三个词静默丢失，且 EXPORT_DONE
        # 照报成功——不比对候选数根本发现不了）。换成空格后 list2cmdline 会给
        # 整个参数加引号，cmd/batch/JVM 三层都当同一个参数，Java 侧 split
        # 正则 `[,\s;|]+` 原本就兼容空白分隔。单词过滤不受影响（无空格不加引号，
        # 与历史行为一致）。
        flt = re.sub(r"[,;|]+", " ", flt).strip() or "*"

        args = [
            _GHIDRA_HEADLESS, proj_dir, proj_name,
            "-import", path,
            "-scriptPath", _GHIDRA_SCRIPTS,
            "-postScript", "ExportAllDecompiled.java",
            out_c, str(max(0, int(max_funcs or 0))), flt,
            "-analysisTimeoutPerFile", str(_BATCH_ANALYSIS_TIMEOUT),
            "-deleteProject",
        ]
        # cmd /c 的引号规则（cmd /? 第 2 条）：若命令串首字符是引号，cmd 会剥掉
        # 首尾各一个引号。带空格的路径被 list2cmdline 引起来后，正好由 Python 在
        # shell=True 时补的外层引号抵消 —— CPython 的 _execute_child 会拼成
        # `cmd.exe /c "{}"`，所以这里**不能**自己再包一层，否则多出一对引号。
        # 少了这层对称关系就是 `The syntax of the command is incorrect`（rc=255，实测）。
        if '"' in path or '"' in out_c:
            shutil.rmtree(work, ignore_errors=True)
            return ("[rea_probe] 路径含英文双引号，无法安全传给 cmd；请改名后重试",
                    _contract(authority="unknown", status="not_applicable",
                              limitations=["路径含 \" 字符，命令行无法安全转义"]))
        cmdline = subprocess.list2cmdline(args)
        try:
            p = subprocess.run(
                cmdline, shell=True,
                capture_output=True,
                timeout=_BATCH_TIMEOUT,
                encoding="utf-8",
                errors="replace",
                env=_rea_env(),
            )
            rc, out, err = p.returncode, p.stdout or "", p.stderr or ""
        except subprocess.TimeoutExpired:
            shutil.rmtree(work, ignore_errors=True)
            return (f"[rea_probe] 批量反编译超时（>{_BATCH_TIMEOUT}s）。"
                    f"大样本先降 REA_BATCH_ANALYSIS_TIMEOUT，或改用 lane=decompile 定点取单个函数",
                    _contract(authority="unknown", status="timeout",
                              limitations=[f"analyzeHeadless 超过 {_BATCH_TIMEOUT}s 未返回，输出不可信"]))
        except Exception as exc:  # noqa: BLE001
            shutil.rmtree(work, ignore_errors=True)
            return (f"[rea_probe] 批量反编译启动失败：{type(exc).__name__}: {exc}",
                    _contract(authority="unknown", status="fail", limitations=[str(exc)]))

        # EXPORT_DONE 是脚本自己打的收尾行；它缺失说明脚本没跑到最后，
        # 此时即便 rc==0 也不能当作成功（Ghidra 对脚本异常经常返回 0）。
        done = re.search(
            r"EXPORT_DONE out=.*? emitted=(\d+) failed=(\d+) skipped=(\d+) "
            r"candidates=(\d+) elapsed_ms=(\d+)", out)
        if not done:
            tail = (out or err)[-600:].replace("\n", " ⏎ ")
            shutil.rmtree(work, ignore_errors=True)
            return (f"[rea_probe] 批量反编译未完成（rc={rc}，未见 EXPORT_DONE）。尾部输出：{tail}",
                    _contract(authority="unknown", status="fail",
                              limitations=["Ghidra 脚本未跑到收尾，结果不可用", f"rc={rc}"]))

        emitted, failed, skipped, cands, ms = (int(x) for x in done.groups())
        wall_ms = int((time.time() - t_wall) * 1000)
        if not os.path.isfile(out_c):
            shutil.rmtree(work, ignore_errors=True)
            return ("[rea_probe] 脚本报告成功但输出文件不存在",
                    _contract(authority="unknown", status="fail",
                              limitations=["期望的输出文件缺失"]))

        size = os.path.getsize(out_c)
        try:
            with open(out_c, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as exc:
            shutil.rmtree(work, ignore_errors=True)
            return f"[rea_probe] 读取输出失败：{exc}", _contract(
                authority="unknown", status="fail", limitations=[str(exc)])

        # 从输出里抽函数清单（不把 400KB 正文塞进上下文）
        funcs = re.findall(r"^// ==== FUNC (\S+) (\S+) size=(\d+)", text, re.M)
        failed_funcs = re.findall(r"^// ==== FUNC (\S+) (\S+) FAILED", text, re.M)
        per_func_ms = (ms / emitted) if emitted else 0.0

        head = [
            f"[rea_probe] lane=decompile_batch  {os.path.basename(path)}",
            f"  导出 {emitted} 个函数（候选 {cands}，跳过 thunk/外部 {skipped}，反编译失败 {failed}）",
            f"  耗时：墙钟 {wall_ms/1000:.1f}s = 固定成本（建项目+自动分析）"
            f" {(wall_ms-ms)/1000:.1f}s + 反编译 {ms/1000:.1f}s",
            f"  边际 {per_func_ms:.0f} ms/函数；对照 lane=decompile 的 ~40s/次（含重复分析）",
            f"  输出文件：{out_c}（{size:,} 字节）",
        ]
        # 盈亏平衡：lane=decompile 每次约 40s 且不可复用分析，批量虽慢一次但只慢一次。
        # 说清楚这点，agent 才不会在「只想要 1 个函数」时误选批量。
        if emitted:
            breakeven = (wall_ms / 40000.0)
            head.append(f"  等效：本次总耗时 ≈ lane=decompile 跑 {breakeven:.1f} 次的成本")
        if max_funcs:
            head.append(f"  上限 max_funcs={max_funcs}（可能被截断，不代表程序只有这些函数）")
        if name_filter:
            head.append(f"  名称过滤 name_filter={name_filter}"
                        f"（无符号二进制函数名多为 FUN_xxxx，按名过滤基本无效）")
        head.append("")
        # 只列前 40 个函数名，够 agent 决定下一步取哪个；其余按需 grep 文件
        show = funcs[:40]
        if show:
            head.append("  函数清单（前 %d）：" % len(show))
            for va, nm, sz in show:
                head.append(f"    {va}  {nm}  size={sz}")
        if len(funcs) > len(show):
            head.append(f"    … 其余 {len(funcs)-len(show)} 个在输出文件中")
        if failed_funcs:
            head.append("  反编译失败：" + ", ".join(f"{nm}@{va}" for va, nm in failed_funcs[:10]))
        if cands == 0:
            head.append("  ⚠ 零候选：这一条不是『程序没有函数』，而是过滤器把它们全滤掉了。"
                        "去掉 name_filter 重跑再下结论")

        # ── 把反编译出来的代码本身内联进上下文 ──────────────────────
        # 2026-10-20 由真题暴露：此前这条通道只回传「函数清单」（地址/名字/大小），
        # 4,271 字节的 C 代码躺在临时文件里，agent 上下文里一个字都没有 —— 于是
        # 「能看到 main size=112，却看不到 main 在干什么」。通道建好了货没送出来，
        # 比没有通道更危险（看起来成功）。所以这里把代码按块内联，并写明截了多少。
        inlined, istats = _inline_decompiled(out_c, funcs, _BATCH_INLINE_CHARS)
        if istats.get("error"):
            head.append(f"  ⚠ 代码内联失败：{istats['error']}（仅剩清单，结论不完整）")
        elif inlined:
            head.append("")
            head.append(f"  ── 反编译代码（{istats['chars']:,} / {istats['total']:,} 字符，"
                        f"{istats['funcs']} 个函数）──")
            head.append(inlined)
            if istats["omittedFuncs"]:
                head.append(f"  … 其余 {istats['omittedFuncs']} 个函数未内联"
                            f"（超 {_BATCH_INLINE_CHARS:,} 字符上限）；完整文件：{out_c}")

        limitations = [
            "全量导出：未做动态验证，反编译结果与运行时行为可能不一致",
            "Ghidra 自动分析有超时上限，超大样本可能漏识别函数（表现为函数数偏少）",
        ]
        if failed:
            limitations.append(f"{failed} 个函数反编译失败，已在输出中以 FAILED 标注")
        if max_funcs:
            limitations.append("受 max_funcs 限制，输出非全集")
        if name_filter:
            limitations.append(f"name_filter={name_filter} 生效，输出仅含匹配项")
            if cands == 0:
                limitations.append(
                    "过滤器零命中：本程序无符号名可匹配（自动分析产出 FUN_ 形命名），"
                    "『0 个函数』不代表程序无代码，本次结论无效")

        # 零命中必须降级为 not_applicable：报 complete 等于用「过滤器」冒充「覆盖」
        if cands == 0:
            status = "not_applicable"
        elif failed or max_funcs:
            status = "partial"
        else:
            status = "complete"

        contract = _contract(
            authority="unknown" if cands == 0 else "observed",
            status=status,
            truncated=bool(max_funcs) or failed > 0,
            degraded=cands == 0,
            reason="过滤器零命中，输出不含任何函数" if cands == 0 else None,
            limitations=limitations,
            evidence={
                "tool": "ghidra.analyzeHeadless+ExportAllDecompiled",
                "outFile": out_c,
                "emitted": emitted,
                "failed": failed,
                "decompileMs": ms,
                "wallMs": wall_ms,
                "ghidraDir": _DEFAULT_GHIDRA,
            },
        )
        return "\n".join(head), contract

    def _run_sync(self, path: str, lane: str, selector: str = "",
                  max_funcs: int = 0, name_filter: str = "",
                  unpack: str = "auto") -> ToolOutput:
        ok, why = _rea_available()
        if not ok:
            return ToolOutput(
                text=f"[rea_probe] REA 不可用：{why}（not_applicable，勿当作'分析干净'）",
                ok=False,
            )
        if lane == "auto":
            lane = _sniff_lane(path)
        # 未知 lane 必须报错，不能静默回退（2026-10-20 实测：传 lane=nonsense 时
        # 落到 else 分支照样跑 pe 通道，输出与 lane=pe 一字不差 —— 调用方会以为
        # 「通道选对了、结果可信」，而实际是它随手给了个不存在的通道）。
        if lane not in _KNOWN_LANES:
            return ToolOutput(
                text=f"[rea_probe] 未知 lane={lane!r}（不会静默回退到 pe）；"
                     f"合法值：{'|'.join(sorted(_KNOWN_LANES))}",
                ok=False,
            )
        if lane == "unknown":
            hint = "wasm 用 wasm_probe（WABT）、pcap 用 pcap_probe；"
            try:
                with open(path, "rb") as f:
                    if f.read(4) == b"\x00asm":
                        hint = "这是 wasm，请改用 wasm_probe 适配器（REA 不支持 wasm）"
            except OSError:
                pass
            return ToolOutput(
                text=f"[rea_probe] 无法识别 {os.path.basename(path)} 的格式；"
                     f"REA 的无引擎通道覆盖 PE/CLI/Go-PE/ELF（{hint}）",
                ok=False,
            )
        # 加壳判定放在分析**之前**：脱壳成功时 path 会被换成副本，之后再看节名
        # 就永远看不到壳了（副本已脱净）—— 于是「脱过壳」这件事会被静默丢掉。
        packer = _packer_hint_file(path)
        unpack_ev: dict | None = None
        if packer and unpack != "off":
            src_note = path
            unpacked, unpack_ev = _unpack_upx(path)
            if unpacked:
                path = unpacked
                logger.info("rea_probe: %s 已脱壳 → %s", src_note, unpacked)
        try:
            if lane == "managed":
                text, contract = self._lane_managed(path)
            elif lane == "go":
                text, contract = self._lane_go(path)
            elif lane == "elf":
                text, contract = self._lane_elf(path)
            elif lane == "decompile":
                text, contract = self._lane_decompile(path, selector)
            elif lane in ("decompile_batch", "batch_decompile", "decompile-all"):
                text, contract = self._lane_decompile_batch(path, max_funcs, name_filter)
            else:
                text, contract = self._lane_pe(path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("rea_probe 失败: %s", exc)
            return ToolOutput(text=f"[rea_probe] 内部错误：{type(exc).__name__}: {exc}", ok=False)

        # 加壳处理必须在出口统一交代：managed/go/pe/decompile 四个通道看到的是同一层
        # 解压存根，只在某个通道里判断会漏。实测 UPX 压 pip.exe：274 函数 → 3 函数，
        # 输出 402,891 B → 8,913 B，而 Ghidra 全程无任何提示。
        # 三种结局必须区分开，不能合并成一句「有壳」：
        #   A 已脱壳 → 结果针对脱壳副本（扩大覆盖），但仍要说明壳层未分析
        #   B 检测到壳但脱壳失败（非 UPX / upx 缺失 / 超时）→ 保持 degraded，写清原因
        #   C unpack=off → 保持原告警，明确是调用方自己关掉的
        if isinstance(contract, dict) and (unpack_ev or packer):
            contract = dict(contract)
            ev = dict(contract.get("evidence") or {})
            if unpack_ev:
                ev["unpack"] = unpack_ev
            contract["evidence"] = ev
            lims = list(contract.get("limitations") or [])
            if unpack_ev and unpack_ev.get("ok"):
                ev_note = (f"已用 upx 脱壳后分析（原文件未改动，副本 "
                           f"{os.path.basename(str(unpack_ev.get('unpacked')))}，"
                           f"{unpack_ev.get('sizeBefore')} B → {unpack_ev.get('sizeAfter')} B，"
                           f"{unpack_ev.get('ms')} ms）")
                text = (f"[rea_probe] {packer} 壳已脱（upx -d）：以下结果针对**脱壳后**的代码，"
                        f"不再是解压存根。仍未覆盖：壳本身的解压/反调试逻辑\n" + text)
                lims.append(f"分析对象是 upx -d 产出的副本：{packer} 解压存根与壳内反调试逻辑未分析；"
                            f"原文件字节未改动")
                contract["limitations"] = lims
            elif packer:
                why = ""
                if unpack_ev:
                    why = f"；脱壳尝试失败：{unpack_ev.get('reason', '')}"
                text = (f"[rea_probe] ⚠ 检测到 {packer} 加壳：以下结构化结果只覆盖解压存根。"
                        f"实测 UPX 样本函数数 274 → 3、输出 403 KB → 8.9 KB；"
                        f"『函数少/字符串少』不代表程序本身如此，需先脱壳"
                        f"（upx 只能脱 UPX；其它壳需专用脱壳器或动态 dump）{why}\n" + text)
                contract["degraded"] = True
                contract["degradationReason"] = (f"疑似 {packer} 加壳，分析仅覆盖解压存根"
                                                 + (f"（{unpack_ev.get('reason', '')[:120]}）"
                                                    if unpack_ev else "（unpack=off 由调用方关闭）"))
                lims.append(f"{packer} 加壳：函数/资源/字符串识别只含存根，不能当作完整覆盖")
                contract["limitations"] = lims
                cov = dict(contract.get("coverage") or {})
                if cov.get("status") == "complete":
                    cov["status"] = "partial"
                    cov["truncated"] = True
                    contract["coverage"] = cov

        body = text + self._rawscan_block(path, text)
        body += "\n  _contract: " + json.dumps(contract, ensure_ascii=False)
        ok_flag = not (isinstance(contract, dict) and contract.get("degraded"))
        return ToolOutput(text=body, raw=json.dumps(contract, ensure_ascii=False), ok=ok_flag)

    @staticmethod
    def _rawscan_block(path: str, structured_text: str) -> str:
        """把裸扫结果渲染成文本块；命中与结构化通道重叠时明确标注。"""
        try:
            hits, meta = _rawscan(path)
        except Exception as exc:  # noqa: BLE001
            return f"\n  裸扫：不可用（{type(exc).__name__}: {exc}）—— 召回未验证，勿当作无 flag"
        n = len(hits)
        if not n:
            extra = "，读取被截断，尾部未扫" if meta.get("truncated") else ""
            return (
                f"\n  裸扫：{meta['scanned']:,} B × 4 路编码 0 命中{extra}"
                f"（含义是『没找到明文 flag』，不是『没有 flag』）"
            )
        dup = sum(1 for h in hits if h["value"] in structured_text)
        head = f"\n  裸扫：{n} 条命中（结构化通道已覆盖 {dup}，裸扫新增 {n - dup}）"
        if meta.get("truncated"):
            head += f"；仅扫前 {meta['scanned']:,} B（共 {meta['size']:,} B）"
        stars = sum(1 for h in hits if h.get("plausibility") == "★")
        if stars != n:
            head += f"；其中 {stars} 条判为高置信（★），其余见方括号"
        lines = [head]
        for h in hits[:8]:
            seen = "已含" if h["value"] in structured_text else "新"
            lines.append(
                f"    [{h.get('plausibility', '?')}] {h['value'][:52]:<54} "
                f"{h['encoding']:<9} @0x{h['offset']:<8X} ← {h['region']} {seen}"
            )
        return "\n".join(lines)


def main() -> int:
    """手工验证入口：python -m tools.adapters.rea_probe <path> [lane] [selector]"""
    if len(sys.argv) < 2:
        print("用法: python -m tools.adapters.rea_probe <path> [auto|managed|go|pe|decompile] [selector]")
        return 2
    path = sys.argv[1]
    lane = sys.argv[2] if len(sys.argv) > 2 else "auto"
    selector = sys.argv[3] if len(sys.argv) > 3 else ""
    out = asyncio.run(ReaProbeAdapter().run({"path": path, "lane": lane, "selector": selector}))
    print(out.text)
    print(f"\nok={out.ok}")
    return 0 if out.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
