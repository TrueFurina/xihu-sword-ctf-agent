"""pwn_nogdb_flow skill：无 gdb 盲打备用路线（Windows 无 WSL/gdb 环境）。

背景：Win11 25H2 Insider 服务栈缺陷 → 无 WSL/Linux 发行版 → gdb 装不了。
测试赛 easy_uaf / shopping 均无 gdb 盲打解出——本 skill 沉淀该方法论。

流程（静态逆向 → 判据验证 → 盲打）：
1. ELF 静态分析：pwntools ELF + pyelftools + capstone
   - checksec（PIE/RELRO/Canary/NX）→ 决定利用类型
   - 反汇编菜单函数 → 定位漏洞原语（free 后未清指针/栈溢出/格式化）
   - got/plt 符号表 → system/read/puts 可用性
2. 交互行为确认（read 裸字节 vs fgets 行读——shopping 教训）
3. 判据测试（无 gdb 的动态验证手段）：
   - 覆盖为非法地址 → 若崩溃则覆盖生效（free_hook 判据）
   - 响应时间差（sleep 命令）→ 命令执行确认
4. 盲打利用链：设计 → 远程执行 → 观察响应/崩溃 → 迭代
"""

import os


def static_analysis(binary: str) -> dict:
    """阶段 1：ELF 静态分析（无 gdb 的核心手段）。"""
    from pwn import ELF
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from elftools.elf.elffile import ELFFile
    import io

    elf = ELF(binary)
    cs = elf.checksec()
    result = {
        "arch": cs.arch if hasattr(cs, "arch") else "amd64",
        "nx": getattr(cs, "nx", None),
        "pie": getattr(cs, "pie", None),
        "relro": getattr(cs, "relro", None),
        "canary": getattr(cs, "canary", None),
        "symbols": {s: hex(a) for s, a in elf.symbols.items()
                    if s in ("system", "printf", "puts", "read", "gets", "malloc", "free") and a},
        "plt": {s: hex(a) for s, a in elf.plt.items()
                if s in ("system", "printf", "puts", "read", "gets")},
        "got": {s: hex(a) for s, a in elf.got.items()
                if s in ("printf", "puts", "read", "system", "free", "malloc")},
    }
    # 反汇编 .text 概览（函数边界 via capstone）
    data = open(binary, "rb").read()
    f = io.BytesIO(data)
    e = ELFFile(f)
    sec = e.get_section_by_name(".text")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    if sec:
        insns = list(md.disasm(sec.data(), sec["sh_addr"]))
        result["text_instructions"] = len(insns)
        # 统计 call 目标（定位关键函数调用）
        calls = {}
        for insn in insns:
            if insn.mnemonic == "call":
                tgt = insn.op_str.strip()
                calls[tgt] = calls.get(tgt, 0) + 1
        result["call_stats"] = {k: v for k, v in sorted(calls.items(), key=lambda x: -x[1])[:10]}
    return result


def interaction_notes() -> list:
    """交互行为要点（shopping 10 版试错的教训）。"""
    return [
        "read(0, buf, n)：裸字节流，用 send()（\x00 保留）——交互输入不自动加换行",
        "fgets(buf, n, stdin)：行读，用 sendline()（自动 \n），\x00 后截断（strlen 类）",
        "scanf %d：数字输入，sendline 后注意残留换行",
        "确认输入类型后再设计 payload——用错 send/sendline 是 pwn 盲打最常见失败点",
    ]


def verdict_test_strategies() -> list:
    """判据测试（无 gdb 时的动态验证手段，shopping free_hook 判据沉淀）。"""
    return [
        "覆盖判据：把目标地址（free_hook 等）覆盖为 0x4141414141414141 → 触发 free/malloc → "
        "若崩溃（Segmentation）则覆盖生效；若正常返回则覆盖未命中（shopping 实测有效）",
        "命令执行判据：payload 内嵌 sleep N → 响应延迟 ≈N 秒则命令执行（注意 Runtime.exec 异步不等待）",
        "泄露判据：格式化字符串/unsorted bin 泄露地址 → 数值在 libc 范围（0x7f..）则泄露成功",
        "交互差异判据：同 payload 分别 send/sendline 测试 → 响应不同说明输入类型判断错误",
    ]


def build_plan(binary: str, host: str = "", port: int = 0) -> dict:
    """组装完整盲打计划。"""
    analysis = static_analysis(binary) if binary and os.path.exists(binary) else {}
    return {
        "ok": True,
        "phase1_static": analysis,
        "phase2_interaction": interaction_notes(),
        "phase3_verdict": verdict_test_strategies(),
        "phase4_blind_attack": [
            "1. 根据 checksec 决定利用类型：非 PIE+system→直接覆盖；PIE→先泄露；全保护堆→tcache/fastbin",
            "2. 设计链 → 远程执行 → 观察响应/崩溃 → 记录结果",
            "3. 失败时用判据测试定位（覆盖未命中/交互类型错/偏移错），每次只改一个变量",
            "4. 盲打迭代上限：同思路 3 次无进展 → 换利用路径（shopping 10 版教训：换触发点而非死磕）",
        ],
        "target": f"{host}:{port}" if host else "（未提供靶机，仅静态分析）",
    }


def pwn_nogdb_flow(params: dict) -> dict:
    """skill 入口。"""
    return build_plan(
        params.get("binary", ""),
        host=params.get("host", ""),
        port=int(params.get("port", 0) or 0),
    )


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return pwn_nogdb_flow(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="pwn 无 gdb 盲打流程")
    parser.add_argument("--binary", required=True, help="ELF 路径")
    args = parser.parse_args()
    import json

    print(json.dumps(pwn_nogdb_flow({"binary": args.binary}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
