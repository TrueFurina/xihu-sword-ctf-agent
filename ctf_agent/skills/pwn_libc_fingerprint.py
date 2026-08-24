"""pwn_libc_fingerprint skill：libc 指纹库（决赛建议 2.2——无 gdb 补 pwn 深度）。

场景：pwn 题泄露了 libc 地址（格式化字符串/unsorted bin），需要：
1. 解析附件 libc.so.6 → 关键符号偏移表（__libc_start_main_ret/system/free/puts/
   read/malloc/__free_hook/__malloc_hook/one_gadget）
2. libc 版本识别（.comment 段 / build-id）
3. 泄露地址 → libc base 计算（base = leaked_addr - symbol_offset）

依赖：pyelftools（解析 ELF 动态符号）。
用法：params = {'libc_path': ..., 'leaked_addr': ..., 'leaked_symbol': ...}
"""

import os
import re


def _parse_libc(path: str) -> dict:
    """解析 libc.so.6：动态符号偏移表 + 版本信息。"""
    import io

    from elftools.elf.elffile import ELFFile

    data = open(path, "rb").read()
    f = io.BytesIO(data)
    e = ELFFile(f)

    # 关键符号（利用链常用）
    key_syms = {
        "__libc_start_main", "__libc_start_main_ret", "system", "free", "puts",
        "printf", "read", "write", "malloc", "realloc", "calloc", "str_bin_sh",
        "/bin/sh", "__free_hook", "__malloc_hook", "__realloc_hook", "one_gadget",
        "environ", "setcontext", "execve",
    }
    syms = {}
    dynsym = e.get_section_by_name(".dynsym")
    if dynsym is not None:
        for sym in dynsym.iter_symbols():
            name = sym.name
            if name in key_syms and sym["st_value"]:
                syms[name] = sym["st_value"]
            elif name.startswith("__libc_start_main") and sym["st_value"]:
                syms.setdefault(name, sym["st_value"])
            elif name == "str_bin_sh" and sym["st_value"]:
                syms["str_bin_sh"] = sym["st_value"]

    # 版本识别：.comment 段（GCC 版本 → libc 近似）或 build-id
    version = "unknown"
    comment = e.get_section_by_name(".comment")
    if comment is not None:
        v = comment.data().decode("utf-8", errors="replace")
        ver_m = re.search(r"GCC: \(GNU\) ([\d.]+)", v)
        if ver_m:
            version = f"GCC {ver_m.group(1)}"
    # .note.gnu.build-id → hash
    build_id = ""
    note = e.get_section_by_name(".note.gnu.build-id")
    if note is not None:
        nd = note.data()
        m = re.search(rb"[\x00-\xff]{4}\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU(.{20})", nd)
        if m:
            build_id = m.group(1).hex()

    return {"symbols": syms, "version": version, "build_id": build_id,
            "elf_class": e.elfclass}


def pwn_libc_fingerprint(params: dict) -> dict:
    """skill 入口：解析 libc 指纹 + 计算 base。"""
    path = params.get("libc_path", "")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": "libc_path 不存在"}
    try:
        info = _parse_libc(path)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"解析失败: {type(exc).__name__} {exc}"}

    syms = info["symbols"]
    result = {
        "ok": True,
        "libc_version": info["version"],
        "build_id": info["build_id"],
        "symbol_offsets": syms,
    }

    # 泄露地址 → base 计算
    leaked = params.get("leaked_addr")
    leaked_sym = params.get("leaked_symbol", "")
    if leaked and leaked_sym in syms:
        base = int(leaked) - syms[leaked_sym]
        result["libc_base"] = base
        result["base_note"] = f"base = leaked({leaked:#x}) - {leaked_sym}({syms[leaked_sym]:#x}) = {base:#x}"
        # 常用利用地址
        for name in ("system", "__free_hook", "__malloc_hook", "one_gadget"):
            if name in syms:
                result.setdefault("attack_addrs", {})[name] = base + syms[name]
    elif leaked:
        result["note"] = f"泄露地址 {leaked:#x} 但未指定泄露符号（leaked_symbol）——需先识别泄露的是哪个符号"

    return result


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="pwn libc 指纹库")
    parser.add_argument("--libc", required=True, help="libc.so.6 路径")
    parser.add_argument("--leaked", default="", help="泄露地址（hex）")
    parser.add_argument("--symbol", default="", help="泄露符号名")
    args = parser.parse_args()
    import json

    print(json.dumps(pwn_libc_fingerprint({
        "libc_path": args.libc,
        "leaked_addr": int(args.leaked, 16) if args.leaked else None,
        "leaked_symbol": args.symbol or "",
    }), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
