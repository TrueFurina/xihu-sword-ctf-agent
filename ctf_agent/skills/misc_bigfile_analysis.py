"""misc_bigfile_analysis skill：超大文件/嵌套压缩包/Linux 内存镜像快速分析。

真题（西湖论剑 2026-08-21 正式赛 MISC-01 / 10734 "flag^galf"）结构链（实测）：
    外层附件.zip → tempdir/MISC附件/ubuntu flag.zip（449,750,135 B）
                  → ubuntu flag.lime（449,749,969 B，Linux 内存镜像）
题名 flag^galf 暗示 XOR（b'flag' ^ b'galf' = 01 0d 0d 01，4 字节循环异或）

核心铁律：449MB 级别文件绝不整读入内存——一律流式/分块（1MB chunk）。
lime 是 LiME 内存取证镜像（魔数 b'EMLF'），flag 可能明文在内存字符串里，
也可能被 XOR 混淆后藏在镜像中。

kind：
- zip_list:         列 zip 顶层条目（只读中央目录，秒级）
- nested_tail:      流式读嵌套 zip 条目尾部 → 定位内层 EOCD + 中央目录 → 列内层条目
                    （免全量解压；实测 449MB 外层只读尾部 4MB 即出内层单条目）
- extract_entry:    分块流式解压指定条目到磁盘（大文件安全，可再 zipfile 打开）
- flag_scan:        分块扫描文件中的 flag 模式/可疑字符串（含跨块匹配）
- lime_probe:       检测 lime 魔数 + 头部系统信息字符串
- strings_window:   指定窗口提取可打印字符串（>=min_len），辅助判读镜像内容
- xor_title_search: 按题名 XOR 线索（可传 key）全文件扫描异或后的 flag 模式
- xor_key_discovery:在受限窗口爆破单字节 XOR key（找到可能 key 后配合 flag_scan 全扫）

沙盒约束：仅 import os/zipfile/struct/re（禁危险子进程/文件树操作类模块）。
"""

import os
import struct
import re

_CHUNK = 1 << 20  # 1MB 分块


def zip_list(params: dict) -> dict:
    """列 zip 顶层条目（只读中央目录，适合秒级预览大 zip）。"""
    path = params.get("path")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": f"文件不存在: {path}"}
    try:
        import zipfile
        zf = zipfile.ZipFile(path)
    except Exception as exc:
        return {"ok": False, "error": f"打开失败（可能不是 zip 或已损坏）: {exc}"}
    infos = zf.infolist()
    entries = []
    for i in infos:
        entries.append({
            "name": i.filename,
            "size": i.file_size,
            "compressed": i.compress_size,
            "compress_type": i.compress_type,
            "is_dir": i.is_dir(),
        })
    total = sum(e["size"] for e in entries)
    return {
        "ok": True,
        "path": path,
        "entry_count": len(entries),
        "total_uncompressed": total,
        "entries": entries[: int(params.get("limit", 50))],
        "truncated": len(entries) > int(params.get("limit", 50)),
    }


def _read_tail(stream, tail_bytes: int) -> (bytearray, int):
    """流式读 stream，仅保留尾部 tail_bytes 字节。返回 (tail, 流总长)。"""
    tail = bytearray()
    total = 0
    while True:
        b = stream.read(_CHUNK)
        if not b:
            break
        total += len(b)
        tail.extend(b)
        if len(tail) > tail_bytes:
            del tail[: len(tail) - tail_bytes]
    return tail, total


def _parse_cd_entries(cd: bytes) -> list:
    """解析 zip 中央目录（PK\\x01\\x02 序列）→ 条目清单。"""
    entries = []
    i = 0
    while i + 46 <= len(cd):
        if cd[i:i + 4] != b"PK\x01\x02":
            i += 1
            continue
        comp_size = struct.unpack_from("<I", cd, i + 20)[0]
        uncomp_size = struct.unpack_from("<I", cd, i + 24)[0]
        name_len = struct.unpack_from("<H", cd, i + 28)[0]
        extra_len = struct.unpack_from("<H", cd, i + 30)[0]
        comment_len = struct.unpack_from("<H", cd, i + 32)[0]
        name = cd[i + 46:i + 46 + name_len].decode("utf-8", errors="replace")
        entries.append({"name": name, "compressed": comp_size, "size": uncomp_size})
        i += 46 + name_len + extra_len + comment_len
    return entries


def nested_tail(params: dict) -> dict:
    """流式读嵌套 zip 条目尾部 → 定位内层 EOCD → 解析内层中央目录。

    适用：外层 zip 中只有一个大 zip 条目（如 10734），免全量解压即可
    看到内层条目结构。若内层 CD 大于 tail_bytes，自动提示改用 extract_entry。
    """
    path = params.get("path")
    entry = params.get("entry")  # 外层 zip 中的嵌套 zip 条目名；None=第一个条目
    tail_bytes = int(params.get("tail_bytes", 8 << 20))
    if not path or not os.path.exists(path):
        return {"ok": False, "error": f"文件不存在: {path}"}
    import zipfile
    try:
        zf = zipfile.ZipFile(path)
    except Exception as exc:
        return {"ok": False, "error": f"打开失败: {exc}"}
    infos = zf.infolist()
    if entry is None:
        target = infos[0] if infos else None
    else:
        target = next((i for i in infos if i.filename == entry), None)
    if target is None:
        return {"ok": False, "error": f"条目不存在: {entry}", "entries": [i.filename for i in infos][:20]}
    try:
        src = zf.open(target)
    except Exception as exc:
        return {"ok": False, "error": f"无法读取条目（加密?）: {exc}"}
    tail, total = _read_tail(src, tail_bytes)
    idx = tail.rfind(b"PK\x05\x06")
    if idx < 0:
        return {"ok": False, "error": "尾部未找到内层 EOCD（内层 zip 加密/损坏？）"}
    eocd = tail[idx:idx + 22]
    total_entries = struct.unpack_from("<H", eocd, 10)[0]
    cd_size = struct.unpack_from("<I", eocd, 12)[0]
    cd_off = struct.unpack_from("<I", eocd, 16)[0]
    # 中央目录紧邻 EOCD 之前（标准布局）；tail 中位置 = idx - cd_size
    cd_start = idx - cd_size
    if cd_start < 0 or cd_start + cd_size > len(tail):
        return {"ok": False, "error": f"中央目录({cd_size}B)超出尾部缓冲({tail_bytes}B)，请增大 tail_bytes 或先 extract_entry",
                "hint": {"total_entries": total_entries, "cd_size": cd_size, "cd_off": cd_off}}
    cd = bytes(tail[cd_start:cd_start + cd_size])
    entries = _parse_cd_entries(cd)
    return {
        "ok": True,
        "inner_entry": target.filename,
        "inner_size": target.file_size,
        "stream_total": total,
        "inner_total_entries": total_entries,
        "inner_entries": entries[: int(params.get("limit", 50))],
        "truncated": len(entries) > int(params.get("limit", 50)),
        "hint": "如需解出内层大文件用 extract_entry；内层若是 .lime 内存镜像用 lime_probe/flag_scan",
    }


def extract_entry(params: dict) -> dict:
    """分块流式解压 zip 指定条目到磁盘（大文件安全，不会整读入内存）。"""
    path = params.get("path")
    entry = params.get("entry")
    out_path = params.get("out_path")
    if not path or not entry or not out_path:
        return {"ok": False, "error": "需要 path/entry/out_path"}
    import zipfile
    try:
        zf = zipfile.ZipFile(path)
        info = zf.getinfo(entry)
    except Exception as exc:
        return {"ok": False, "error": f"打开/取条目失败: {exc}"}
    try:
        src = zf.open(info)
        os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
        written = 0
        with open(out_path, "wb") as dst:
            while True:
                b = src.read(_CHUNK)
                if not b:
                    break
                dst.write(b)
                written += len(b)
    except Exception as exc:
        return {"ok": False, "error": f"解压失败: {exc}"}
    return {"ok": True, "out_path": out_path, "written": written,
            "entry_size": info.file_size, "complete": written == info.file_size}


def flag_scan(params: dict) -> dict:
    """分块扫描大文件中的 flag 模式/可疑字符串（含跨块匹配）。"""
    path = params.get("path")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": f"文件不存在: {path}"}
    patterns = params.get("patterns") or [b"flag{", b"DASCTF{", b"ctf{", b"FLAG{", b"key=", b"password", b"secret"]
    patterns = [p.encode() if isinstance(p, str) else p for p in patterns]
    max_matches = int(params.get("max_matches", 20))
    max_len = max(len(p) for p in patterns)
    matches = []
    total = 0
    carry = b""
    with open(path, "rb") as f:
        while True:
            b = f.read(_CHUNK)
            if not b:
                break
            total += len(b)
            buf = carry + b
            for p in patterns:
                start = 0
                while True:
                    pos = buf.find(p, start)
                    if pos < 0:
                        break
                    off = total - len(b) - len(carry) + pos
                    ctx = buf[pos:pos + min(len(p) + 64, len(buf))]
                    matches.append({"offset": off, "pattern": p.decode(errors="replace"),
                                    "context": ctx.decode("latin-1", errors="replace")})
                    if len(matches) >= max_matches:
                        return {"ok": True, "path": path, "scanned": total,
                                "match_count": len(matches), "matches": matches,
                                "note": "命中已达上限，可能还有更多"}
                    start = pos + 1
            carry = buf[-max_len:]
    return {"ok": True, "path": path, "scanned": total,
            "match_count": len(matches), "matches": matches}


def lime_probe(params: dict) -> dict:
    """探测 LiME 内存镜像：魔数 + 头部系统信息。"""
    path = params.get("path")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": f"文件不存在: {path}"}
    with open(path, "rb") as f:
        head = f.read(4096)
    size = os.path.getsize(path)
    res = {"ok": True, "path": path, "size": size}
    if head[:4] == b"EMLF":
        res["format"] = "lime (LiME Linux 内存镜像)"
        res["magic"] = head[:4].hex()
    elif head[:4] == b"\x7fELF":
        res["format"] = "ELF 文件（非内存镜像）"
    else:
        res["format"] = "未知二进制"
        res["magic"] = head[:8].hex()
    # 头部系统信息字符串（Linux version / 进程名等）
    strings_found = re.findall(rb"[\x20-\x7e]{8,}", head)
    res["head_strings"] = [s.decode(errors="replace") for s in strings_found[:15]]
    return res


def strings_window(params: dict) -> dict:
    """指定窗口提取可打印字符串（默认文件头部 4MB）。"""
    path = params.get("path")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": f"文件不存在: {path}"}
    offset = int(params.get("offset", 0))
    length = int(params.get("length", 4 << 20))
    min_len = int(params.get("min_len", 6))
    max_strs = int(params.get("max_strings", 60))
    with open(path, "rb") as f:
        f.seek(offset)
        buf = f.read(length)
    strings_found = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, buf)
    return {
        "ok": True, "path": path, "offset": offset, "length": len(buf),
        "string_count": len(strings_found),
        "strings": [s.decode(errors="replace") for s in strings_found[:max_strs]],
        "truncated": len(strings_found) > max_strs,
    }


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def xor_title_search(params: dict) -> dict:
    """按题名 XOR 线索全文件扫描异或后的 flag 模式。

    默认 key 由题目名推导：'flag' ^ 'galf' = 01 0d 0d 01（10734 题名 flag^galf）。
    原理：若 flag 文本被 key 循环异或，则 ciphertext 含 prefix XOR key 的字节序列。
    关键：循环 XOR 的 key 相位取决于 flag 在文件中的偏移（off % key_len），
    故对每个相位（0..L-1）各扫一遍——L 通常很小（4），全文件 L 遍。
    """
    path = params.get("path")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": f"文件不存在: {path}"}
    key = params.get("key")
    if key is None:
        key = bytes(a ^ b for a, b in zip(b"flag", b"galf"))  # 01 0d 0d 01
    if isinstance(key, str):
        key = key.encode()
    prefixes = params.get("prefixes") or [b"DASCTF{", b"flag{", b"ctf{"]
    prefixes = [p.encode() if isinstance(p, str) else p for p in prefixes]
    max_matches = int(params.get("max_matches", 20))
    L = len(key)
    matches = []
    total = 0
    carry = b""
    # 预计算所有相位的 xor_pattern：phase_p = prefix XOR key 旋转 phase 位
    phase_patterns = []
    for phase in range(L):
        rot = key[phase:] + key[:phase]
        phase_patterns.append([_xor_bytes(p, rot) for p in prefixes])
    max_len = max(len(p) for pp in phase_patterns for p in pp)
    with open(path, "rb") as f:
        while True:
            b = f.read(_CHUNK)
            if not b:
                break
            total += len(b)
            buf = carry + b
            for phase, xps in enumerate(phase_patterns):
                for xp, orig in zip(xps, prefixes):
                    start = 0
                    while True:
                        pos = buf.find(xp, start)
                        if pos < 0:
                            break
                        off = total - len(b) - len(carry) + pos
                        # 用「文件偏移相位」反解上下文：key 相位 = off % L
                        ph2 = off % L
                        rot2 = key[ph2:] + key[:ph2]
                        ctx = _xor_bytes(buf[pos:pos + 64], rot2)
                        matches.append({"offset": off, "key": key.hex(), "phase": phase,
                                        "target_prefix": orig.decode(errors="replace"),
                                        "xor_prefix_hex": xp.hex(),
                                        "decoded_context": ctx.decode("latin-1", errors="replace")})
                        if len(matches) >= max_matches:
                            return {"ok": True, "path": path, "scanned": total, "key": key.hex(),
                                    "match_count": len(matches), "matches": matches}
                        start = pos + 1
            carry = buf[-max_len:]
    return {"ok": True, "path": path, "scanned": total, "key": key.hex(),
            "match_count": len(matches), "matches": matches,
            "note": "0 命中：可能非该 key 的循环 XOR，或 flag 明文存储（试 flag_scan）"}


def xor_key_discovery(params: dict) -> dict:
    """受限窗口爆破单字节 XOR key（找到候选后配合 flag_scan/xor_title_search 全扫）。

    窗口默认文件头部 256KB——避免 256 × 449MB 全扫；候选 key 再全文件验证。
    """
    path = params.get("path")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": f"文件不存在: {path}"}
    window = int(params.get("window", 256 << 10))
    prefixes = params.get("prefixes") or [b"DASCTF{", b"flag{", b"ctf{"]
    prefixes = [p.encode() if isinstance(p, str) else p for p in prefixes]
    with open(path, "rb") as f:
        buf = f.read(window)
    hits = []
    for k in range(256):
        for p in prefixes:
            xp = bytes(b ^ k for b in p)
            if xp in buf:
                hits.append({"key": k, "prefix": p.decode(errors="replace"),
                             "xor_prefix_hex": xp.hex()})
                break
    return {
        "ok": True, "path": path, "window": len(buf),
        "candidate_keys": hits,
        "note": "用命中的 key 调 xor_title_search(key=单字节bytes) 全文件扫描",
    }


def misc_bigfile_analysis(params: dict) -> dict:
    """skill 入口。"""
    kind = params.get("kind", "zip_list")
    handler = {
        "zip_list": zip_list,
        "nested_tail": nested_tail,
        "extract_entry": extract_entry,
        "flag_scan": flag_scan,
        "lime_probe": lime_probe,
        "strings_window": strings_window,
        "xor_title_search": xor_title_search,
        "xor_key_discovery": xor_key_discovery,
    }.get(kind)
    if handler is None:
        return {"ok": False, "error": f"unknown kind: {kind}",
                "kinds": list(handler_map_keys())}
    return handler(params)


def handler_map_keys():
    return ["zip_list", "nested_tail", "extract_entry", "flag_scan",
            "lime_probe", "strings_window", "xor_title_search", "xor_key_discovery"]


def run(params):
    """SkillManager 统一入口。"""
    return misc_bigfile_analysis(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="超大文件/嵌套zip/lime 镜像分析")
    parser.add_argument("--kind", required=True)
    parser.add_argument("--path", default="")
    parser.add_argument("--entry", default="")
    parser.add_argument("--out-path", default="")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--length", type=int, default=0)
    args = parser.parse_args()
    import json

    params = {"kind": args.kind, "path": args.path}
    if args.entry:
        params["entry"] = args.entry
    if args.out_path:
        params["out_path"] = args.out_path
    if args.offset:
        params["offset"] = args.offset
    if args.length:
        params["length"] = args.length
    print(json.dumps(misc_bigfile_analysis(params), ensure_ascii=False, indent=1,
                     default=lambda o: o.decode("latin-1") if isinstance(o, bytes) else str(o)))


if __name__ == "__main__":
    main()
