"""Skill: ZipCrypto（传统 zip 加密）密码爆破 / CRC 定位。

来源：xuanhun_ezip L3 攻防（2026-10-07/08）实战沉淀。
关键工程教训（此 skill 已内置修正，勿再踩）：
1. ZipCrypto 密钥流是流式的——第 12 字节头的校验比对必须消费前 11 字节并持续
   更新 keys，跳过流式更新会让大空间爆破结果全部作废（历史上曾因此误判）。
2. 校验字节取值：flag_bits & 0x8（data descriptor）时 = local header 的 DOS time
   高字节；否则 = CRC32 高字节。双筛最稳。
3. deflate 条目（method=8）无法用已知明文攻击（bkcrack -x）——明文是压缩后字节
   流，PNG 头等原始序列不可见；store 条目（method=0）才可以。

输入: params = {
    "zip_path": zip 文件路径,
    "entry": 条目名（缺省取第一个）,
    "dict_path": 可选，密码字典（每行一个）,
    "charsets": 可选，如 ["digits","lower","upper","alnum","base36","base62"],
    "min_len": 最短长度（默认 1）,
    "max_len": 最长长度（默认 6，Python 慢速路径建议 ≤6）,
    "max_candidates": 上限（默认 5e7，防止死循环烧时间）,
}
输出: {'ok': bool, 'password': str|None, 'entry': str, 'data': bytes|None,
       'flag': str|None, 'out_path': str|None, 'error': str|None}

flag 提取：解密成功后正则扫描 flag{...} / FLAG{...}；同时把明文落盘 out_path。
"""

import os
import re
import struct
import zlib
import binascii
import itertools
import tempfile

_CRCTAB = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    _CRCTAB.append(_c)


def _crc_upd(crc: int, b: int) -> int:
    return (crc >> 8) ^ _CRCTAB[(crc ^ b) & 0xFF]


def _keys_update(k0, k1, k2, b):
    k0 = _crc_upd(k0, b)
    k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
    k2 = _crc_upd(k2, (k1 >> 24) & 0xFF)
    return k0, k1, k2


def _stream_keystream_byte(k0, k1, k2):
    """当前 keys 状态下的密钥流字节（与 zipfile._ZipDecrypter 逐字节对拍一致）。"""
    return ((k2 | 2) * (((k2 | 2) ^ 1) & 0xFFFF) >> 8) & 0xFF


def _local_entry(zip_path: str, entry_name: str | None):
    """返回 (hdr12, body, info_crc, check_byte, method, usize)。密文含 12 字节头。"""
    blob = open(zip_path, "rb").read()
    # 用中央目录拿到 entry 与 header_offset，再按 local header 精确定位
    import zipfile
    z = zipfile.ZipFile(zip_path)
    infos = z.infolist()
    if entry_name:
        info = next((i for i in infos if i.filename == entry_name), None)
        if info is None:
            raise FileNotFoundError(f"entry 不存在: {entry_name}")
    else:
        info = infos[0]
    ho = info.header_offset
    _sig, _ver, flag, method, mtime, _mdate, crc, csize, usize, nlen, elen = struct.unpack(
        "<IHHHHHIIIHH", blob[ho:ho + 30])
    hdr = blob[ho + 30 + nlen + elen: ho + 30 + nlen + elen + 12]
    body = blob[ho + 30 + nlen + elen + 12: ho + 30 + nlen + elen + csize]
    if flag & 0x8:  # data descriptor：校验字节 = local DOS time 高字节
        check = (mtime >> 8) & 0xFF
    else:            # 常规：CRC32 高字节
        check = (crc >> 24) & 0xFF
    return hdr, body, crc & 0xFFFFFFFF, check, method, usize


def _pass1_candidates(hdr, check_byte, pwd_bytes):
    """流式正确的 12 字节头校验（返回 True 表示候选通过第一道筛）。"""
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for b in pwd_bytes:
        k0, k1, k2 = _keys_update(k0, k1, k2, b)
    ok = True
    for j in range(12):
        p = _stream_keystream_byte(k0, k1, k2)
        c = hdr[j] ^ p
        k0, k1, k2 = _keys_update(k0, k1, k2, c)  # 关键：消费明文头字节后 keys 持续更新
        if j == 11 and c != check_byte:
            ok = False
    return ok


def _try_password(zip_path: str, info_name: str, expect_crc: int, pwd: bytes):
    """精确复核：完整解密 + inflate（若 method=8）+ CRC32 比对。"""
    import zipfile
    z = zipfile.ZipFile(zip_path)
    info = next(i for i in z.infolist() if i.filename == info_name)
    try:
        z.setpassword(pwd)
        data = z.read(info)
    except Exception:
        return None
    if binascii.crc32(data) & 0xFFFFFFFF != expect_crc:
        return None
    return data


def _gen_passwords(charsets, min_len, max_len):
    tables = {
        "digits": "0123456789",
        "lower": "abcdefghijklmnopqrstuvwxyz",
        "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "base36": "0123456789abcdefghijklmnopqrstuvwxyz",
        "base62": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    }
    for cs in charsets:
        table = tables.get(cs)
        if not table:
            continue
        for L in range(min_len, max_len + 1):
            for tup in itertools.product(table, repeat=L):
                yield "".join(tup).encode()


def _extract_flag(data: bytes):
    m = re.search(rb"(?:flag|FLAG|ctf|CTF)\{[^}\n]{1,120}\}", data)
    return m.group(0).decode() if m else None


def run(params):
    zip_path = str(params.get("zip_path") or params.get("path") or "").strip()
    if not zip_path or not os.path.exists(zip_path):
        return {"ok": False, "error": f"zip 文件不存在: {zip_path}"}
    entry = params.get("entry")
    try:
        hdr, body, crc, check, method, usize = _local_entry(zip_path, entry)
    except Exception as e:
        return {"ok": False, "error": f"解析失败: {e}"}
    info_name = entry
    import zipfile
    if not info_name:
        info_name = zipfile.ZipFile(zip_path).infolist()[0].filename

    max_cand = int(params.get("max_candidates", 50_000_000))
    min_len = int(params.get("min_len", 1))
    max_len = int(params.get("max_len", 6))
    found = None
    tried = 0

    # 1) 字典路径
    dict_path = params.get("dict_path")
    if dict_path and os.path.exists(dict_path):
        with open(dict_path, "rb") as f:
            for line in f:
                pwd = line.rstrip(b"\r\n")
                if not pwd:
                    continue
                tried += 1
                if tried > max_cand:
                    break
                if _pass1_candidates(hdr, check, pwd):
                    data = _try_password(zip_path, info_name, crc, pwd)
                    if data is not None:
                        found = (pwd, data)
                        break

    # 2) 字符集枚举
    if not found:
        charsets = params.get("charsets") or ["digits", "lower"]
        for pwd in _gen_passwords(charsets, min_len, max_len):
            tried += 1
            if tried > max_cand:
                return {"ok": False, "error": f"候选超上限 {max_cand}，未命中",
                        "entry": info_name, "tried": tried}
            if _pass1_candidates(hdr, check, pwd):
                data = _try_password(zip_path, info_name, crc, pwd)
                if data is not None:
                    found = (pwd, data)
                    break

    if not found:
        return {"ok": False, "error": "密码未命中", "entry": info_name,
                "tried": tried, "check_byte": hex(check)}

    pwd, data = found
    flag = _extract_flag(data)
    out_path = os.path.join(
        tempfile.gettempdir(),
        f"zcb_{os.path.basename(info_name) or 'entry'}")
    with open(out_path, "wb") as f:
        f.write(data)
    return {"ok": True, "password": pwd.decode("utf-8", "replace"),
            "entry": info_name, "size": len(data), "flag": flag,
            "out_path": out_path, "tried": tried}


if __name__ == "__main__":
    import argparse
    import json
    ap = argparse.ArgumentParser(description="ZipCrypto 密码爆破")
    ap.add_argument("--zip", required=True)
    ap.add_argument("--entry", default=None)
    ap.add_argument("--dict", dest="dict_path", default=None)
    ap.add_argument("--charsets", default="digits,lower")
    ap.add_argument("--min-len", type=int, default=1)
    ap.add_argument("--max-len", type=int, default=6)
    args = ap.parse_args()
    print(json.dumps(run({
        "zip_path": args.zip, "entry": args.entry, "dict_path": args.dict_path,
        "charsets": args.charsets.split(","),
        "min_len": args.min_len, "max_len": args.max_len,
    }), ensure_ascii=False, indent=1))
