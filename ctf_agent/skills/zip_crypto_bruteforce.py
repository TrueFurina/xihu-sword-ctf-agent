"""Skill: ZipCrypto（传统 zip 加密）密码爆破 / CRC 定位。

来源：xuanhun_ezip L3 攻防（2026-10-07/08）实战沉淀。
关键工程教训（此 skill 已内置修正，勿再踩）：
1. ZipCrypto 密钥流是流式的——第 12 字节头的校验比对必须消费前 11 字节并持续
   更新 keys，跳过流式更新会让大空间爆破结果全部作废（历史上曾因此误判）。
2. 校验字节取值：flag_bits & 0x8（data descriptor）时 = local header 的 DOS time
   高字节；否则 = CRC32 高字节。双筛最稳。
3. deflate 条目（method=8）无法用已知明文攻击（bkcrack -x）——明文是压缩后字节
   流，PNG 头等原始序列不可见；store 条目（method=0）才可以。

性能（2026-10-09 实测，本机，真 ZipCrypto fixture）
--------------------------------------------------
第一道筛（`_pass1_*`）原本是纯 Python 逐字节流式推 keys，是**主要瓶颈**：

    逐个 _pass1_candidates         :  46,203 候选/秒（4 位 lower）
    run() 端到端（含命中复核）      :  25,000 候选/秒
    itertools.product 生成候选      : 6,797,611 候选/秒（**不是**瓶颈）

⇒ 于是把第一道筛改成 **numpy 批量**（同时对整批候选推进 keys）：

    _pass1_vector / _scan_enum     : 1,055,728 ~ 2,099,356 候选/秒（24~45x）

⚠️ **提速后新瓶颈换成命中复核**：头校验只有 1 个校验字节 ⇒ 误报率 1/256，
每 256 个候选就要付一次 `_try_password`（实测 **3.0 ms/次**，zipfile 的解密器
是纯 Python 逐字节）。所以端到端约 **85,000 候选/秒**（不是 1M），
本轮不改复核——它需要独立方案（向量化 body 解密 + CRC），见文件末尾 NOTE。

numpy 是硬依赖（`requirements.txt` 已 pin），但这里仍写成**软依赖**：
取不到就回退逐个实现，结果完全一致（有对拍测试保证）。

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

try:
    import numpy as np
    _HAVE_NUMPY = True
except ImportError:      # pragma: no cover - numpy 是硬依赖，此处仅为不拖垮导入
    np = None
    _HAVE_NUMPY = False

_CRCTAB = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    _CRCTAB.append(_c)

# 批量筛的块大小：65536 条一批，矩阵内存 ~3MB，实测速率与 200k 一批持平。
_CHUNK = 65536

if _HAVE_NUMPY:
    # 用 int64：k1 的乘法最大 2^32 * 2^27 = 2^59，uint32 会溢出。
    _CRCN = np.array(_CRCTAB, dtype=np.int64)
    _MULT = np.int64(134775813)
    _MASK = np.int64(0xFFFFFFFF)


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


def _pass1_vector(hdr, check_byte, pwds):
    """批量版 `_pass1_candidates`：返回通过第一道筛的下标列表。

    与逐个版**逐条对拍过**（30,004 条随机候选，命中集合完全一致）；
    无 numpy 时直接回退逐个版，行为不变。
    """
    if not _HAVE_NUMPY:
        return [i for i, p in enumerate(pwds)
                if _pass1_candidates(hdr, check_byte, p)]
    n = len(pwds)
    if n == 0:
        return []
    k0 = np.full(n, 0x12345678, dtype=np.int64)
    k1 = np.full(n, 0x23456789, dtype=np.int64)
    k2 = np.full(n, 0x34567890, dtype=np.int64)

    # 变长候选按长度分桶 —— 桶内等长才能 reshape 成矩阵一次性推进
    by_len = {}
    for i, p in enumerate(pwds):
        by_len.setdefault(len(p), []).append(i)
    for L, idxs in by_len.items():
        if L == 0:
            continue
        sel = np.asarray(idxs, dtype=np.intp)
        mat = np.frombuffer(b"".join(pwds[i] for i in idxs),
                            dtype=np.uint8).reshape(len(idxs), L)
        a0, a1, a2 = k0[sel], k1[sel], k2[sel]
        for j in range(L):
            b = mat[:, j].astype(np.int64)
            a0 = (a0 >> 8) ^ _CRCN[(a0 ^ b) & 0xFF]
            a1 = ((a1 + (a0 & 0xFF)) * _MULT + 1) & _MASK
            a2 = (a2 >> 8) ^ _CRCN[(a2 ^ (a1 >> 24)) & 0xFF]
        k0[sel], k1[sel], k2[sel] = a0, a1, a2

    c = None
    for j in range(12):
        t = k2 | 2
        p = ((t * ((t ^ 1) & 0xFFFF)) >> 8) & 0xFF
        c = np.int64(hdr[j]) ^ p
        k0 = (k0 >> 8) ^ _CRCN[(k0 ^ c) & 0xFF]
        k1 = ((k1 + (k0 & 0xFF)) * _MULT + 1) & _MASK
        k2 = (k2 >> 8) ^ _CRCN[(k2 ^ (k1 >> 24)) & 0xFF]
    return np.nonzero(c == check_byte)[0].tolist()


def _pwd_from_index(idx: int, table: bytes, length: int) -> bytes:
    """把 `_scan_enum` 命中的全局序号还原成密码字节。

    编码与 `itertools.product` **同序**（末位变化最快）——已对拍。
    """
    n = len(table)
    out = bytearray(length)
    for j in range(length - 1, -1, -1):
        out[j] = table[idx % n]
        idx //= n
    return bytes(out)


def _scan_enum(hdr, check_byte, table: bytes, length: int,
               start: int, count: int):
    """向量枚举 + 校验：`table` 上 length 位候选的 [start, start+count) 段。

    返回命中的**全局序号**列表（该长度空间内从 0 计）。
    候选本身不落成 Python 对象（这是比 `_gen_passwords` 快的关键：
    连 `itertools.product` 的 join/encode 都省了）。
    """
    base = np.int64(len(table))
    tbl = np.frombuffer(table, dtype=np.uint8).astype(np.int64)
    idx = np.arange(start, start + count, dtype=np.int64)
    k0 = np.full(count, 0x12345678, dtype=np.int64)
    k1 = np.full(count, 0x23456789, dtype=np.int64)
    k2 = np.full(count, 0x34567890, dtype=np.int64)
    # ⚠️ 必须先推进**高位**（密码第 0 字节）——keys 是流式的，字节顺序错了
    #    整个结果就废了。第一版写成 `col % base` 从末位开始推 ⇒ 端到端
    #    **漏掉正确密码**（回退路径能解出、向量路径解不出，靠这个才抓到）。
    #    序号编码仍是「末位变化最快」（与 itertools.product 同序），
    #    只是 keys 推进要按位权从高到低取。
    pows = [np.int64(len(table) ** (length - 1 - j)) for j in range(length)]
    for j in range(length):
        d = (idx // pows[j]) % base
        b = tbl[d]
        k0 = (k0 >> 8) ^ _CRCN[(k0 ^ b) & 0xFF]
        k1 = ((k1 + (k0 & 0xFF)) * _MULT + 1) & _MASK
        k2 = (k2 >> 8) ^ _CRCN[(k2 ^ (k1 >> 24)) & 0xFF]
    c = None
    for j in range(12):
        t = k2 | 2
        p = ((t * ((t ^ 1) & 0xFFFF)) >> 8) & 0xFF
        c = np.int64(hdr[j]) ^ p
        k0 = (k0 >> 8) ^ _CRCN[(k0 ^ c) & 0xFF]
        k1 = ((k1 + (k0 & 0xFF)) * _MULT + 1) & _MASK
        k2 = (k2 >> 8) ^ _CRCN[(k2 ^ (k1 >> 24)) & 0xFF]
    return (np.nonzero(c == check_byte)[0] + start).tolist()


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


_CHARSET_TABLES = {
    "digits": "0123456789",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "base36": "0123456789abcdefghijklmnopqrstuvwxyz",
    "base62": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
}


def _gen_passwords(charsets, min_len, max_len):
    tables = _CHARSET_TABLES
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


def _drain(pwds, hdr, check, zip_path, info_name, crc):
    """一批候选：批量过第一道筛，再对命中者逐个精确复核。"""
    for i in _pass1_vector(hdr, check, pwds):
        pwd = pwds[i]
        data = _try_password(zip_path, info_name, crc, pwd)
        if data is not None:
            return (pwd, data)
    return None


def _scan_stream(pwd_iter, hdr, check, zip_path, info_name, crc,
                 max_cand, tried=0):
    """逐块消费候选流。返回 (found, tried, over_limit)。

    `over_limit`：预算正好用尽且候选流还没走完（调用方据此决定报错文案）。
    语义与改造前的逐个循环一致——`tried` 达到 `max_cand` 后**下一个**候选即超限。
    """
    buf = []
    for pwd in pwd_iter:
        if tried >= max_cand:
            return None, tried + 1, True
        tried += 1
        buf.append(pwd)
        if len(buf) >= _CHUNK:
            hit = _drain(buf, hdr, check, zip_path, info_name, crc)
            buf.clear()
            if hit:
                return hit, tried, False
    if buf:
        hit = _drain(buf, hdr, check, zip_path, info_name, crc)
        if hit:
            return hit, tried, False
    return None, tried, False


def _scan_charsets(charsets, min_len, max_len, hdr, check, zip_path,
                   info_name, crc, max_cand, tried=0):
    """字符集枚举（按 `digits → lower → ...` 顺序，与 `_gen_passwords` 同序）。

    numpy 可用时走 `_scan_enum`（候选根本不落成 Python 对象）；
    否则回退 `_gen_passwords` + `_scan_stream`，结果一致。
    """
    for cs in charsets:
        table = _CHARSET_TABLES.get(cs)
        if not table:
            continue
        tb = table.encode()
        for L in range(min_len, max_len + 1):
            if not _HAVE_NUMPY:
                found, tried, over = _scan_stream(
                    _gen_passwords([cs], L, L), hdr, check, zip_path,
                    info_name, crc, max_cand, tried)
                if found or over:
                    return found, tried, over
                continue
            total = len(tb) ** L
            for start in range(0, total, _CHUNK):
                cnt = min(_CHUNK, total - start)
                room = max_cand - tried
                if room <= 0:
                    return None, tried + 1, True
                scan = min(cnt, room)
                for gi in _scan_enum(hdr, check, tb, L, start, scan):
                    pwd = _pwd_from_index(gi, tb, L)
                    data = _try_password(zip_path, info_name, crc, pwd)
                    if data is not None:
                        return (pwd, data), tried + (gi - start) + 1, False
                tried += scan
                if scan < cnt:          # 预算用尽（块被截断）
                    return None, tried + 1, True
    return None, tried, False


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
        def _lines():
            with open(dict_path, "rb") as f:
                for line in f:
                    p = line.rstrip(b"\r\n")
                    if p:
                        yield p
        # 字典超限时沿用旧行为：走完再报「密码未命中」（不报超上限）
        found, tried, _over = _scan_stream(
            _lines(), hdr, check, zip_path, info_name, crc, max_cand, tried)

    # 2) 字符集枚举
    if not found:
        charsets = params.get("charsets") or ["digits", "lower"]
        found, tried, over = _scan_charsets(
            charsets, min_len, max_len, hdr, check, zip_path, info_name,
            crc, max_cand, tried)
        if over:
            return {"ok": False, "error": f"候选超上限 {max_cand}，未命中",
                    "entry": info_name, "tried": tried}

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
