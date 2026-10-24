# -*- coding: utf-8 -*-
"""misc_deflate_huffman_flag skill：DEFLATE 动态 Huffman 树隐码确定性求解器。

针对题型（question-specific）
---------------------------
Google CTF 2021 misc「David and the Tree」：题面给一个 ZIP，内装
 lipogram 小说 *Gadsby*（Ernest Vincent Wright，全文约 5 万字**不用
 字母 E**）的前 26 章（大写）。题面暗示「what's more important is not
 what you have, but what you're missing」——缺失的是字母 **E**；标题
 「David」指 DEFLATE 的 Huffman 树（David A. Huffman）。

真相：每个条目的 deflate 流都是**动态 Huffman 块**（BTYPE=10），其
 litlen 码树为符号 69（'E'）分配了一个**正常编码器绝不会分配**的码
（文本里没有 E，频率编码不会给它码长）——该码即隐写信道：每条目一个
 字符。提取方式：取符号 69 的规范码，`& 0xFF` 后对低 8 位**逆序**，
 得 ASCII 字符；按 ZIP 条目序拼接即 flag。本题 26 条目全部为 8 位
 等长码（256 符号 × 2^-8 = 1 的满树），实测解出 flag 且与题面
 flag_sha256 逐字匹配（真值由下游 answer_check / sha256 仲裁校验，
 本文件与测试均不落 flag 明文）。

管线（全部确定性、纯标准库）
--------------------------
1. ZIP 结构解析：EOCD → 中央目录（权威 csz / 本地头偏移）→ 逐条目
   取本地头后的 deflate 原始字节（对 data descriptor 形态稳健）
2. RFC 1951 动态块头解析：BFINAL/BTYPE → HLIT/HDIST/HCLEN →
   CLCL 序码长（3 bit）→ 规范法建码长 Huffman → 解出 litlen+dist
   码长（0-15 直给 / 16 复刻前值 3-6 / 17 重复 0 3-10 / 18 重复 0 11-138）
3. 规范法（RFC 1951 §3.2.2）建 litlen 码表，取符号 69 的码
4. `& 0xFF` + 8 位逆序 → ASCII 字符；全条目拼装

防误报双守卫（缺一不可，2026-10-13 设计）
----------------------------------------
· **lipogram 守卫**：逐条目 zlib 解压，解压文本的 E 占比须
  ≤ 1e-3。真题型 ~1.6e-5（26 章共 3 个源自原版印刷失误的 E），
  正常英文文本 ~1e-1，两侧各留 ~60/100 倍裕度。只凭「E 码存在」
  不构成判据——正常含 E 文本的树里同样有 E 码。
· **码长守卫**：符号 69 的码长须 ≤ 9 位。频率编码对稀有符号给长码
  （本题 E 出现 0-1 次/章，正常编码器会给 13-15 位）；8 位满树码是
  人工构造指纹。
另：全部条目须为 deflate（method 8）且**每条**都提出字符（拼装语义），
条目数 ≥ 4；任一条目不满足 → 整体 None（fail-closed，不崩不谎报）。

诚实口径
--------
本路是「RFC 1951 位级语法 + 规范 Huffman 构造」的确定性实现，
非 grep 明文、非读答案文件。⚠️ 属 B1 工具链补齐产物，不代表 LLM
自主能力。命中由下游 flag_pattern + 答案校验把关。
"""
import os
import struct
import zlib

# DEFLATE 码长码（code-length code）的读取顺序（RFC 1951 §3.2.5）
_CLCL_ORDER = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)

# 隐写符号：'E'
_E_SYMBOL = 69

# 守卫阈值（见模块 docstring「防误报双守卫」）
_E_RATIO_MAX = 1e-3      # 解压文本 E 占比上限（lipogram 判定）
_E_CODE_LEN_MAX = 9      # 符号 69 码长上限（人工树指纹）
_MIN_ENTRIES = 4         # flag 至少 4 字符
_MAX_ZIP_BYTES = 32 * 1024 * 1024  # skill 自护栏（presolve 层另有 8MB 预检）


class _BitReader:
    """DEFLATE 位流：每字节 LSB first（RFC 1951 §3.1.1）。"""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0  # 绝对位偏移

    def read(self, n: int) -> int:
        v = 0
        for i in range(n):
            byte = self.data[self.pos >> 3]
            v |= ((byte >> (self.pos & 7)) & 1) << i
            self.pos += 1
        return v


def _build_codes(lengths):
    """RFC 1951 §3.2.2 规范码分配：lengths[sym]=0 表示无码。

    返回与 lengths 等长的码值表（码值为整数，第 len-1 位是第一个
    被读出的位——DEFLATE 惯例）。
    """
    max_len = max(lengths) if lengths else 0
    bl_count = [0] * (max_len + 1)
    for l in lengths:
        if l:
            bl_count[l] += 1
    next_code = [0] * (max_len + 2)
    code = 0
    for bits in range(1, max_len + 1):
        code = (code + bl_count[bits - 1]) << 1
        next_code[bits] = code
    codes = [0] * len(lengths)
    for n, l in enumerate(lengths):
        if l:
            codes[n] = next_code[l]
            next_code[l] += 1
    return codes


def _build_decoder(lengths):
    """(len, code) -> symbol 查表（仅用于码长码解码）。"""
    codes = _build_codes(lengths)
    return {(l, codes[s]): s for s, l in enumerate(lengths) if l}


def _decode_symbol(br: _BitReader, table) -> int:
    """逐位读入匹配规范码；16 位内不中 → 抛错（流损坏）。"""
    code = 0
    for l in range(1, 16):
        code |= br.read(1)
        hit = table.get((l, code))
        if hit is not None:
            return hit
        code <<= 1
    raise ValueError("bad huffman code")


def _parse_dynamic_litlen(br: _BitReader):
    """解析一个动态 Huffman 块头，返回 litlen 码长表。"""
    hlit = br.read(5) + 257
    hdist = br.read(5) + 1
    hclen = br.read(4) + 4
    cl_lengths = [0] * 19
    for i in range(hclen):
        cl_lengths[_CLCL_ORDER[i]] = br.read(3)
    cl_table = _build_decoder(cl_lengths)
    lengths = []
    need = hlit + hdist
    while len(lengths) < need:
        sym = _decode_symbol(br, cl_table)
        if sym < 16:
            lengths.append(sym)
        elif sym == 16:
            if not lengths:
                raise ValueError("code 16 with no previous length")
            lengths.extend([lengths[-1]] * (3 + br.read(2)))
        elif sym == 17:
            lengths.extend([0] * (3 + br.read(3)))
        else:  # 18
            lengths.extend([0] * (11 + br.read(7)))
        if len(lengths) > need + 138:  # 病态膨胀保护
            raise ValueError("code length stream overruns")
    return lengths[:hlit]


def _reverse8(v: int) -> int:
    r = 0
    for _ in range(8):
        r = (r << 1) | (v & 1)
        v >>= 1
    return r


def _e_char_from_deflate(deflate: bytes):
    """从一条 deflate 流提取隐写字符；无动态块/无 E 码 → None。

    逐块扫描：BTYPE=10 且 litlen 树给符号 69 分配了码 → 取该码变换。
    BTYPE=00（stored）按 LEN 跳过；BTYPE=01（fixed）无法在不解码的
    情况下跳过 → 放弃（None）。
    """
    br = _BitReader(deflate)
    while True:
        bfinal = br.read(1)
        btype = br.read(2)
        if btype == 2:
            litlen_lengths = _parse_dynamic_litlen(br)
            if (len(litlen_lengths) > _E_SYMBOL
                    and 0 < litlen_lengths[_E_SYMBOL] <= _E_CODE_LEN_MAX):
                code = _build_codes(litlen_lengths)[_E_SYMBOL]
                return chr(_reverse8(code & 0xFF))
            return None
        if btype == 0:
            br.pos = (br.pos + 7) & ~7  # 跳到字节边界
            ln = br.read(16)
            br.read(16)                 # NLEN（不校验，宽松跳过）
            br.pos += 8 * ln
        else:
            return None
        if bfinal:
            return None
        if (br.pos >> 3) >= len(deflate):
            return None


def _e_ratio(text: bytes) -> float:
    """解压文本中 E/e 的占比。"""
    if not text:
        return 0.0
    return (text.count(b"E") + text.count(b"e")) / len(text)


def _zip_deflate_streams(data: bytes):
    """ZIP → [(条目名, deflate 字节)]，按中央目录序。

    经 EOCD → 中央目录取权威 (method, csz, 本地头偏移)，再回读本地头
    （对 bit-3 data descriptor 形态稳健：本地头 csz 可能为 0，以中央
    目录为准）。任何结构不一致 → None（fail-closed）。
    """
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(data):
        return None
    (_sig, _disk, _cddisk, _ndisk, ntot, _cdsz,
     cdoff, _clen) = struct.unpack("<IHHHHIIH", data[eocd:eocd + 22])
    if ntot == 0 or cdoff <= 0 or cdoff >= len(data):
        return None
    out = []
    off = cdoff
    for _ in range(ntot):
        if off + 46 > len(data) or data[off:off + 4] != b"PK\x01\x02":
            return None
        (_s, _ver, _vneed, _flag, method, _t, _d, _crc, csz, _usz,
         nlen, elen, _clen2, _dsk, _ia, _ea, lh) = struct.unpack(
            "<IHHHHHHIIIHHHHHII", data[off:off + 46])
        name = data[off + 46:off + 46 + nlen]
        off += 46 + nlen + elen + _clen2
        if method != 8 or csz == 0:
            return None  # 拼装语义：每条目都须承载码，非 deflate 即失败
        if lh + 30 > len(data) or data[lh:lh + 4] != b"PK\x03\x04":
            return None
        lnlen, lelen = struct.unpack("<HH", data[lh + 26:lh + 30])
        start = lh + 30 + lnlen + lelen
        if start + csz > len(data):
            return None
        out.append((name.decode("utf-8", "replace"), data[start:start + csz]))
    return out


def solve(data: bytes):
    """ZIP 字节 → flag 字符串；非目标形态 → None。"""
    if not data or len(data) > _MAX_ZIP_BYTES:
        return None
    if data[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
        return None
    entries = _zip_deflate_streams(data)
    if not entries or len(entries) < _MIN_ENTRIES:
        return None
    chars = []
    for _name, ds in entries:
        # 守卫①：lipogram 判定（解压文本几乎不含 E；raw deflate 无 zlib 头）
        try:
            text = zlib.decompressobj(wbits=-15).decompress(ds)
        except zlib.error:
            return None
        if _e_ratio(text) > _E_RATIO_MAX:
            return None
        # 守卫② + 提取：E 码须存在且为人工短码
        ch = _e_char_from_deflate(ds)
        if ch is None or not (0x20 <= ord(ch) <= 0x7E):
            return None
        chars.append(ch)
    flag = "".join(chars)
    if len(flag) < _MIN_ENTRIES:
        return None
    return flag


def run(params: dict) -> dict:
    """skill 入口（KPI 计数只数顶层 run 入口者）。

    params:
        "path": ZIP 文件路径
    返回:
        {"flag": <str>} 或 {"flag": None}
    """
    path = str((params or {}).get("path") or "")
    if not path or not os.path.isfile(path):
        return {"flag": None}
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return {"flag": None}
    try:
        flag = solve(data)
    except Exception:  # noqa: BLE001 - 非目标形态一律优雅放弃（不崩、不谎报）
        return {"flag": None}
    return {"flag": flag}
