"""数字矩阵 → QR 码解码（版本 1-10，全 8 掩码，byte/alnum/numeric）。

适用题型（确定性、零外部依赖）：
    附件是「一串整数」，每个整数是二维码的一行（每行 n 位 = n 个模块），
    行数 = 列数 = QR 边长。典型题面会暗示「这是二维码 / QR code / 二维码」。

    例（NYU CTF Bench 2023q-for-1black0white）：
        qr_code.txt = 29 行十进制整数，每行 29 位 → 29×29 = QR 版本 3，
        解码得 csawctf{1_d1dnt_kn0w_th1s_w0uld_w0rk}。

为什么手写解码器而不是装第三方库：
    QR 解码只需「格式信息(BCH) + 掩码表 + 之字形取码字 + 分块反交织 + 段解析」，
    全部是公开标准的确定性算法；手写实现零二进制依赖（opencv/pyzbar 均为数十 MB
    且需要系统级 zbar），契合本框架「确定性优先、依赖精简」的定位。
    版本 1-10 覆盖 21×21..57×57，byte 模式可容纳 271 字节（L 级），远超 CTF flag 长度。

算法（全部来自 ISO/IEC 18004，无任何「猜答案」成分）：
    1. 边长 → 版本：size = 4·version + 17；
    2. 读两份格式信息（MSB 在 coord 列表首位），与 32 个合法 BCH 码字比对
       → 得到纠错等级(L/M/Q/H) 与 8 个掩码中的哪一个；
    3. 按掩码公式翻转数据模块；
    4. 之字形遍历（右下起，交替向上/向下，跳过第 6 列定位列）取出码字比特；
    5. 按版本+等级的 (ec/块, 块数, 数据码字/块) 表反交织，拼回数据码字流；
    6. 解析段：数字(0001)/字母数字(0010)/字节(0100)，拼接输出。

诚实口径：
    · 本技能只做「解码」，不做任何形式的明文嗅探/grep；命中与否由下游
      flag_pattern + 答案校验（题面提供时）把关；
    · 数字→矩阵的位序（MSB/LSB）与明暗极性（0/1 或 1/0）在题面未知，
      故对 4 种组合各试一次，仅返回「像 flag」或「唯一可打印」的结果，
      避免把噪声当命中；
    · 不支持的版本(>10) / 汉字模式 / 多段 ECI → 返回 None（不谎报）。

接口对齐 skills/*.run：
    params:
        "path": 整数文本文件路径（与 text 二选一）
        "text": 含整数的文本
        "rows": 直接给定整数列表（最高优先，用于测试）
    返回: 解码出的 bytes；无命中 → None
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Sequence, Tuple

# 默认 flag 形状（与其他 skill 保持一致）
_FLAG_RE = re.compile(
    rb"(?:flag|FLAG|Flag|dasctf|DASCTF|ctf|CTF|nssctf|NSSCTF|isctf|ISCTF|HTB|htb)"
    rb"\{[ -~]{1,200}\}"
)

# 版本 → 对齐图案中心坐标（ISO/IEC 18004 附录 E，版本 1-10）
_ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}

# (版本, 等级) -> (每块纠错码字, [(块数, 每块数据码字), ...])
# 等级索引：0=L, 1=M, 2=Q, 3=H
_BLOCKS = {
    (1, 0): (7, [(1, 19)]), (1, 1): (10, [(1, 16)]), (1, 2): (13, [(1, 13)]), (1, 3): (17, [(1, 9)]),
    (2, 0): (10, [(1, 34)]), (2, 1): (16, [(1, 28)]), (2, 2): (22, [(1, 22)]), (2, 3): (28, [(1, 16)]),
    (3, 0): (15, [(1, 55)]), (3, 1): (26, [(1, 44)]), (3, 2): (18, [(2, 17)]), (3, 3): (22, [(2, 13)]),
    (4, 0): (20, [(1, 80)]), (4, 1): (18, [(2, 32)]), (4, 2): (26, [(2, 24)]), (4, 3): (16, [(4, 9)]),
    (5, 0): (26, [(1, 108)]), (5, 1): (24, [(2, 43)]), (5, 2): (18, [(2, 15), (2, 16)]), (5, 3): (22, [(2, 11), (2, 12)]),
    (6, 0): (18, [(2, 68)]), (6, 1): (16, [(4, 27)]), (6, 2): (24, [(4, 19)]), (6, 3): (28, [(4, 15)]),
    (7, 0): (20, [(2, 78)]), (7, 1): (18, [(4, 31)]), (7, 2): (18, [(2, 14), (4, 15)]), (7, 3): (26, [(4, 13), (1, 14)]),
    (8, 0): (24, [(2, 97)]), (8, 1): (22, [(2, 38), (2, 39)]), (8, 2): (22, [(4, 18), (2, 19)]), (8, 3): (26, [(4, 14), (2, 15)]),
    (9, 0): (30, [(2, 116)]), (9, 1): (22, [(3, 36), (2, 37)]), (9, 2): (20, [(4, 16), (4, 17)]), (9, 3): (24, [(4, 12), (4, 13)]),
    (10, 0): (18, [(2, 68), (2, 69)]), (10, 1): (26, [(4, 43), (1, 44)]), (10, 2): (24, [(6, 19), (2, 20)]), (10, 3): (28, [(6, 15), (2, 16)]),
}

_EC_ORDER = {0b01: 0, 0b00: 1, 0b11: 2, 0b10: 3}  # 等级位 -> 索引

MIN_VERSION, MAX_VERSION = 1, 10
_SIZE_OF = lambda v: 4 * v + 17  # noqa: E731


def _fmt_bits(data5: int) -> int:
    """5 bit (ec|mask) → 15 bit BCH 码字（生成多项式 0x537），再异或 0x5412。"""
    d = data5 << 10
    for i in range(4, -1, -1):
        if d & (1 << (i + 10)):
            d ^= 0x537 << i
    return ((data5 << 10) | d) ^ 0x5412


_FORMAT_TABLE = {}
for _ec in (0b01, 0b00, 0b11, 0b10):
    for _mk in range(8):
        _FORMAT_TABLE[_fmt_bits((_ec << 3) | _mk)] = (_ec, _mk)


def _fmt_coords(size: int) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """两份格式信息的位置（顺序 = 码字 bit14..bit0，即首位为 MSB）。"""
    c1 = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
          (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    c2 = [(size - 1, 8), (size - 2, 8), (size - 3, 8), (size - 4, 8), (size - 5, 8),
          (size - 6, 8), (size - 7, 8), (8, size - 8), (8, size - 7), (8, size - 6),
          (8, size - 5), (8, size - 4), (8, size - 3), (8, size - 2), (8, size - 1)]
    return c1, c2


def _function_map(size: int, version: int) -> List[List[bool]]:
    """功能图案掩码（finder/separator/timing/alignment/format/dark module/version info）。"""
    f = [[False] * size for _ in range(size)]

    def finder(r0, c0):
        for r in range(r0 - 1, r0 + 8):
            for c in range(c0 - 1, c0 + 8):
                if 0 <= r < size and 0 <= c < size:
                    f[r][c] = True

    finder(0, 0); finder(0, size - 7); finder(size - 7, 0)
    for i in range(size):
        f[6][i] = True; f[i][6] = True
    for r in _ALIGN[version]:
        for c in _ALIGN[version]:
            if (r < 8 and c < 8) or (r < 8 and c > size - 9) or (r > size - 9 and c < 8):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    f[r + dr][c + dc] = True
    for i in range(9):
        f[8][i] = True; f[i][8] = True
    for i in range(8):
        f[8][size - 1 - i] = True; f[size - 1 - i][8] = True
    f[size - 8][8] = True
    if version >= 7:
        for i in range(6):
            for j in range(3):
                f[size - 11 + j][i] = True
                f[i][size - 11 + j] = True
    return f


def _read_format(mat, size):
    c1, c2 = _fmt_coords(size)
    for coords in (c1, c2):
        v = 0
        for i, (r, c) in enumerate(coords):
            v |= (mat[r][c] & 1) << (14 - i)
        if v in _FORMAT_TABLE:
            return _FORMAT_TABLE[v]
    return None


def _unmask(mat, size, mask):
    def fn(i, j):
        if mask == 0: return (i + j) % 2 == 0
        if mask == 1: return i % 2 == 0
        if mask == 2: return j % 3 == 0
        if mask == 3: return (i + j) % 3 == 0
        if mask == 4: return (i // 2 + j // 3) % 2 == 0
        if mask == 5: return (i * j) % 2 + (i * j) % 3 == 0
        if mask == 6: return ((i * j) % 2 + (i * j) % 3) % 2 == 0
        return ((i + j) % 2 + (i * j) % 3) % 2 == 0
    return [[mat[i][j] ^ 1 if fn(i, j) else mat[i][j] for j in range(size)]
            for i in range(size)]


def _read_codewords(mat, size, version):
    """之字形取数据模块比特 → 码字（MSB 先）。"""
    f = _function_map(size, version)
    bits = []
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rng = range(size - 1, -1, -1) if upward else range(size)
        for i in rng:
            for c in (col, col - 1):
                if not f[i][c]:
                    bits.append(mat[i][c] & 1)
        upward = not upward
        col -= 2
    cw = []
    for i in range(0, len(bits) - 7, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        cw.append(b)
    return cw


def _deinterleave(cw, blocks):
    lens = []
    for nb, dc in blocks:
        lens += [dc] * nb
    out = [[] for _ in lens]
    idx = 0
    for i in range(max(lens)):
        for b in range(len(lens)):
            if i < lens[b]:
                out[b].append(cw[idx]); idx += 1
    flat = []
    for blk in out:
        flat += blk
    return flat


def _parse(data_cw, version):
    bits = []
    for b in data_cw:
        for j in range(7, -1, -1):
            bits.append((b >> j) & 1)

    def take(n, pos):
        v = 0
        for k in range(n):
            v = (v << 1) | bits[pos + k]
        return v, pos + n

    AL = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    pos, total = 0, len(bits)
    out = bytearray()
    while pos + 4 <= total:
        mode, pos = take(4, pos)
        if mode == 0:
            break
        if mode == 0b0001:            # 数字
            nb = 10 if version <= 9 else 12
            ln, pos = take(nb, pos)
            while ln >= 3 and pos + 10 <= total:
                v, pos = take(10, pos); out += b"%03d" % v; ln -= 3
            if ln == 2 and pos + 7 <= total:
                v, pos = take(7, pos); out += b"%02d" % v
            elif ln == 1 and pos + 4 <= total:
                v, pos = take(4, pos); out += b"%01d" % v
        elif mode == 0b0010:          # 字母数字
            nb = 9 if version <= 9 else 11
            ln, pos = take(nb, pos)
            while ln >= 2 and pos + 11 <= total:
                v, pos = take(11, pos)
                out += (AL[v // 45] + AL[v % 45]).encode(); ln -= 2
            if ln == 1 and pos + 6 <= total:
                v, pos = take(6, pos); out += AL[v].encode()
        elif mode == 0b0100:          # 字节
            nb = 8 if version <= 9 else 16
            ln, pos = take(nb, pos)
            for _ in range(ln):
                if pos + 8 > total:
                    break
                v, pos = take(8, pos); out.append(v)
        else:
            # 汉字(1000)/ECI(0111) 等未支持 → 该段放弃，整体判失败
            return None
    return bytes(out)


def decode_matrix(grid) -> Optional[bytes]:
    """n×n 的 0/1 矩阵（1=暗模块）→ payload bytes；不支持/失败 → None。"""
    size = len(grid)
    if size == 0 or any(len(r) != size for r in grid):
        return None
    if (size - 17) % 4 != 0:
        return None
    version = (size - 17) // 4
    if not (MIN_VERSION <= version <= MAX_VERSION):
        return None
    fmt = _read_format(grid, size)
    if fmt is None:
        return None
    ec_bits, mask = fmt
    key = (version, _EC_ORDER[ec_bits])
    if key not in _BLOCKS:
        return None
    um = _unmask(grid, size, mask)
    cw = _read_codewords(um, size, version)
    return _parse(_deinterleave(cw, _BLOCKS[key][1]), version)


def _payload_score(b: bytes) -> int:
    """打分：flag 形状 > 纯可打印；无法打印 → -1。"""
    if not b:
        return -1
    if _FLAG_RE.search(b):
        return 1000 + len(b)
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    if printable < len(b) * 0.95:
        return -1
    return printable


def rows_to_grid(rows: Sequence[int], size: int, msb_first: bool, dark_is_one: bool):
    grid = []
    for x in rows:
        row = [((x >> (size - 1 - c)) if msb_first else (x >> c)) & 1 for c in range(size)]
        if not dark_is_one:
            row = [1 - b for b in row]
        grid.append(row)
    return grid


def decode_rows(rows: Sequence[int]) -> Optional[bytes]:
    """整数行列表 → payload。自动试 {MSB/LSB 位序} × {暗=1/暗=0} 四种组合。"""
    n = len(rows)
    if (n - 17) % 4 != 0 or not (MIN_VERSION <= (n - 17) // 4 <= MAX_VERSION):
        return None
    if any(x < 0 or x.bit_length() > n for x in rows):
        return None
    best, best_score = None, -1
    for msb in (True, False):
        for dark1 in (True, False):
            try:
                got = decode_matrix(rows_to_grid(rows, n, msb, dark1))
            except Exception:  # noqa: BLE001 - 单组合失败不影响其它组合
                continue
            if not got:
                continue
            s = _payload_score(got)
            if s > best_score:
                best, best_score = got, s
    return best if best_score > 0 else None


def extract_rows(text: str) -> Optional[List[int]]:
    """纯整数文本（可含空白/逗号/换行分隔）→ 整数列表；夹杂非数字内容 → None。"""
    stripped = re.sub(r"[\s,;]+", " ", str(text or "")).strip()
    if not stripped:
        return None
    toks = stripped.split(" ")
    if not all(re.fullmatch(r"[+-]?\d+", t) for t in toks):
        return None          # 含非整数 token → 不是「纯数字矩阵」附件
    return [int(t) for t in toks]


def run(params: dict) -> Optional[bytes]:
    """见模块 docstring 的接口说明。"""
    rows = params.get("rows")
    if rows is None:
        text = params.get("text")
        if text is None and params.get("path"):
            p = str(params["path"])
            if not os.path.isfile(p) or os.path.getsize(p) > 2 * 1024 * 1024:
                return None
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except Exception:  # noqa: BLE001
                return None
        if text is None:
            return None
        rows = extract_rows(text)
    if not rows:
        return None
    return decode_rows([int(x) for x in rows])
