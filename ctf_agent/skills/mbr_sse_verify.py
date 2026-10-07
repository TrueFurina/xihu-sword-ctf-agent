"""realism-MBR：Master Boot Record 内 SSE(`andps`+`psadbw`) 字节校验链反推。

背景（CSAW-Quals 2017 rev `realism`，512B MBR，题面要求 `qemu-system-i386`）：
MBR 在实模式下开启 SSE（置 CR0.EM=0/MP=1、CR4.OSFXSR|OSXMMEXCPT），把用户输入的
20 字节存于低内存，校验逻辑：

    cmpl "flag", buf            ; 前 4 字节必须 "flag"
    xmm0 = movaps buf+4         ; body = 输入[4:20]（16 字节）
    xmm0 = pshufd xmm0, imm     ; 按 imm 置换 4 个 dword
    xmm5 = movaps <load_base>   ; 初值 = 代码首 16 字节
    si = 8
  loop:
    xmm2 = xmm0 & mask[si]      ; mask 逐字节移位，每轮把 shuf 的第 (k-1) 与 (k+7) 位清零
    xmm5 = psadbw xmm5, xmm2    ; 链式：上轮结果作本轮第一操作数
    edi  = (lo<<16)|hi          ; psadbw 低 8 字节 SAD 与高 8 字节 SAD
    cmp  edi, exp[si-1]         ; 8 项 u32 期望表
    si--; jnz loop

本 skill 不做通用反汇编，而是按上述固定结构**自动提取**初值/期望表/置换立即数后，
把 16 字节 body 拆成两个独立的 8 字节子系统（shuf 低半只进 lo 方程、高半只进 hi 方程），
用「逐轮递推 + 总和约束」确定性地还原，再用完整 psadbw 链仿真复核。

诚实口径：仅覆盖「单表 andps 掩码 + 链式 psadbw + 常量期望表」这一子集；
命中属 presolve 静态直出，不计入 LLM 自主解题率，也不得外推为『rev 类可解』。
"""
from __future__ import annotations

import struct
from typing import List, Optional

MBR_BASE = 0x7C00          # 标准 MBR 加载地址
_ANDPS = b"\x0f\x54"       # andps xmm, m128
_PSADBW = b"\x0f\xf6"      # psadbw
_PSHUFD = b"\x66\x0f\x70"  # pshufd
_CMP_EDX = b"\x66\x67\x3b"  # cmp 0x????????(%edx), %edi


def is_mbr_sse_verify(data: bytes) -> bool:
    """廉价判据：512B + MBR 引导签名 55 AA + 含 andps/psadbw/pshufd 三件套。"""
    if not isinstance(data, (bytes, bytearray)) or len(data) != 512:
        return False
    if data[510:512] != b"\x55\xaa":
        return False
    return _ANDPS in data and _PSADBW in data and _PSHUFD in data


def extract(data: bytes):
    """定位并返回 (init16, exp8, pshufd_imm, mask_addr, exp_addr)。

    init16: xmm5 初值 = 代码加载基址处的前 16 字节。
    exp8  : 8 项 32 位期望值（si=1..8 顺序，即 mem[exp_addr + (si-1)*4]）。
    """
    ia = data.find(_ANDPS)
    if ia < 0:
        return None
    mask_addr = struct.unpack_from("<H", data, ia + 3)[0] if ia + 5 <= len(data) else None
    ic = data.find(_CMP_EDX)
    if ic < 0 or ic + 8 > len(data):
        return None
    exp_addr = struct.unpack_from("<I", data, ic + 4)[0]
    ip = data.find(_PSHUFD)
    if ip < 0 or ip + 5 > len(data):
        return None
    pshufd_imm = data[ip + 4]
    base = MBR_BASE
    init16 = data[0:16]
    exp = []
    for si in range(1, 9):
        o = exp_addr + (si - 1) * 4 - base
        if o < 0 or o + 4 > len(data):
            return None
        exp.append(struct.unpack_from("<I", data, o)[0])
    if mask_addr is None:
        return None
    return init16, exp, pshufd_imm, mask_addr, exp_addr


def _pshufd_inverse(imm: int):
    """返回 dst dword 索引 -> src dword 索引 的映射（pshufd 语义）。"""
    return [(imm >> (2 * i)) & 3 for i in range(4)]


_PRINT_LO, _PRINT_HI = 0x20, 0x7E


def _is_printable(buf) -> bool:
    return all(_PRINT_LO <= b <= _PRINT_HI for b in buf)


def _pick(cands):
    """在候选集中确定唯一解。

    SAD（绝对差和）非单射：某些实例会有多于一个 8 字节子解产生**完全相同**的期望表。
    CTF flag 必为可打印文本，故以「可打印 ASCII」作域约束消歧：
      唯一候选 → 直取；多候选 → 取其中唯一可打印者；仍不唯一 → None（保持诚实）。
    """
    if not cands:
        return None
    if len(cands) == 1:
        return list(cands[0])
    pr = [list(c) for c in cands if _is_printable(c)]
    if len(pr) == 1:
        return pr[0]
    return None


def _solve_half(init8: List[int], tgt: List[int]):
    """核心递推：解一个 8 字节子系统。

    tgt[k-1] = 第 k 轮（k=1..8）目标 SAD 值。掩码结构假定「每轮清零第 k-1 位」。
    返回所有满足的 8 字节解。
    """
    c = init8
    lo1lo, lo1hi = tgt[0] & 0xFF, tgt[0] >> 8
    sols = []
    for X0 in range(256):
        # 第 2 轮方程直出总和 T
        T = tgt[1] - lo1hi - abs(lo1lo - X0)
        if T < 0:
            continue
        for X1 in range(256):
            X = [X0, X1] + [None] * 6
            prev = tgt[1]
            ok = True
            for k in range(3, 9):
                Xk = abs((prev & 0xFF) - X0) + abs((prev >> 8) - X1) + T - tgt[k - 1]
                if Xk < 0 or Xk > 255:
                    ok = False
                    break
                X[k - 1] = Xk
                prev = tgt[k - 1]
            if not ok or sum(X[2:8]) != T:
                continue
            # 第 1 轮：对初值 8 字节的 SAD（第 0 位被清零）
            lhs = abs(c[0] - 0) + sum(abs(c[i] - X[i]) for i in range(1, 8))
            if lhs != tgt[0]:
                continue
            sols.append(X)
    return sols


def _check_mask(data: bytes, mask_addr: int) -> bool:
    """校验掩码表确为「逐轮移位单字节清零」结构。

    第 k 轮（k=1..8，si=9-k）读取 16 字节窗口 data[mask_addr+si : +16]；
    须每字节 ∈ {0x00,0xff}，且 0x00 恰好落在索引 k-1 与 k+7。
    """
    for k in range(1, 9):
        si = 9 - k
        o = mask_addr + si - MBR_BASE
        if o < 0 or o + 16 > len(data):
            return False
        win = data[o:o + 16]
        zeros = {i for i, b in enumerate(win) if b == 0x00}
        if any(b not in (0x00, 0xFF) for b in win):
            return False
        if zeros != {k - 1, k + 7}:
            return False
    return True


def solve(data: bytes) -> Optional[bytes]:
    """返回解出的 flag（bytes）；无法唯一确定则返回 None。"""
    ext = extract(data)
    if not ext:
        return None
    init16, exp, pshufd_imm, mask_addr, exp_addr = ext
    if not _check_mask(data, mask_addr):
        return None
    # edi = (lo<<16)|hi  -> 高 16 位为 lo，低 16 位为 hi
    loT = [exp[8 - k] >> 16 for k in range(1, 9)]        # lo_k
    hiT = [exp[8 - k] & 0xFFFF for k in range(1, 9)]     # hi_k
    Hset = _solve_half(init16[0:8], loT)
    Lset = _solve_half(init16[8:16], hiT)
    H = _pick(Hset)
    L = _pick(Lset)
    if H is None or L is None:
        return None
    shuf = bytes(H) + bytes(L)                           # shuf = [d2,d3,d1,d0] 语义
    # 逆置换：body dword[j] = shuf 中承载 dword j 的那一段
    inv = _pshufd_inverse(pshufd_imm)                    # shuf dword i 来自 src dword inv[i]
    if sorted(inv) != [0, 1, 2, 3]:
        return None                                      # pshufd 非置换（有重复源）→ 不可逆
    src = [None] * 4
    for i, s in enumerate(inv):
        src[s] = shuf[4 * i:4 * i + 4]
    body = b"".join(src)
    flag = b"flag" + body
    return flag


def simulate(data: bytes, flag: bytes) -> bool:
    """用完整 psadbw 链仿真复核给定 flag（用于自检/测试）。

    复刻 MBR 校验：前 4 字节 "flag"、body 16 字节经 pshufd 后与 8 项期望表逐轮比对。
    """
    ext = extract(data)
    if not ext:
        return False
    init16, exp, pshufd_imm, _mask_addr, _exp_addr = ext
    if len(flag) != 20 or flag[:4] != b"flag":
        return False
    body = bytes(flag[4:20])
    d = [body[0:4], body[4:8], body[8:12], body[12:16]]
    perm = _pshufd_inverse(pshufd_imm)
    shuf = list(b"".join(d[perm[i]] for i in range(4)))
    xmm5 = list(init16)
    for k in range(1, 9):
        M = list(shuf)
        M[k - 1] = 0
        M[k + 7] = 0
        lo = sum(abs(xmm5[j] - M[j]) for j in range(0, 8))
        hi = sum(abs(xmm5[j] - M[j]) for j in range(8, 16))
        xmm5 = [(lo & 0xFF), (lo >> 8) & 0xFF, 0, 0, 0, 0, 0, 0,
                (hi & 0xFF), (hi >> 8) & 0xFF, 0, 0, 0, 0, 0, 0]
        if ((lo << 16) | hi) != exp[8 - k]:
            return False
    return True


def run(params):
    """统一 run(params) 接口：支持 {"path": ...} 与 {"raw": bytes|str}。"""
    if isinstance(params, (bytes, bytearray)):
        raw = bytes(params)
    elif isinstance(params, str):
        try:
            raw = open(params, "rb").read()
        except OSError:
            return None
    elif isinstance(params, dict):
        if params.get("path"):
            try:
                raw = open(params["path"], "rb").read()
            except OSError:
                return None
        elif params.get("raw") is not None:
            r = params["raw"]
            raw = r.encode("utf-8", "surrogatepass") if isinstance(r, str) else bytes(r)
        else:
            return None
    else:
        return None
    if not is_mbr_sse_verify(raw):
        return None
    return solve(raw)
