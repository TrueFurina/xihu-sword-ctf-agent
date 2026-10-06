"""rev_const_compare — 静态逆向「常量比对」型 flag 求解（确定性，零 LLM）。

适用题型（presolve 确定性求解 · reverse 类）
------------------------------------------
二进制把**用户输入经一次可逆变换后**与**内嵌常量数组**比对（`strcmp`/`strncmp`/
`memcmp`/逐元素循环）。本 skill 用 `objdump` 反汇编 + 常量/变换自动提取，
**反演该变换**还原 flag。命中的候选由 sha256 / 题面 flag_pattern 硬门把关，
无把握一律不返回（不谎报）。

已实现的三类变换（均来自实测真题）：
  1. ``xor_const``   —— 输入整体 XOR 单字节常量 后 strcmp 常量数组。
       CSAW-Quals 2023 **whataxor** → ``csawctf{0ne_sheeP_1wo_sheWp_2hree_5heeks...xor}``。
  2. ``subst_table`` —— 附件内经 2 字节/项替换表 (from→to) 逐字节映射 后 strncmp 常量。
       CSAW-Quals 2017 **tablez** → ``flag{t4ble_l00kups_ar3_b3tter_f0r_m3}``。
  3. ``tree_index``  —— 常量数组被视为二叉查找树（左子 2i+1 / 右子 2i+2），
       函数返回「字符在树中的下标」，再与下标数组比对。
       CSAW-Quals 2019 **beleaf** → ``flag{we_beleaf_in_your_re_future}``。

依赖：系统 ``objdump``（mingw-w64 自带）；无则返回 None（不谎报）。
诚实口径：本 skill 只做**确定性静态求解**，命中仍由 sha256/flag_pattern 校验；
「可确定性攻破」仅限此类「常量比对」范式，不可外推到通用逆向（多数 rev 仍需人/angr）。
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import subprocess
from typing import Dict, List, Optional, Tuple

_SIZE = {"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8}

_OBJDUMP_CANDIDATES = (
    "objdump",
    r"D:/miniconda3_new/Library/mingw-w64/bin/objdump.exe",
    "objdump.exe",
)

_IMM_STORE = re.compile(r"mov\s+(BYTE|WORD|DWORD|QWORD) PTR \[rbp-(0x[0-9a-f]+)\],(0x[0-9a-f]+)")
_MOVABS = re.compile(r"movabs\s+(\w+),(0x[0-9a-f]+)")
_MOV_R2S = re.compile(r"mov\s+(BYTE|WORD|DWORD|QWORD) PTR \[rbp-(0x[0-9a-f]+)\],(\w+)")
_XOR_IMM = re.compile(r"\bxor\s+al,(0x[0-9a-f]+)")
_MOV_ESI = re.compile(r"\bmov\s+esi,(0x[0-9a-f]+)")
_LEA_RIP = re.compile(r"lea\s+\w+,\[rip\+0x[0-9a-f]+\]\s+#\s+([0-9a-f]+)(?:\s+<([^>]+)>)?")
_LEA_SCALE = re.compile(r"lea\s+\w+,\[rax\*(4|8)\+0x0\]")
_FUNC_HDR = re.compile(r"^([0-9a-f]+) <([^>]+)>:")
_FLAG_RE = re.compile(rb"[A-Za-z0-9_]{1,12}\{[^}\s\x00-\x1f]{3,120}\}")


# --------------------------------------------------------------------------
# ELF 段表 / 反汇编
# --------------------------------------------------------------------------
def _sections(b: bytes) -> Optional[List[Tuple[str, int, int, int]]]:
    """返回 [(name, addr, offset, size)]（仅 ELF64 可加载段）。"""
    if len(b) < 64 or b[:4] != b"\x7fELF" or b[4] != 2:
        return None
    try:
        e_shoff = struct.unpack_from("<Q", b, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", b, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", b, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", b, 0x3E)[0]
    except struct.error:
        return None
    raw = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + 40 > len(b):
            break
        nameoff, typ, _flags, addr, offset, size = struct.unpack_from("<IIQQQQ", b, off)
        raw.append((nameoff, typ, addr, offset, size))
    if not raw:
        return None
    str_off = raw[e_shstrndx][3] if e_shstrndx < len(raw) else 0
    out = []
    for nameoff, typ, addr, offset, size in raw:
        if not addr or not size:
            continue
        end = b.find(b"\x00", str_off + nameoff) if str_off else -1
        name = b[str_off + nameoff:end].decode("latin-1", "replace") if end > 0 else ""
        out.append((name, addr, offset, size))
    return out or None


def _v2o(secs: List[Tuple[str, int, int, int]], va: int) -> Optional[int]:
    for _name, addr, offset, size in secs:
        if addr <= va < addr + size:
            return offset + (va - addr)
    return None


def _sec_span(secs: List[Tuple[str, int, int, int]], va: int) -> Optional[int]:
    for _name, addr, _offset, size in secs:
        if addr <= va < addr + size:
            return addr + size
    return None


def _disasm(path: str) -> Optional[str]:
    for exe in _OBJDUMP_CANDIDATES:
        try:
            r = subprocess.run(
                [exe, "-d", "-M", "intel", path],
                capture_output=True, timeout=90,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0 and r.stdout:
            return r.stdout.decode("utf-8", "replace")
    return None


def _functions(asm: str) -> List[Dict]:
    funcs: List[Dict] = []
    cur: Optional[Dict] = None
    for line in asm.splitlines():
        m = _FUNC_HDR.match(line.strip())
        if m:
            if cur:
                funcs.append(cur)
            cur = {"addr": m.group(1), "name": m.group(2), "lines": []}
        elif cur is not None:
            cur["lines"].append(line)
    if cur:
        funcs.append(cur)
    return funcs


# --------------------------------------------------------------------------
# 栈上常量数组 / 变换提取
# --------------------------------------------------------------------------
def _stack_const_array(lines: List[str]) -> bytes:
    """从一段函数反汇编中还原「栈上常量字节串」（按栈偏移从数组头到尾）。

    支持 ``mov BYTE/WORD/DWORD PTR [rbp-X],imm`` 与 ``movabs reg,imm`` + ``mov [rbp-X],reg``。
    取**从最大偏移开始的最长连续段**（数组头在 rbp-最大偏移；不连续即停，
    避免把 canary（[rbp-0x8]）等无关槽并入）。
    """
    slots: Dict[int, bytes] = {}
    last_movabs: Dict[str, Tuple[int, int]] = {}  # reg -> (value, line_idx)
    for idx, line in enumerate(lines):
        m = _MOVABS.search(line)
        if m:
            last_movabs[m.group(1)] = (int(m.group(2), 16), idx)
            continue
        m = _IMM_STORE.search(line)
        if m:
            sz = _SIZE[m.group(1)]
            off = int(m.group(2), 16)
            val = int(m.group(3), 16) & ((1 << (8 * sz)) - 1)
            slots[off] = val.to_bytes(sz, "little")
            continue
        m = _MOV_R2S.search(line)
        if m and m.group(3) in last_movabs:
            val, midx = last_movabs[m.group(3)]
            # 🔴 仅当 movabs 紧邻本次存储（≤4 行且中间无 call，防寄存器被 call/其他写覆盖
            #    造成的「假常量」——2026-10-07 tablez 实测：mov [rbp-0xc8],rax 中的 rax
            #    实为 strlen 返回值，误采会污染数组）。
            if idx - midx <= 4 and not any("call" in lines[k] for k in range(midx + 1, idx)):
                sz = _SIZE[m.group(1)]
                off = int(m.group(2), 16)
                slots[off] = (val & ((1 << (8 * sz)) - 1)).to_bytes(sz, "little")
    if not slots:
        return b""
    order = sorted(slots, reverse=True)
    # 🔴 取**最长连续段**（不能只取「最大偏移起」——tablez 实测 [rbp-0xd0] 处有一个
    #    孤立的 8 字节 0，会遮蔽真正的 38 字节常量数组）。
    best = b""
    i = 0
    while i < len(order):
        run = bytearray()
        expect = order[i]
        j = i
        while j < len(order) and order[j] == expect:
            blk = slots[order[j]]
            run += blk
            expect = order[j] - len(blk)
            j += 1
        if len(run) > len(best):
            best = bytes(run)
        i = j if j > i else i + 1
    return best


def _xor_keys(lines: List[str]) -> List[int]:
    keys = []
    for line in lines:
        m = _XOR_IMM.search(line)
        if m:
            keys.append(int(m.group(1), 16) & 0xFF)
        m = _MOV_ESI.search(line)
        if m:
            keys.append(int(m.group(1), 16) & 0xFF)
    seen, out = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _cmp_function(asm: str) -> Optional[Dict]:
    for fn in _functions(asm):
        blob = "\n".join(fn["lines"])
        if re.search(r"call\s+[0-9a-f]+ <(strcmp|strncmp|memcmp)@plt>", blob):
            return fn
    return None


# --------------------------------------------------------------------------
# 检测器
# --------------------------------------------------------------------------
def _candidate_xor_const(asm: str) -> List[bytes]:
    fn = _cmp_function(asm)
    if not fn:
        return []
    arr = _stack_const_array(fn["lines"]).rstrip(b"\x00")
    if len(arr) < 6:
        return []
    out = [arr]  # key = 0（恒等）
    for k in _xor_keys(asm.splitlines()):
        out.append(bytes(c ^ k for c in arr))
    return out


def _candidate_subst_table(asm: str, secs, b: bytes) -> List[bytes]:
    fn = _cmp_function(asm)
    if not fn:
        return []
    blob = asm  # 🔴 替换表符号（trans_tbl）可能定义在别的函数（如 get_tbl_entry）→ 全文搜索
    arr = _stack_const_array(fn["lines"]).rstrip(b"\x00")
    if len(arr) < 6:
        return []
    cands = []
    for m in re.finditer(_LEA_RIP, blob):
        sym = (m.group(2) or "").lower()
        if not re.search(r"tbl|tab|table|sbox|s_box", sym):
            continue
        va = int(m.group(1), 16)
        off = _v2o(secs, va)
        if off is None:
            continue
        pairs = b[off:off + 1024]
        inv: Dict[int, int] = {}
        ok = 0
        for i in range(0, len(pairs) - 1, 2):
            frm, to = pairs[i], pairs[i + 1]
            if frm == 0 and to == 0:
                break
            # 🔴 首次出现优先（setdefault）：表后可能紧跟其它数据产生「伪 from→to」，
            #    覆盖式赋值会污染真映射（2026-10-07 tablez 实测：'u' 被覆写成 '.'）。
            inv.setdefault(to, frm)
            ok += 1
        if ok < 8:
            continue
        cand = bytes(inv.get(c, ord("?")) for c in arr)
        cands.append(cand)
    return cands


def _candidate_tree_index(asm: str, secs, b: bytes) -> List[bytes]:
    lines = asm.splitlines()
    addr_by_scale: Dict[int, int] = {}
    for idx, line in enumerate(lines):
        m = _LEA_SCALE.search(line)
        if not m:
            continue
        scale = int(m.group(1))
        for j in range(idx, min(idx + 4, len(lines))):
            m2 = _LEA_RIP.search(lines[j])
            if m2:
                addr_by_scale[scale] = int(m2.group(1), 16)
                break
    a_addr = addr_by_scale.get(4)
    t_addr = addr_by_scale.get(8)
    if a_addr is None or t_addr is None or t_addr <= a_addr:
        return []
    a_off, t_off = _v2o(secs, a_addr), _v2o(secs, t_addr)
    t_end = _sec_span(secs, t_addr)
    if a_off is None or t_off is None or t_end is None:
        return []
    n_target = (t_end - t_addr) // 8
    n_arr = (t_addr - a_addr) // 4
    if not (1 <= n_target <= 4096) or not (1 <= n_arr <= 65536):
        return []
    try:
        arr = list(struct.unpack_from("<%di" % n_arr, b, a_off))
        tgt = list(struct.unpack_from("<%dq" % n_target, b, t_off))
    except struct.error:
        return []
    if any(not (0 <= t < n_arr) for t in tgt):
        return []
    return [bytes((arr[t] & 0xFF) for t in tgt)]


# --------------------------------------------------------------------------
# 校验 / 入口
# --------------------------------------------------------------------------
def _sha256_hex(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()


def _verify(cand: bytes, sha256: Optional[str], pattern: Optional[str]) -> bool:
    if sha256:
        return _sha256_hex(cand) == sha256.strip().lower()
    if pattern:
        try:
            return re.search(pattern.encode(), cand) is not None
        except re.error:
            return False
    return bool(_FLAG_RE.search(cand))


def solve(path: str, sha256: Optional[str] = None, pattern: Optional[str] = None) -> Optional[bytes]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as fh:
            b = fh.read()
    except OSError:
        return None
    asm = _disasm(path)
    if not asm:
        return None
    secs = _sections(b)
    cands: List[bytes] = []
    if secs:
        cands += _candidate_subst_table(asm, secs, b)
        cands += _candidate_tree_index(asm, secs, b)
    cands += _candidate_xor_const(asm)
    for cand in cands:
        if cand and _verify(cand, sha256, pattern):
            return cand
    return None


def run(params: dict) -> Optional[bytes]:
    """params = {'path': ELF 路径, 'sha256': 可选真值(64 hex), 'pattern': 可选 flag 正则}。"""
    path = params.get("path")
    if not path:
        return None
    return solve(str(path), params.get("sha256"), params.get("pattern"))
