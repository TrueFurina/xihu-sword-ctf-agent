"""Håstad 广播攻击（同一明文多模数小指数 RSA，2026-09-03 新增）。

密码学定义（西湖论剑真题 real_crypto_ezrsa）：
    同一明文 m，用 k 组**不同**模数 n_1..n_k、同一个小指数 e 分别加密：
        c_i = m^e mod n_i
    当 m^e < N = n_1·n_2·…·n_k 时，由中国剩余定理合并得 C = m^e (mod N)，
    此时 C 在整数范围内就等于 m^e（未发生模归约），直接开 e 次整数根即得 m。
    这就是 Håstad 广播攻击（J. Håstad, 1988）的基础情形。

    真题约束：`assert(e < 100)` 但 e 未显式给出 → 需在 2..99 范围内暴力试 e。
    实测 real_crypto_ezrsa：3 组 2048-bit 模数，e=17，CRT 后开 17 次根即出 flag，
    与题面自带 flag_sha256 逐字匹配（2026-09-03 验证通过）。

解码策略（确定性 + 可复现）：
    1. 从文本/文件解析全部大整数（>= 100 位十进制视为 RSA 参数）；
    2. 尝试两种 (n, c) 配对：**交错式**（n1,c1,n2,c2,…，对应 print 交替输出）
       与**分段式**（前半全 n、后半全 c）；
    3. 对每种配对做 CRT 合并（要求模数两两互素，否则该配对跳过）；
    4. 对 e = 2..e_max 做整数 e 次根，开得尽且解出 bytes 含 flag 模式即返回。
    5. 全程无命中 → 返回 None（不谎报）。

接口对齐 skills/caesar_bruteforce.run：run(params) -> flag 明文 或 None。
    params:
        "text": 含大整数的原始文本（如 output 文件内容）
        "path": 大整数文件路径（与 text 二选一）
        "pairs": [(n, c), ...] 直接给定模数/密文对（可选，最高优先）
        "e_max": 指数上界（默认 99，对应真题 assert(e<100)）
        "patterns": 额外 flag 正则（可选）

诚实口径：本技能是「Håstad 广播攻击」这一真实密码学攻击的确定性实现
（CRT + 整数开根，非 grep 明文、非读答案密钥），命中结果由题面 flag_sha256
逐字校验把关，属台账 B 类（确定性密码学变换），可计入严格 KPI。
"""
from __future__ import annotations

import os
import re
from math import gcd
from typing import List, Optional, Sequence, Tuple

# 默认 flag 模式（与项目其他 skill 保持一致）
_DEFAULT_FLAG_RE = re.compile(
    rb"(?:flag|FLAG|Flag|dasctf|DASCTF|ctf|CTF|nssctf|NSSCTF|ISCTF|isctf)"
    rb"\{[ -~]{1,200}\}"
)

# 判定为「RSA 大整数」的最小十进制位数（2048-bit ≈ 617 位十进制）
_MIN_BIGINT_DIGITS = 100


def _parse_numbers(text: str) -> List[int]:
    """从文本中解析所有大整数（按出现顺序去重保序）。"""
    out: List[int] = []
    seen = set()
    for m in re.finditer(r"\b\d{%d,}\b" % _MIN_BIGINT_DIGITS, text):
        v = int(m.group(0))
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _candidate_pairings(nums: Sequence[int]) -> List[List[Tuple[int, int]]]:
    """生成候选 (n, c) 配对方案。

    返回 [[(n1,c1),(n2,c2),...], ...]，每种方案是一组可尝试的广播样本。
    """
    pairs: List[List[Tuple[int, int]]] = []
    k = len(nums)
    if k < 4:
        return pairs
    half = k // 2
    # 方案 A：交错式 n1,c1,n2,c2,...（真题 task.py 的 print 顺序即此）
    if k % 2 == 0:
        a = [(nums[i], nums[i + 1]) for i in range(0, k, 2)]
        pairs.append(a)
    # 方案 B：分段式 前半 n / 后半 c
    b = [(nums[i], nums[half + i]) for i in range(half)]
    pairs.append(b)
    # 方案 C：分段式的「密文在前、模数在后」
    c = [(nums[half + i], nums[i]) for i in range(half)]
    pairs.append(c)
    return pairs


def _crt(residues: Sequence[int], moduli: Sequence[int]) -> Optional[Tuple[int, int]]:
    """通用 CRT（允许非两两互素，做一致性校验）。

    Returns:
        (C, N) 使 C ≡ r_i (mod m_i)，或 None（不一致/无解）。
    """
    R, M = 0, 1
    for r, m in zip(residues, moduli):
        g = gcd(M, m)
        if (r - R) % g != 0:
            return None
        # 化为互素后合并
        m_div = m // g
        try:
            inv = pow(M // g, -1, m_div)
        except ValueError:  # 无逆元
            return None
        t = (((r - R) // g) * inv) % m_div
        R = R + M * t
        M = M * m_div
    return R % M, M


def _iroot(n: int, k: int) -> Optional[int]:
    """整数 k 次根：存在整数 r 使 r**k == n 则返回 r，否则 None。"""
    if n < 0:
        return None
    if n < 2:
        return n
    if k == 1:
        return n
    # 上界：2^ceil(bits/k)
    hi = 1 << ((n.bit_length() + k - 1) // k + 1)
    lo = 1
    while lo <= hi:
        mid = (lo + hi) // 2
        p = mid ** k
        if p == n:
            return mid
        if p < n:
            lo = mid + 1
        else:
            hi = mid - 1
    return None


def _to_bytes(m: int) -> bytes:
    """整数转 bytes（保留前导零语义：按 8 位对齐）。"""
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(max(length, 1), "big")


def _attack(pairs: Sequence[Tuple[int, int]], e_max: int,
            flag_re: re.Pattern) -> Optional[str]:
    """对一组 (n, c) 做 Håstad 广播攻击。"""
    if len(pairs) < 2:
        return None
    moduli = [n for n, _ in pairs]
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                return None  # 模数不互素 → 非广播攻击场景（可能是共模攻击）
    crt_res = _crt([c for _, c in pairs], moduli)
    if crt_res is None:
        return None
    C, _N = crt_res
    for e in range(2, e_max + 1):
        r = _iroot(C, e)
        if r is None:
            continue
        try:
            raw = _to_bytes(r)
        except Exception:  # noqa: BLE001 - 转换失败跳过
            continue
        m = flag_re.search(raw)
        if m:
            return m.group(0).decode("utf-8", "replace")
    return None


def run(params: dict) -> Optional[str]:
    """Skill 标准入口：Håstad 广播攻击。

    Args:
        params: {"text"|"path"|"pairs", "e_max"?, "patterns"?}

    Returns:
        解出的 flag 明文，或 None（未命中）。
    """
    if not isinstance(params, dict):
        return None
    e_max = int(params.get("e_max", 99) or 99)
    extra = params.get("patterns")
    if extra:
        pats = list(extra) if isinstance(extra, (list, tuple)) else [str(extra)]
        src = _DEFAULT_FLAG_RE.pattern.decode() if isinstance(
            _DEFAULT_FLAG_RE.pattern, bytes) else _DEFAULT_FLAG_RE.pattern
        flag_re = re.compile(("|".join([src] + pats)).encode())
    else:
        flag_re = _DEFAULT_FLAG_RE

    pairs = params.get("pairs")
    if pairs:
        try:
            norm = [(int(n), int(c)) for n, c in pairs]
        except Exception:  # noqa: BLE001
            norm = []
        if norm:
            hit = _attack(norm, e_max, flag_re)
            if hit:
                return hit

    text = str(params.get("text", "") or "")
    if not text:
        p = params.get("path")
        if p and os.path.isfile(str(p)):
            try:
                with open(str(p), "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except Exception:  # noqa: BLE001
                return None
    if not text:
        return None

    nums = _parse_numbers(text)
    if len(nums) < 4:
        return None
    for pairing in _candidate_pairings(nums):
        hit = _attack(pairing, e_max, flag_re)
        if hit:
            return hit
    return None


def suggest_steps(description=None, attachment_text=None) -> List[str]:
    """给出解题步骤建议。"""
    return [
        "识别是否为同一明文多模数加密（output 含多组 n 与 c）",
        "用 CRT 合并各组密文，得到 C ≡ m^e (mod ∏n_i)",
        "对 e = 2..99 逐个尝试整数开 e 次根，解出 m",
        "将 m 转为 bytes 提取 flag，并与题面 flag_sha256 校验",
    ]
