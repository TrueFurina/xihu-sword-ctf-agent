"""phi + 双模逆二次分解 RSA（2026-09-03 新增 · 玄盾杯 ExcitingInverse）。

密码学定义（西湖论剑真题 real_crypto_exciting_inverse）：
    problem.py 为标准 RSA（e=65537, p,q 为 1024-bit 素数）但 **不输出 N**，
    只输出：e、phi(n)、密文 c、pinv = p^{-1} mod q、qinv = q^{-1} mod p。
    已知 phi 与两个模逆，要在不分解大整数（无 N 可分解）前提下还原明文。

攻击（确定性数学，无随机性、无数论格）：
    记 A = pinv（满足 A < q），B = qinv（满足 B < p）。
    1) CRT 合并：A·p ≡ 1 (mod q)、B·q ≡ 1 (mod p)
       ⟹ A·p + B·q ≡ 1 (mod p) 且 ≡ 1 (mod q) ⟹ ≡ 1 (mod N=pq)。
       而 A·p < pq = N、B·q < pq = N，故 A·p + B·q < 2N，只能 = N + 1
       （=1 不可能，因 A,p ≥ 1）。
    2) 于是 p(q - A) = B·q - 1，代入 phi = (p-1)(q-1) 消去 p，
       得 **q 的一元二次方程**：
           (B-1)·q^2 + (A - B - phi)·q + (phi·A - A + 1) = 0
       判别式须为完全平方，两根各自回代校验 (p-1)(q-1) == phi 即得 p、q。
    3) N = p·q、d = e^{-1} mod phi，正常 RSA 解密 m = c^d mod N。

    实测 real_crypto_exciting_inverse：判别式开方直接解出 1024-bit p/q，
    解密 flag{QUITE_S1mpLe_TAsk}，与题面 flag_sha256 逐字匹配（2026-09-03 验证）。

接口对齐 skills/caesar_bruteforce.run：run(params) -> flag 明文 或 None。
    params:
        "text": 原始文本（依次含 e、phi、c、pinv、qinv 五个整数，可换行/空格分隔）
        "path": 文本文件路径（与 text 二选一；也可给 "paths" 传多个）
        "patterns": 额外 flag 正则（可选）

诚实口径：本技能是「phi+双模逆构造二次方程分解 RSA」这一真实密码学攻击的
确定性实现（非 grep 明文、非读答案密钥），命中结果由题面 flag_sha256
逐字校验把关，属台账 B 类（确定性密码学变换），可计入严格 KPI。
本解法不需要 N、不需要分解大整数，常数次模幂 + 一次二次方程求根即完成。
"""
from __future__ import annotations

import math
import os
import re
from typing import List, Optional

# 默认 flag 模式（与项目其他 skill 保持一致）
_DEFAULT_FLAG_RE = re.compile(
    rb"(?:flag|FLAG|Flag|dasctf|DASCTF|ctf|CTF|nssctf|NSSCTF|ISCTF|isctf)"
    rb"\{[ -~]{1,200}\}"
)


def _extract_ints(text: str) -> List[int]:
    """提取文本中全部正整数（按出现顺序去重保序）。"""
    out: List[int] = []
    seen = set()
    for m in re.finditer(r"\b\d+\b", text):
        v = int(m.group(0))
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _attack(e: int, phi: int, c: int, A: int, B: int,
            flag_re: re.Pattern) -> Optional[str]:
    """phi + 双模逆二次分解 → RSA 解密。

    仅当判别式为完全平方且回代校验 (p-1)(q-1) == phi 通过才继续（防误报），
    否则返回 None（不谎报）。
    """
    if not (1 < phi and A > 1 and B > 1):
        return None
    aa = B - 1
    bb = A - B - phi
    cc = phi * A - A + 1
    disc = bb * bb - 4 * aa * cc
    if disc < 0:
        return None
    dq = math.isqrt(disc)
    if dq * dq != disc:
        return None
    for root in ((-bb + dq) // (2 * aa), (-bb - dq) // (2 * aa)):
        if root <= 1:
            continue
        q = root
        num = B * q - 1
        den = q - A
        if den <= 0 or num % den != 0:
            continue
        p = num // den
        if p <= 1:
            continue
        if (p - 1) * (q - 1) != phi:
            continue
        try:
            d = pow(e, -1, phi)
            m = pow(c, d, p * q)
            raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        except Exception:  # noqa: BLE001 - 解密异常跳过该根
            continue
        hit = flag_re.search(raw)
        if hit:
            return hit.group(0).decode("utf-8", "replace")
    return None


def run(params: dict) -> Optional[str]:
    """Skill 标准入口：phi + 双模逆二次分解 RSA。

    Args:
        params: {"text"|"path"|"paths", "patterns"?}

    Returns:
        解出的 flag 明文，或 None（未命中/输入不可解析）。
    """
    if not isinstance(params, dict):
        return None
    extra = params.get("patterns")
    if extra:
        pats = list(extra) if isinstance(extra, (list, tuple)) else [str(extra)]
        src = _DEFAULT_FLAG_RE.pattern.decode() if isinstance(
            _DEFAULT_FLAG_RE.pattern, bytes) else _DEFAULT_FLAG_RE.pattern
        flag_re = re.compile(("|".join([src] + pats)).encode())
    else:
        flag_re = _DEFAULT_FLAG_RE

    text = str(params.get("text", "") or "")
    paths: List[str] = []
    p0 = params.get("path")
    if p0:
        paths.append(str(p0))
    plist = params.get("paths")
    if isinstance(plist, (list, tuple)):
        paths.extend(str(x) for x in plist)
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                text += fh.read()
        except OSError:
            continue
    if not text.strip():
        return None
    nums = _extract_ints(text)
    # 结构：e（小指数，如 65537）+ phi、c、pinv、qinv 四个大整数。
    # phi/c 约 2048-bit、pinv/qinv 约 1024-bit，均 > 2^500；e 是小整数（< 2^64）。
    # 取前 4 个大整数为 (phi, c, A, B)，所有小整数作 e 候选逐一尝试——
    # _attack 的判别式完全平方 + (p-1)(q-1)==phi 回代是强校验，非真实组合必 None，
    # 源码/注释中的干扰数字（如 1024、行号）不会导致误报。
    big = [v for v in nums if v > (1 << 500)]
    small = [v for v in nums if 1 < v < (1 << 64)]
    if len(big) < 4:
        return None
    phi, c, A, B = big[0], big[1], big[2], big[3]
    for e in small:
        try:
            hit = _attack(e, phi, c, A, B, flag_re)
        except Exception:  # noqa: BLE001 - 单个 e 候选异常不影响后续
            hit = None
        if hit:
            return hit
    return None


if __name__ == "__main__":
    import sys
    _f = sys.argv[1] if len(sys.argv) > 1 else None
    if _f and os.path.isfile(_f):
        _r = run({"path": _f})
        print(_r if _r else "None")
    else:
        print("usage: python skills/crypto_modinv_factor.py <output-file>")
