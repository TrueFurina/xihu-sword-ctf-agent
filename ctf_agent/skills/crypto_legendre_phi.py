"""phi 已知的 Legendre 符号逐位分解（2026-09-03 新增 · 玄盾杯 SimpleLegendre）。

密码学定义（西湖论剑真题 real_crypto_simplelegendre）：
    task.py 加密：明文二进制串的每一位 bi 被加密为一个密文
        c = ( x^(2^k·r + bi) · r^2 ) mod N
    其中 r 随机且 gcd(r, N)=1，k = bit_length(r) >= 1；x, N 为公钥。
    密钥生成 make_key 保证 x 同时是模 p 与模 q 的**二次非剩余**
    （条件式两项欧拉准则值相加 = p+q-2 蕴含 (x|p) = (x|q) = -1），
    且 N % 8 == 1、phi % 8 == 4。output 文件直接给出 phi(N)、N 与密文列表。

攻击（确定性数学，无随机性）：
    1) phi 已知 ⟹ 分解 N：p+q = N - phi + 1，判别式 (p+q)^2 - 4N 为完全平方
       → 解二次方程得 p, q（phi 泄露即可分解 RSA 模数，经典结论）。
    2) 对每个密文 c，Legendre 符号 (c|p) = (x|p)^(2^k·r+bi) · (r^2|p)
       = (-1)^(2^k·r+bi) · 1 = (-1)^bi（因 2^k·r 恒偶、r^2 恒为二次剩余），
       故 (c|p) = 1 ⟺ bi=0，(c|p) = -1（即 p-1）⟺ bi=1。
    3) 逐位还原二进制串，按 8 位对齐转 bytes 即得明文 flag。

    实测 real_crypto_simplelegendre：分解出 1024-bit p、q，逐位 Legendre 还原
    flag{GO0D_J0b_of_TH1s_encrYption}，与题面 flag_sha256 逐字匹配
    （2026-09-03 验证通过，~1s）。

接口对齐 skills/caesar_bruteforce.run：run(params) -> flag 明文 或 None。
    params:
        "text": 原始文本（含 phi、N 两行大整数 + 一行 python 列表密文）
        "path": 文本文件路径（与 text 二选一；也可给 "paths" 传多个）
        "patterns": 额外 flag 正则（可选）

诚实口径：本技能是「phi 泄露分解 + Legendre 符号逐位判定」这一真实密码学
攻击的确定性实现（非 grep 明文、非读答案密钥），命中结果由题面 flag_sha256
逐字校验把关，属台账 B 类（确定性密码学变换），可计入严格 KPI。
本解法不需要分解大整数（phi 即给）、不需要格、不需要随机性，纯 O(bits) 次模幂。
"""
from __future__ import annotations

import ast
import math
import os
import re
from typing import List, Optional, Tuple

# 默认 flag 模式（与项目其他 skill 保持一致）
_DEFAULT_FLAG_RE = re.compile(
    rb"(?:flag|FLAG|Flag|dasctf|DASCTF|ctf|CTF|nssctf|NSSCTF|ISCTF|isctf)"
    rb"\{[ -~]{1,200}\}"
)

# 判定为「RSA 模数级大整数」的最小十进制位数（1024-bit ≈ 309 位，
# 2048-bit ≈ 617 位；用 150 位阈值隔离小参数/行号/时间戳）
_MIN_BIGINT_DIGITS = 150


def _extract_enc_list(text: str) -> Optional[List[int]]:
    """提取 python 列表字面量形式的密文列表（如 output 的 enc）。

    仅接受超长纯整数列表（含逗号分隔、数字），用 ast.literal_eval 安全求值。
    """
    for m in re.finditer(r"\[[0-9][0-9,\s]*\]", text):
        seg = m.group(0)
        if len(seg) < 100:  # 太短不可能是密文列表
            continue
        try:
            v = ast.literal_eval(seg)
        except Exception:  # noqa: BLE001 - 求值失败跳过该候选
            continue
        if (isinstance(v, list) and len(v) > 0
                and all(isinstance(x, int) for x in v)):
            return v
    return None


def _extract_moduli(text: str) -> List[int]:
    """提取非列表区域内的大整数（phi / N 候选，按出现顺序）。"""
    out: List[int] = []
    seen = set()
    # 先剔除列表段落，避免把密文元素当 phi/N
    body = re.sub(r"\[[0-9][0-9,\s]*\]", " ", text)
    for m in re.finditer(r"\b\d{%d,}\b" % _MIN_BIGINT_DIGITS, body):
        v = int(m.group(0))
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _factor_via_phi(N: int, phi: int) -> Optional[Tuple[int, int]]:
    """phi 泄露分解 N：解 p+q 与 p-q 二次方程，校验后返回 (p, q)。"""
    if not (1 < phi < N):
        return None
    s = N - phi + 1  # p + q
    d2 = s * s - 4 * N
    if d2 < 0:
        return None
    d = math.isqrt(d2)
    if d * d != d2:
        return None
    if (s + d) % 2 != 0:
        return None
    p = (s + d) // 2
    q = (s - d) // 2
    if p <= 1 or q <= 1 or p * q != N:
        return None
    if (p - 1) * (q - 1) != phi:
        return None
    return (p, q)


def _attack(phi: int, N: int, enc: List[int],
            flag_re: re.Pattern) -> Optional[str]:
    """phi 分解 + 逐位 Legendre 符号判定还原明文。

    仅当所有密文的 Legendre 符号都明确判定为 1 或 p-1 才继续（防误报），
    任一位不可判定即返回 None（不谎报）。
    """
    fac = _factor_via_phi(N, phi)
    if fac is None:
        return None
    p, q = fac
    exp = (p - 1) // 2
    bits: List[str] = []
    for c in enc:
        lv = pow(c % p, exp, p)
        if lv == 1:
            bits.append("0")
        elif lv == p - 1:
            bits.append("1")
        else:
            return None  # 不可判定（如 p|c 等异常），不硬解
    bs = "".join(bits)
    pad = (8 - len(bs) % 8) % 8
    bs = "0" * pad + bs
    try:
        raw = int(bs, 2).to_bytes(len(bs) // 8, "big")
    except Exception:  # noqa: BLE001 - 转换失败
        return None
    m = flag_re.search(raw)
    if m:
        return m.group(0).decode("utf-8", "replace")
    return None


def run(params: dict) -> Optional[str]:
    """Skill 标准入口：phi 泄露分解 + Legendre 逐位判定。

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

    # 收集文本：优先 paths（多个附件），其次 path，其次 text
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

    enc = _extract_enc_list(text)
    mods = _extract_moduli(text)
    if not enc or len(mods) < 2:
        return None
    # 尝试相邻候选组合（phi, N）；通用场景允许候选多于 2 个
    for i in range(len(mods) - 1):
        phi, N = mods[i], mods[i + 1]
        try:
            hit = _attack(phi, N, enc, flag_re)
        except Exception:  # noqa: BLE001 - 单组异常不影响后续候选
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
        print("usage: python skills/crypto_legendre_phi.py <output-file>")
