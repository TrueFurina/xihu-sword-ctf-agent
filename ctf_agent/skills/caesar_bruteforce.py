"""Skill: 凯撒密码暴力破解

对密文尝试全部 26 种位移，返回含 flag 的明文。
适用于 CTF crypto 题型中的凯撒密码。

输入: params = {"text": "密文"}
输出: 解出的明文或 None
"""

import string


def run(params):
    """凯撒暴力：26 种位移全遍历。

    Args:
        params: {"text": "密文"}

    Returns:
        含 flag 的明文，或所有位移中最可能的明文
    """
    cipher = str(params.get("text", ""))
    if not cipher:
        return None

    results = []
    for shift in range(26):
        plaintext = _caesar_shift(cipher, shift)
        results.append((shift, plaintext))
        if "flag{" in plaintext.lower() or "dasctf{" in plaintext.lower():
            return plaintext

    # 无 flag：返回最接近英文可读的结果（元音比例最高）
    best = max(results, key=lambda x: _score(x[1]))
    return best[1] if best else None


def _caesar_shift(text: str, shift: int) -> str:
    """凯撒位移解密（反向移位）。"""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def _score(text: str) -> float:
    """简单评分：元音比例（越高越可能是英文）。"""
    vowels = sum(1 for c in text.lower() if c in "aeiou")
    alpha = sum(1 for c in text if c.isalpha())
    return vowels / max(alpha, 1)


def suggest_steps(description=None, attachment_text=None):
    """给出解题步骤建议。"""
    return [
        "凯撒密码：26种位移暴力遍历",
        "检查每种位移的明文是否含 flag{ 或 DASCTF{",
        "无明确 flag 时取元音比例最高的结果",
    ]
