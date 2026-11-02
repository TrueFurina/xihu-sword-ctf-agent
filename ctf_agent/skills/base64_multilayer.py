"""Skill: Base64 多层自动解码器

自动检测并解码多层 Base64/Base32/Base16 编码。
适用于 CTF crypto/misc 题型中多层编码的 flag。

输入: params = {"text": "编码后的字符串"}
输出: 解码后的明文
"""

import base64


def run(params):
    """多层解码：自动检测 Base64/32/16 并逐层解码。

    Args:
        params: {"text": "编码字符串"}

    Returns:
        解码后的明文
    """
    text = str(params.get("text", ""))
    max_layers = 20

    for _ in range(max_layers):
        decoded = _try_decode(text)
        if decoded is None or decoded == text:
            break
        text = decoded
        if "flag{" in text.lower() or "dasctf{" in text.lower():
            break

    return text


def _try_decode(text):
    """按**特异性从高到低**尝试：Base16(hex) → Base32 → Base64。

    ⚠️ 顺序是功能性的，不是随意的（2026-11-01 审计）。

    原顺序是 Base64 → Base32 → Base16，实测有个硬缺陷：
    **hex 的字符集是 base64 的子集**（0-9a-f 全在 base64 字母表里），
    所以纯 hex 串会先被 Base64 分支"成功"解码成乱码并提前 return，
    永远走不到 Base16 分支。

        输入 "666c61677b6865787d"
        Base64 先试 → '뮜�^��...'（乱码，但 isprintable 检查通过了一部分）
        正确的 Base16 → 'flag{hex}'

    修复：把判定条件**最严格**的 Base16 放最前（全 hex 字符 + 偶数长度），
    其次 Base32（大写字母表 + 长度约束），最后 Base64（最宽松）。
    """
    text = text.strip()
    if not text:
        return None

    # Base16 (hex)
    try:
        if all(c in "0123456789abcdefABCDEF" for c in text) and len(text) % 2 == 0:
            result = bytes.fromhex(text).decode("utf-8", errors="replace")
            if result and all(c.isprintable() or c in "\n\r\t" for c in result):
                return result
    except Exception:
        pass

    # Base32
    try:
        padded = text + "=" * ((8 - len(text) % 8) % 8) if len(text) % 8 else text
        result = base64.b32decode(padded.upper()).decode("utf-8", errors="replace")
        if result and all(c.isprintable() or c in "\n\r\t" for c in result):
            return result
    except Exception:
        pass

    # Base64
    try:
        padded = text + "=" * ((4 - len(text) % 4) % 4) if len(text) % 4 else text
        result = base64.b64decode(padded).decode("utf-8", errors="replace")
        if result and all(c.isprintable() or c in "\n\r\t" for c in result):
            return result
    except Exception:
        pass

    return None
