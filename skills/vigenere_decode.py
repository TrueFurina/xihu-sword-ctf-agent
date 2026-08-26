"""Vigenère 解码（key 字符当移位，字母位推进）—— 2022安网杯 crypto1 模式。

解码链：flag.txt 可能是 base64/八进制/hex 编码 → 提取 key 和 data →
Vigenère 解密（key 字符当移位，仅字母位推进，数字/连字符保留）。
"""
from __future__ import annotations
import re, os, base64


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Vigenère 解密：key 字符当移位（仅字母位推进）。"""
    out = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)].upper()) - ord('A')
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return ''.join(out)


def run(params: dict) -> dict:
    """skill 入口：params 可含 text/key/path。"""
    text = params.get("text", "")
    key = params.get("key", "")
    path = params.get("path", "")
    if not text and path:
        if os.path.isfile(path):
            text = open(path, encoding="utf-8").read()
    if not text:
        return {"ok": False, "error": "需要 text 或 path"}

    # 尝试从 text 提取 key/data（flag.txt 格式："key:... data:..."）
    km = re.search(r"key\s*[:：=]\s*(\S+)", text, re.I)
    dm = re.search(r"data\s*[:：=]\s*(\S+)", text, re.I)
    if km and dm:
        key = km.group(1)
        text = dm.group(1)
    # 也试 base64 / 八进制提取
    for enc, dec in (("base64", lambda x: base64.b64decode(x).decode(errors="ignore")),
                     ("octal", lambda x: ''.join(chr(int(n, 8)) for n in x.split() if n.isdigit())),
                     ("hex", lambda x: bytes.fromhex(re.sub(r'\s+','',x)).decode(errors="ignore"))):
        try:
            dec_text = dec(text.strip())
            if 'key' in dec_text.lower() and 'data' in dec_text.lower():
                km2 = re.search(r"key\s*[:：=]\s*(\S+)", dec_text, re.I)
                dm2 = re.search(r"data\s*[:：=]\s*(\S+)", dec_text, re.I)
                if km2 and dm2:
                    key, text = km2.group(1), dm2.group(1)
                    break
        except Exception:
            pass

    if not key:
        return {"ok": False, "error": "需要 key 参数（Vigenère）"}

    plain = vigenere_decrypt(text, key)
    m = re.search(r"flag\{[^}]+\}", plain, re.I)
    return {
        "ok": True, "decoded": plain, "key": key,
        "flag_candidate": m.group(0) if m else "",
    }
