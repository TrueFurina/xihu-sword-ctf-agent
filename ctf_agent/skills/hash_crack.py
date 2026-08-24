"""Skill: 哈希弱密码爆破

自动检测 MD5/SHA1/SHA256 哈希并用常见弱口令字典爆破。
适用于 CTF crypto/misc 题型中的哈希破解。

输入: params = {"hash": "目标哈希值", "hashtype": "md5|sha1|sha256（可选）"}
输出: 破解出的明文或 None
"""

import hashlib

# 常见弱口令字典（CTF 高频）
COMMON_WORDS = [
    "admin", "password", "root", "123456", "12345678", "123456789",
    "qwerty", "abc123", "111111", "1234567", "password1", "admin123",
    "root123", "test", "guest", "user", "letmein", "welcome",
    "monkey", "dragon", "master", "login", "admin1", "pass",
    "pass123", "passwd", "changeme", "secret", "p@ssw0rd",
    "admin@123", "root@123", "toor", "administrator", "manager",
    "operator", "guest123", "default", "000000", "654321",
    "passw0rd", "P@ssword", "1q2w3e4r", "q1w2e3r4", "abc",
    "test123", "user123", "11111111", "88888888", "66666666",
]


def run(params):
    """哈希爆破：自动检测类型 + 常见口令字典。

    Args:
        params: {"hash": "目标哈希值", "hashtype": "md5|sha1|sha256（可选）"}

    Returns:
        破解出的明文或 None
    """
    target = str(params.get("hash", "")).strip().lower()
    if not target:
        return None

    # 自动检测哈希类型（按长度）
    hashtype = str(params.get("hashtype", "")).lower()
    if not hashtype:
        if len(target) == 32:
            hashtype = "md5"
        elif len(target) == 40:
            hashtype = "sha1"
        elif len(target) == 64:
            hashtype = "sha256"
        else:
            return None

    hash_func = getattr(hashlib, hashtype, None)
    if hash_func is None:
        return None

    for word in COMMON_WORDS:
        if hash_func(word.encode()).hexdigest() == target:
            return word

    # 扩展尝试：大小写变体
    for word in list(COMMON_WORDS):
        for variant in [word.upper(), word.capitalize(), word + "1", word + "123"]:
            if hash_func(variant.encode()).hexdigest() == target:
                return variant

    return None


def suggest_steps(description=None, attachment_text=None):
    """给出解题步骤建议。"""
    return [
        "识别哈希类型（MD5=32位hex, SHA1=40位, SHA256=64位）",
        "用常见弱口令字典爆破（admin/password/root/123456 等）",
        "flag格式通常为 flag{明文} 或直接提交明文",
    ]
