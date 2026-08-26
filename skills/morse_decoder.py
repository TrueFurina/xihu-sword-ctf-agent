"""Skill: 摩斯密码解码器

用途：解码摩斯密码点划序列（. 与 -）为明文
输入: {"text": "摩斯密码字符串"} 或 {"path": "文件路径"}
输出: 解码后的明文字符串
"""

import re

MORSE_TABLE = {
    '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
    '..-.': 'f', '--.': 'g', '....': 'h', '..': 'i', '.---': 'j',
    '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n', '---': 'o',
    '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't',
    '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y',
    '--..': 'z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9',
}


def run(params):
    """解码摩斯密码。

    Args:
        params: {"text": "点划序列"} 或 {"path": "文件路径"}

    Returns:
        解码后的明文字符串
    """
    text = params.get("text", "")
    if not text and params.get("path"):
        with open(params["path"], "r", encoding="utf-8") as f:
            text = f.read()
    if not text:
        return "无输入"

    # 提取点划序列（跳过注释/前缀）
    m = re.search(r'[.\-]{1,5}(?:[ /][.\-]{1,5})*', text)
    code = m.group(0) if m else text

    result = []
    for token in code.replace('/', ' ').split():
        if token in MORSE_TABLE:
            result.append(MORSE_TABLE[token])
        else:
            result.append('?')
    return ''.join(result)
