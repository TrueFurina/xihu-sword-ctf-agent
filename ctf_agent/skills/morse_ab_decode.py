"""A/B 字符串 → 摩斯电码解码（classicCrypto 类题）。

解码链：A/B（A=划/B=点）→ 摩斯 → 字母/数字/标点文本。
再配合单表替换（quipqiup/hill-climbing）或直接找 UUID 结构。
"""
from __future__ import annotations

MORSE = {
    ".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G",
    "....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N",
    "---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U",
    "...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z",
    "-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5",
    "-....":"6","--...":"7","---..":"8","----.":"9",
    ".-.-.-":".","--..--":",","..--..":"?","-.-.--":"!","-..-.":"/",
    "-.--.":"(","-.--.-":")",".-...":"&","---...":":","-.-.-.":";",
    "-...-":"=",".-.-.":"+","-....-":"-","..--.-":"_",".-..-.":'"',
    ".----.":"'","...-..-":"$",".--.-.":"@",
}


def decode(text: str, dot_char: str = "B", dash_char: str = "A") -> str:
    """A/B 序列解码。dot_char/dash_char 指定哪个字符是点/划。

    默认 A=划/B=点（classicCrypto 实测方向）。解不出时换 A=点/B=划。
    """
    import re
    groups = [g for g in re.split(r"\s+", text.strip()) if g]
    out = []
    for g in groups:
        m = "".join("." if c == dot_char else "-" for c in g)
        out.append(MORSE.get(m, "?"))
    return "".join(out)


def run(params: dict) -> dict:
    """skill 入口：params 可含 text（A/B 串）或 path（文件路径）。"""
    text = params.get("text", "")
    path = params.get("path", "")
    if not text and path:
        import os
        if os.path.isfile(path):
            text = open(path, encoding="utf-8").read()
    if not text:
        return {"ok": False, "error": "需要 text 或 path 参数"}

    for dot, dash in (("B", "A"), ("A", "B")):
        try:
            out = decode(text, dot, dash)
        except Exception:
            continue
        # 有效输出 = 未知字符少
        unknown = out.count("?")
        if unknown < len(out) * 0.3:
            import re
            uuid = re.search(r"[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}", out)
            return {
                "ok": True,
                "decoded": out,
                "unknown": unknown,
                "uuid_candidate": uuid.group(0) if uuid else "",
                "hint": "单表替换可用 quipqiup/频率分析；UUID 结构为 flag 主体",
            }
    return {"ok": False, "error": "摩斯解码失败（两种方向都试过）"}
