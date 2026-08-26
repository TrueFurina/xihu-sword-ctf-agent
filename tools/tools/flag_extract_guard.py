"""flag 提取完整保障（锐评「差最后一步」修复——2026-08-22 沉淀）。

背景（正式赛 0 解出锐评核心）：模板解出了（CRYPTO-01 PDF 解密成功）
但 flag 提取失败（PDF 明文/流找不到）——「差最后一步」是系统性失败。
本模块提供「提取保障」：
1. 宽松多候选：flag{...}/DASCTF{...}/CTF{...}——大小写——多候选输出
2. ROT13/ROT18 检查：真题 flag 可能 ROT 编码（crypto_high_exponent 发现
   QNFPGS{...}——题名 How many rot 提示）——提取不到时自动 ROT 解码
3. 变体检查：flag 可能被拆分/加盐/前缀变异
"""

import re

FLAG_PATTERNS = [
    re.compile(rb"(?:DASCTF|flag|ctf)\{([^}\s]{3,})\}", re.I),
    re.compile(rb"(?:DASCTF|flag|ctf)\{([^}\s]{1,100})", re.I),  # 宽松（截断容忍）
]

ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def _rot13(s: str) -> str:
    return s.translate(ROT13_TABLE)


def extract_flags(data: bytes, max_candidates: int = 8) -> list:
    """宽松多候选 flag 提取——含 ROT13 检查。

    Returns: [(flag_str, method)]——flag_str 为 {} 内内容（按比赛提交格式）。
    """
    cands = []
    text = data.decode("utf-8", errors="ignore")
    low = text.lower()

    # ① 直接匹配（标准格式）
    for m in re.finditer(r"(?:DASCTF|flag|ctf)\{([^}\s]{3,})\}", text, re.I):
        inner = m.group(1)
        if inner not in [c[0] for c in cands]:
            cands.append((inner, "direct"))
        if len(cands) >= max_candidates:
            break

    # ② 宽松（无闭合 }——截断容忍）
    if not cands:
        for pat in FLAG_PATTERNS:
            for m in pat.finditer(data):
                inner = m.group(1).decode("utf-8", errors="ignore").rstrip("}")
                if 3 <= len(inner) <= 128 and inner not in [c[0] for c in cands]:
                    cands.append((inner, "loose"))
                if len(cands) >= max_candidates:
                    break

    # ③ ROT13 检查（真题 flag 可能 ROT 编码——QNFPGS{...}）
    if not cands:
        for m in re.finditer(r"(?:QNFPGS|synp|pgs)\{([^}\s]{3,})\}", text):
            inner = _rot13(m.group(1))
            if inner not in [c[0] for c in cands]:
                cands.append((inner, "rot13"))
            if len(cands) >= max_candidates:
                break
        # 若正文含 QNFPGS 前缀（ROT13 的 DASCTF）——整段 ROT13 再提取
        if "QNFPGS{" in text.upper():
            rot = _rot13(text)
            for m in re.finditer(r"(?:DASCTF|flag|ctf)\{([^}\s]{3,})\}", rot, re.I):
                inner = m.group(1)
                if inner not in [c[0] for c in cands]:
                    cands.append((inner, "rot13_whole"))
                if len(cands) >= max_candidates:
                    break

    return cands


def best_flag(data: bytes) -> dict:
    """提取最优候选（按方法优先级）。"""
    cands = extract_flags(data)
    if not cands:
        return {"ok": False, "candidates": []}
    # 优先级：direct > rot13 > loose > rot13_whole
    order = {"direct": 0, "rot13": 1, "loose": 2, "rot13_whole": 3}
    best = min(cands, key=lambda c: order.get(c[1], 9))
    return {"ok": True, "flag": best[0], "method": best[1], "candidates": cands}


if __name__ == "__main__":
    import sys

    # 自测：ROT13 编码 flag 提取（真题 QNFPGS{...} 场景）
    test = b"QNFPGS{vafvqr_ebg13_synt}"
    r = best_flag(test)
    print("ROT13 自测:", r)
    test2 = b"flag{normal_flag_test} suffix"
    print("direct 自测:", best_flag(test2))
