"""zip_filename_chain_decode skill：多层嵌套 zip 文件名链解码。

场景：附件是 N 层嵌套 zip，每层只有一个 zip，最终是 flag.txt（可能是陷阱），
真实 flag 藏在文件名链的编码里（如反转 + base32/64/58/62/36/hex/摩斯）。

关键坑（来自 10663 解压缩）：文件名链需要**从尾到头**拼接再解码，
且最终 flag.txt 内容可能是陷阱（如 'DASCTF{ni_cai?}'）。

用法（skill 调用）：
    params = {'zip_path': '...zip', 'max_layers': 100}
    result = zip_filename_chain_decode(params)  -> {'flag': ..., 'chain': [...]}
"""

import base64
import binascii
import itertools
import os
import re
import struct
import tempfile
import zipfile
import zlib

_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def _b32(s: str) -> bytes:
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s.upper() + pad)


def _b64(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s + pad)


def _b58(s: str) -> bytes:
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for c in s:
        n = n * 58 + alpha.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _b62(s: str) -> bytes:
    alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    n = 0
    for c in s:
        n = n * 62 + alpha.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _b36(s: str) -> bytes:
    n = int(s, 36)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _morse(s: str) -> str:
    out = []
    for tok in re.split(r"\s+", s.strip()):
        out.append(_MORSE.get(tok, ""))
    return "".join(out)


def _try_decoders(s: str) -> list:
    """尝试多种编码，返回所有能解出可读文本的候选。"""
    results = []
    for name, fn in [
        ("base32", lambda x: _b32(x)),
        ("base64", lambda x: _b64(x)),
        ("hex", lambda x: binascii.unhexlify(x)),
        ("base58", lambda x: _b58(x)),
        ("base62", lambda x: _b62(x)),
        ("base36", lambda x: _b36(x)),
    ]:
        try:
            b = fn(s)
            if b:
                results.append((name, b))
        except Exception:
            pass
    return results


def _is_readable(b: bytes) -> bool:
    if not b:
        return False
    printable = sum(1 for c in b if 32 <= c < 127 or c in (10, 13))
    return printable / len(b) > 0.85


def _zip_encrypted(zf: zipfile.ZipFile) -> bool:
    """检测 zip 是否有加密条目（通用位字段 bit0）。"""
    try:
        return any(i.flag_bits & 0x1 for i in zf.infolist())
    except Exception:
        return False


def _brute_force_zip_password(zf: zipfile.ZipFile) -> bytes:
    """爆破加密 zip 密码（2026-08-22 赛后补强：xuanhun_ezip 层 2 卡点）。

    密码空间：5 位数字(00000-99999) → 6 位数字 → 常见词（含 Readme 线索词）。
    关键坑：zipfile 对 deflate 加密文件密码错误时抛 **zlib.error** 而非
    RuntimeError——异常捕获不全会中断爆破（赛后手工分析实证）。

    返回密码 bytes；10 万+9 十万+词表全失败返回 b""（调用方据此标记未解出）。
    """
    target = ""
    for i in zf.infolist():
        if i.flag_bits & 0x1:
            target = i.filename
            break
    if not target:
        return b""

    def _candidates():
        for i in range(100000):
            yield f"{i:05d}"
        for i in range(100000, 1000000):
            yield f"{i:06d}"
        for w in ("admin", "123456", "password", "flag", "ctf", "gogo", "zip",
                  "test", "root", "666888", "888888", "666666", "123123",
                  "abc123", "qwerty", "111111", "000000"):
            yield w

    for pwd in _candidates():
        pb = pwd.encode()
        try:
            zf.read(target, pwd=pb)
            return pb
        except (RuntimeError, zipfile.BadZipFile, zlib.error, EOFError):
            continue
    return b""


def zip_filename_chain_decode(params: dict) -> dict:
    """解压多层 zip，收集文件名链，尝试解码出 flag。"""
    zip_path = params.get("zip_path", "")
    max_layers = int(params.get("max_layers", 200))
    if not zip_path or not os.path.exists(zip_path):
        return {"ok": False, "error": "zip_path not found"}

    workdir = tempfile.mkdtemp(prefix="zipchain_")
    chain = []
    cur = os.path.abspath(zip_path)
    layer = 0
    flags = []

    try:
        while layer < max_layers:
            layer += 1
            if not zipfile.is_zipfile(cur):
                break
            with zipfile.ZipFile(cur) as z:
                names = z.namelist()
                # 2026-08-22 赛后补强：真加密 zip（xuanhun_ezip 层2卡点）——
                # 检测加密 → 爆破密码（5/6位数字+词表，捕获 zlib.error）→ 带密码读取
                pwd = b""
                if _zip_encrypted(z):
                    pwd = _brute_force_zip_password(z)
                    if not pwd:
                        return {
                            "ok": False,
                            "error": f"第 {layer} 层 zip 加密密码爆破失败（5/6位数字+常见词）",
                            "layer": layer,
                            "chain": chain,
                        }
                # 找 .zip 条目作为下一层：同时兼容 10663 单一zip链 与 xuanhun
                # 多条目加密 zip（下一层 zip + Readme.txt 并存）
                zip_names = [n for n in names if n.lower().endswith(".zip")]
                if zip_names:
                    nxt = zip_names[0]
                    chain.append(os.path.splitext(nxt)[0])
                    cur = os.path.join(workdir, f"l{layer}.zip")
                    with open(cur, "wb") as f:
                        f.write(z.read(nxt, pwd=pwd))
                else:
                    # 最后一层：读所有条目内容，匹配 flag（文件名或内容均可）
                    for n in names:
                        try:
                            data = z.read(n, pwd=pwd)
                        except (RuntimeError, zipfile.BadZipFile, zlib.error, EOFError):
                            continue
                        txt = data.decode("utf-8", errors="replace")
                        m = re.search(r"(?:DASCTF|flag|ctf)\{[^}\s]{4,}\}", txt, re.I)
                        if m:
                            flags.append(m.group(0))
                        elif len(data) < 500:
                            flags.append(txt)
                    break

        # 文件名链解码：从尾到头拼接（10663 关键坑）
        # ⚠️ 必须用完整链（含单字符段如 'I'，不要过滤长度），完整反转 + base32 才能正确解码
        # 但要去除外层目录结构名（含 / 或 \ 的 tempdir/xxx）与末尾 flag.zip 名
        code_chain = [
            c for c in chain
            if "/" not in c and "\\" not in c
            and c.lower() not in ("flag", "flag.txt")
        ]
        reversed_chain = "".join(code_chain[::-1])
        forward_chain = "".join(code_chain)
        candidates = []
        for label, src in [("reversed", reversed_chain), ("forward", forward_chain)]:
            for enc_name, b in _try_decoders(src):
                candidates.append((label, enc_name, b))

        flag = ""
        for label, enc_name, b in candidates:
            txt = b.decode("utf-8", errors="replace")
            m = re.search(r"(?:DASCTF|flag|ctf)\{[^}\s]{4,}\}", txt, re.I)
            if m:
                flag = m.group(0)
                break
            if _is_readable(b):
                flag = txt.strip()
                break

        return {
            "ok": True,
            "flag": flag,
            "chain": chain,
            "chain_count": len(chain),
            "decoded_candidates": [
                {"dir": label, "enc": enc, "text": b.decode("utf-8", errors="replace")[:120]}
                for label, enc, b in candidates[:5]
            ],
            "last_layer_files": flags,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        # mkdtemp 临时目录交由系统临时区自动管理（AST 白名单禁 os.remove/rmdir/shutil）
        pass


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return zip_filename_chain_decode(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="多层 zip 文件名链解码")
    parser.add_argument("--zip", required=True, help="zip 附件路径")
    args = parser.parse_args()
    import json

    print(json.dumps(zip_filename_chain_decode({"zip_path": args.zip}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
