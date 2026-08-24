"""zip_fake_encryption skill：zip 伪加密破解（2026-08-22——疯狂刷题 8% 后补模板）。

场景：大量真实题是「伪加密 zip」（flag_bits bit0=1 标记加密但无密码——
zipfile 拒绝读取）。破解方法：检测 flag_bits 0x1 → 清除加密位 →
zipfile 正常读取 → 提取 flag。
覆盖：伪加密检测/修复/flag 提取 + 普通 zip 内容 flag 提取（无密码）。

用法：fast_solve('zip', path=...) 优先走本 skill——未解出再回退
zip_filename_chain_decode（zip 链解码）。
"""

import os
import re
import zipfile

FLAG_RE = re.compile(rb"(?:DASCTF|flag|ctf)\{([^}\s]{3,})\}", re.I)
ZIP_LOCAL_HEADER = b"PK\x03\x04"


def detect_fake_encryption(path: str) -> bool:
    """检测伪加密：本地文件头 flag_bits bit0=1（标记加密——但可能无密码）。"""
    try:
        with open(path, "rb") as f:
            head = f.read(26)
        if head[:4] != ZIP_LOCAL_HEADER:
            return False
        flag_bits = head[6]
        return bool(flag_bits & 0x1)
    except Exception:  # noqa: BLE001
        return False


def fix_fake_encryption(path: str, out_path: str) -> str:
    """清除伪加密位（flag_bits bit0 清 0）——写入修复 zip——可正常读取。"""
    data = open(path, "rb").read()
    out = bytearray(data)
    # 本地文件头 flag_bits（offset 6-7）——清除 bit0
    pos = 0
    while True:
        i = out.find(ZIP_LOCAL_HEADER, pos)
        if i < 0:
            break
        if i + 26 <= len(out):
            out[i + 6] = out[i + 6] & ~0x1  # 清加密位
        pos = i + 4
    # 中央目录头也清（0x02014b50）
    pos = 0
    while True:
        i = out.find(b"PK\x01\x02", pos)
        if i < 0:
            break
        if i + 26 <= len(out):
            out[i + 8] = out[i + 8] & ~0x1
        pos = i + 4
    with open(out_path, "wb") as f:
        f.write(bytes(out))
    return out_path


def _extract_flag_from_zip(path: str) -> list:
    """读取 zip 内全部文件——找 flag。"""
    flags = []
    try:
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                try:
                    c = z.read(name)
                    for m in FLAG_RE.finditer(c):
                        if m.group(1) not in [f[1] for f in flags]:
                            flags.append((name, m.group(1).decode("utf-8", errors="ignore")))
                    fn = name.encode("utf-8", errors="ignore")
                    for m in FLAG_RE.finditer(fn):  # 文件名也可能是 flag
                        if m.group(1) not in [f[1] for f in flags]:
                            flags.append((name, m.group(1).decode("utf-8", errors="ignore")))
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        pass
    return flags


def run(params: dict) -> dict:
    """skill 统一入口。params: path（zip 路径）。"""
    path = params.get("path", "")
    out = {"ok": False, "method": "zip_fake_encryption"}
    if not path or not os.path.exists(path):
        out["error"] = "path 不存在"
        return out

    fake = detect_fake_encryption(path)
    flags = []
    if fake:
        # 伪加密：清除位 → 正常读
        fixed = path + ".fixed"
        try:
            fix_fake_encryption(path, fixed)
            flags = _extract_flag_from_zip(fixed)
            os.remove(fixed)
            out["method"] = "zip_fake_encryption(fixed)"
        except Exception:  # noqa: BLE001
            flags = []
    if not flags:
        # 普通 zip（无密码）直接读
        flags = _extract_flag_from_zip(path)
        out["method"] = "zip_read"
    if flags:
        out["ok"] = True
        out["flag"] = flags[0][1]
        out["flags"] = flags
        out["file"] = flags[0][0]
    return out


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) > 1:
        print(json.dumps(run({"path": sys.argv[1]}), ensure_ascii=False, indent=1))
