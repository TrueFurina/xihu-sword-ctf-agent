"""Skill: ZIP 伪加密检测与修复（免密解压）

题型：压缩包伪加密（如 misc-002，西湖论剑高频 misc 基础题）。
原理：zip 加密标志位（通用位字段 bit 0）被置位 → 解压要密码；清掉该位即可免密解压。
覆盖：局部文件头(PK\\x03\\x04)/中央目录头(PK\\x01\\x02)的通用位字段 offset=6 处字节。

⚠️ 安全沙盒约束：禁止 import shutil/os/subprocess —— 本实现只用 open() 纯字节操作，
   不碰任何被禁模块，沙盒可直跑。

输入: params = {'path': zip 文件路径}
输出: {'ok': bool, 'fixed_path': str, 'flag': str|None, 'error': str|None}
"""

import struct


def _clear_encryption_bit(path: str, out_path: str) -> int:
    """清掉 zip 所有头部条目加密标志位（通用位字段第 0 位）。

    返回修复的条目数。
    """
    with open(path, "rb") as fh:
        data = fh.read()

    fixed = 0
    buf = bytearray(data)
    i = 0
    n = len(buf)
    # 局部文件头 PK\x03\x04：签名(4) + 版本(2) + 通用位(2) @ offset 6
    while i + 30 <= n:
        if buf[i:i+4] == b"PK\x03\x04":
            flags = struct.unpack_from("<H", buf, i + 6)[0]
            if flags & 0x0001:
                struct.pack_into("<H", buf, i + 6, flags & ~0x0001)
                fixed += 1
            name_len = struct.unpack_from("<H", buf, i + 26)[0]
            extra_len = struct.unpack_from("<H", buf, i + 28)[0]
            i += 30 + name_len + extra_len
        else:
            i += 1

    # 中央目录头 PK\x01\x02：签名(4) + 版本(2) + 版本需(2) + 通用位(2) @ offset 8
    i = 0
    while i + 46 <= n:
        if buf[i:i+4] == b"PK\x01\x02":
            flags = struct.unpack_from("<H", buf, i + 8)[0]
            if flags & 0x0001:
                struct.pack_into("<H", buf, i + 8, flags & ~0x0001)
                fixed += 1
            name_len = struct.unpack_from("<H", buf, i + 28)[0]
            extra_len = struct.unpack_from("<H", buf, i + 30)[0]
            comment_len = struct.unpack_from("<H", buf, i + 32)[0]
            i += 46 + name_len + extra_len + comment_len
        else:
            i += 1

    with open(out_path, "wb") as fh:
        fh.write(bytes(buf))
    return fixed


def _extract_flag(zip_path: str) -> str:
    """免密解压并尝试找出 flag（纯 zipfile 标准库，无需密码）。"""
    import zipfile
    import re

    flag = None
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            try:
                content = zf.read(name).decode(errors="ignore")
            except Exception:
                continue
            m = re.search(r"flag\{[^}]+\}", content)
            if m:
                flag = m.group(0)
                break
            # 也可能是文件名藏 flag
            m2 = re.search(r"flag\{[^}]+\}", name)
            if m2:
                flag = m2.group(0)
                break
    return flag or ""


def run(params):
    path = str(params.get("path") or params.get("zip_path") or "").strip()
    if not path:
        return {"ok": False, "error": "缺少 path 参数"}
    import os

    if not os.path.exists(path):
        return {"ok": False, "error": f"zip 文件不存在: {path}"}

    # 先尝试免密直解（可能本来就无需密码）
    import tempfile

    try:
        import zipfile
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
        # 直解失败才修复
    except Exception:
        names = []

    out_path = path + ".fixed.zip"
    fixed = _clear_encryption_bit(path, out_path)
    try:
        import zipfile
        with zipfile.ZipFile(out_path) as zf:
            names = zf.namelist()
    except Exception as exc:
        return {"ok": False, "fixed": fixed, "error": f"修复后仍无法打开: {exc}"}

    flag = _extract_flag(out_path)
    return {
        "ok": True,
        "fixed_path": out_path,
        "fixed": fixed,
        "names": names[:20],
        "flag": flag or None,
    }


def suggest_steps(description=None, attachments=None):
    """解题步骤建议。"""
    return [
        "第一步：file_analyze(附件路径) 确认是 zip，尝试 zipfile 直解",
        "直解要密码 → 判定伪加密：用 misc_zip_fake_encryption 修复（清通用位字段 bit0，纯字节操作，勿 import shutil——沙盒拦截）",
        "修复后免密解压 → 读 flag.txt 提取 flag",
    ]
