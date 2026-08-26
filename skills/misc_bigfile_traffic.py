"""misc_bigfile_traffic skill：大文件/流量题快速解析（正式赛 MISC-01/02 沉淀）。

0 解出根因④工具链补强：16MB pcapng/449MB zip/9.7MB 附件包——
zipfile 全量遍历超时（中央目录读取慢）。本 skill 用：
1. mmap 分块扫描（大文件直接搜 flag 明文——不解析全部）
2. pcapng 轻量字符串提取（只读可打印 ASCII——跳过包解析）
3. 大 zip 中央目录直读（zipfile namelist 限时——跳过超大文件读内容）
"""

import mmap
import os
import re
import zipfile

FLAG_RE = re.compile(rb"(?:DASCTF|flag)\{[^}\s]{3,}\}")


def _mmap_scan(path: str, patterns: list = None, limit_mb: int = None) -> list:
    """mmap 分块扫描——大文件直接搜 flag 明文（不超时）。"""
    patterns = patterns or [b"flag{", b"DASCTF{", b"ctf{"]
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            found = []
            for pat in patterns:
                start = 0
                while True:
                    i = mm.find(pat, start)
                    if i < 0:
                        break
                    end = mm.find(b"}", i)
                    if 0 < end - i < 100:
                        found.append(mm[i:end + 1].decode("utf-8", errors="ignore"))
                    start = i + 1
                    if len(found) >= 20:
                        break
            return found
        finally:
            mm.close()


def _zip_central_dir(path: str, max_files: int = 300) -> list:
    """大 zip 中央目录直读——只列文件（不解压内容）——限文件数防超时。"""
    out = []
    try:
        z = zipfile.ZipFile(path)
        for i, info in enumerate(z.infolist()):
            if i >= max_files:
                break
            out.append((info.filename, info.file_size, bool(info.flag_bits & 0x1)))
            if info.file_size < 200_000 and not info.is_dir():
                try:
                    c = z.read(info.filename)
                    m = FLAG_RE.findall(c)
                    if m:
                        out.append(("FLAG", m[0].decode("utf-8", errors="ignore")))
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        pass
    return out


def run(params: dict) -> dict:
    """skill 统一入口。params: path/kind（pcapng|zip|attachment）/patterns。"""
    path = params.get("path", "")
    kind = params.get("kind", "")
    out = {"ok": False, "method": f"bigfile_{kind}"}
    if not path or not os.path.exists(path):
        out["error"] = "path 不存在"
        return out

    if kind in ("pcapng", "traffic", "pcap"):
        flags = _mmap_scan(path)
        out["flags"] = flags
        out["size_mb"] = round(os.path.getsize(path) / 1024 / 1024, 1)
        out["ok"] = bool(flags)
    elif kind in ("zip", "attachment"):
        central = _zip_central_dir(path)
        flags = [x[1] for x in central if x[0] == "FLAG"]
        out["central"] = [x for x in central if x[0] != "FLAG"][:20]
        out["flags"] = flags
        out["ok"] = bool(flags)
    else:
        # 默认：mmap 扫描 + 小文件 zip 中央目录
        flags = _mmap_scan(path)
        out["flags"] = flags
        out["ok"] = bool(flags)
    if out.get("flags"):
        out["flag"] = out["flags"][0]
    return out


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        import json

        p = sys.argv[1]
        k = sys.argv[2] if len(sys.argv) > 2 else ""
        print(json.dumps(run({"path": p, "kind": k}), ensure_ascii=False, indent=1))
