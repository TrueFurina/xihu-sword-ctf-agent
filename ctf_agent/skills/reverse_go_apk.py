"""reverse_go_apk skill：Go 程序/APK 逆向深挖（正式赛 REVERSE-01/02 沉淀）。

0 解出根因④工具链补强：REVERSE-01（gogogo.exe——Go 程序）strings 无 flag、
REVERSE-02（MirrorShield.apk）strings 无 flag。本 skill 提供深挖路径：
1. Go 二进制：长度前缀字符串提取（Go 字符串是 length-prefixed UTF-8——
   比普通 strings 提取更全）+ .gopclntab 符号线索 + 只读数据段扫描
2. APK：zipfile 列 classes.dex/AndroidManifest——dex 字符串提取——
   找 flag 线索（dex 里 flag 可能被混淆/分割）
"""

import os
import re
import struct
import zipfile

FLAG_RE = re.compile(rb"(?:DASCTF|flag)\{[^}\s]{3,}\}")


def _go_strings(data: bytes, max_hits: int = 30) -> list:
    """Go 长度前缀字符串提取（Go 字符串：varint 长度 + UTF-8 内容）。"""
    hits = []
    i = 0
    n = len(data)
    while i < n - 2:
        # varint 长度（1 字节小长度为主——Go 字符串大多 <128）
        ln = data[i]
        if 3 <= ln <= 64 and i + 1 + ln <= n:
            chunk = data[i + 1:i + 1 + ln]
            if all(32 <= b < 127 or b in (0x0a, 0x0d, 0x09) for b in chunk) and b"flag" in chunk.lower() or FLAG_RE.search(chunk):
                hits.append(chunk)
                if len(hits) >= max_hits:
                    break
        i += 1
    return hits


def _go_symbols(data: bytes, max_hits: int = 20) -> list:
    """Go 符号线索（.gopclntab 附近——函数名/常量名——flag 线索）。"""
    idx = data.find(b"\xfb\xff\xff\xff\x00\x00")  # gopclntab magic
    if idx < 0:
        idx = data.find(b"go:buildid")
    if idx < 0:
        return []
    window = data[max(0, idx - 2000): idx + 8000]
    return [s for s in re.findall(rb"[\x20-\x7e]{6,}", window) if b"flag" in s.lower() or b"ctf" in s.lower()][:max_hits]


def _apk_analysis(path: str) -> dict:
    """APK 分析：列 classes.dex/AndroidManifest——dex 字符串提取找 flag。"""
    out = {"dex_files": [], "manifest_flags": []}
    try:
        z = zipfile.ZipFile(path)
        dexes = [n for n in z.namelist() if n.endswith(".dex")]
        out["dex_files"] = dexes
        for n in dexes:
            try:
                d = z.read(n)
                flags = FLAG_RE.findall(d)
                if flags:
                    out["manifest_flags"].extend([f.decode("utf-8", errors="ignore") for f in flags])
                # dex 字符串池（小端长度前缀）
                for m in re.finditer(rb"(?:DASCTF|flag)\{[^}\s]{3,}\}", d):
                    out["manifest_flags"].append(m.group(0).decode("utf-8", errors="ignore"))
            except Exception:  # noqa: BLE001
                pass
        for n in z.namelist():
            if "AndroidManifest" in n:
                try:
                    mf = z.read(n)
                    flags = FLAG_RE.findall(mf)
                    out["manifest_flags"].extend([f.decode("utf-8", errors="ignore") for f in flags])
                except Exception:  # noqa: BLE001
                    pass
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
    return out


def run(params: dict) -> dict:
    """skill 统一入口。params: path/kind（go|apk）。"""
    path = params.get("path", "")
    kind = params.get("kind", "")
    out = {"ok": False, "method": f"reverse_{kind}"}
    if not path or not os.path.exists(path):
        out["error"] = "path 不存在"
        return out
    data = open(path, "rb").read()

    if kind == "apk" or path.lower().endswith(".apk"):
        info = _apk_analysis(path)
        out.update(info)
        out["flags"] = info["manifest_flags"]
    else:  # go / 二进制
        out["go_strings"] = [s.decode("utf-8", errors="ignore") for s in _go_strings(data)]
        out["go_symbols"] = [s.decode("utf-8", errors="ignore") for s in _go_symbols(data)]
        out["flags"] = [f.decode("utf-8", errors="ignore") for f in FLAG_RE.findall(data)]
    if out.get("flags"):
        out["ok"] = True
        out["flag"] = out["flags"][0]
    return out


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) > 1:
        p = sys.argv[1]
        k = sys.argv[2] if len(sys.argv) > 2 else ""
        print(json.dumps(run({"path": p, "kind": k}), ensure_ascii=False, indent=1))
