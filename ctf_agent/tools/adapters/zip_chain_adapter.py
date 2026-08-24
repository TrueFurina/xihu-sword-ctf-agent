"""多层嵌套 zip 文件名链解码适配器（misc 解压类题）。

复盘来源：10663 解压缩 —— 38 层嵌套 zip，文件名链 2 字符编码（base32/64/58/62/36/摩斯/培根），
flag.txt 内是陷阱 flag（ni_cai?），真实 flag 在文件名链中。封装为自动脚本。

用法（主 Agent plan）：
    {"tool": "zip_chain_decode",
     "zip_path": "data/attachments/xxx.zip"}   # 起始 zip 路径
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import zipfile
from typing import Optional

from tools.base import ToolAdapter, ToolOutput

# 常见编码探测器：输入文件名链字符串，返回 (编码名, 解码结果) 或 None
def _try_decode_chain(chain: str) -> Optional[tuple]:
    """对文件名链尝试多种编码解码。"""
    s = chain.strip()
    if not s:
        return None
    candidates = []

    # base32（标准，去掉 padding 和 =）
    for c in (s, s.upper()):
        try:
            pad = "=" * ((8 - len(c) % 8) % 8)
            decoded = base64.b32decode(c + pad)
            candidates.append(("base32", decoded))
        except Exception:  # noqa: BLE001
            pass
    # base64
    for c in (s, s.upper()):
        try:
            pad = "=" * ((4 - len(c) % 4) % 4)
            decoded = base64.b64decode(c + pad)
            candidates.append(("base64", decoded))
        except Exception:  # noqa: BLE001
            pass
    # base36
    try:
        n = int(s, 36)
        candidates.append(("base36", n.to_bytes((n.bit_length() + 7) // 8, "big")))
    except Exception:  # noqa: BLE001
        pass
    # hex
    try:
        if re.fullmatch(r"[0-9a-fA-F]+", s):
            candidates.append(("hex", bytes.fromhex(s)))
    except Exception:  # noqa: BLE001
        pass
    # base58
    try:
        decoded = _b58decode(s)
        candidates.append(("base58", decoded))
    except Exception:  # noqa: BLE001
        pass

    # 选第一个解码出可打印内容（含 flag/dasctf 或大量字母数字）的
    for name, data in candidates:
        if not data:
            continue
        try:
            text = data.decode("utf-8")
        except Exception:  # noqa: BLE001
            continue
        if any(k in text.lower() for k in ("flag", "dasctf", "{", "}")):
            return (name, data)
        if sum(c.isalnum() for c in text) > len(text) * 0.6:
            return (name, data)
    return candidates[0] if candidates else None


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58_ALPHABET.index(ch)
    pad = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


class _ZipSlipError(Exception):
    """zip 成员名不安全（路径穿越/绝对路径/盘符），拒绝解压。"""


def _validate_zip_member(info) -> Optional[str]:
    """校验 zip 成员名是否安全（zip-slip 防护）。

    P0 安全（2026-08-21 审计）：`extractall` 对 `../` 成员名不设防，
    恶意附件 zip 可写出临时目录覆盖项目文件。返回错误描述（None=安全）。
    拒绝：
      - 含 `..` 路径穿越（含反斜杠混淆 `..\\`）
      - 以 `/` 或 `\\` 开头（绝对路径）
      - 含盘符（`C:` 等）
      - 空成员名
    """
    name = getattr(info, "filename", None) or ""
    if not name:
        return "zip 成员名为空"
    norm = name.replace("\\", "/")
    if norm.startswith("/"):
        return f"zip 成员为绝对路径: {name!r}"
    if len(norm) >= 2 and norm[1] == ":":
        return f"zip 成员含盘符: {name!r}"
    for part in norm.split("/"):
        if part == "..":
            return f"zip 成员含路径穿越(../): {name!r}"
    return None


class ZipChainDecodeAdapter(ToolAdapter):
    """多层 zip 文件名链解码（自动循环解压 + 编码探测）。"""

    name = "zip_chain_decode"
    categories = ["misc"]

    def __init__(self, sandbox=None, max_depth: int = 60) -> None:
        super().__init__(sandbox)
        self.max_depth = max_depth

    async def run(self, params: dict) -> ToolOutput:
        import tempfile

        zip_path = str(params.get("zip_path") or "").strip()
        if not zip_path or not os.path.isfile(zip_path):
            return ToolOutput(text=f"zip 文件不存在: {zip_path}", ok=False)

        names_chain = []
        zip_slip_err = ""
        current = zip_path
        with tempfile.TemporaryDirectory() as tmp:
            for depth in range(self.max_depth):
                try:
                    with zipfile.ZipFile(current) as z:
                        names = z.namelist()
                        if not names:
                            break
                        # P0 安全（2026-08-21）：extractall 前校验全部成员名，
                        # 拒绝 ../ 穿越 / 绝对路径 / 盘符（zip-slip 防护）
                        for _info in z.infolist():
                            _merr = _validate_zip_member(_info)
                            if _merr:
                                raise _ZipSlipError(_merr)
                        # 只取第一个条目（嵌套链通常是单文件）
                        inner = names[0]
                        # 文件名可能是中文目录（编码坑）：优先取非目录条目
                        for n in names:
                            if not n.endswith("/"):
                                inner = n
                                break
                        names_chain.append(inner)
                        z.extractall(tmp)
                        current = os.path.join(tmp, *inner.split("/"))
                        if not os.path.isfile(current):
                            # 解压后不是文件，可能是目录，递归找
                            found = None
                            for root, _, files in os.walk(tmp):
                                if files:
                                    found = os.path.join(root, files[0])
                                    break
                            current = found or ""
                            if not current:
                                break
                except _ZipSlipError as exc:
                    zip_slip_err = str(exc)
                    break
                except zipfile.BadZipFile:
                    break
                except Exception:  # noqa: BLE001
                    break

            # 读最终文件内容（可能是 flag.txt 或解码结果）
            final_content = ""
            if os.path.isfile(current):
                try:
                    with open(current, "rb") as f:
                        final_content = f.read().decode("utf-8", "replace")[:300]
                except Exception:  # noqa: BLE001
                    pass

            # 文件名链解码（10663 实测：反向 base32；同时尝试正/反向 + 首字母/尾字母链）
            pure = [re.sub(r"[^A-Za-z0-9]", "", n) for n in names_chain if re.sub(r"[^A-Za-z0-9]", "", n)]
            full = "".join(pure)
            head = "".join(p[0] for p in pure if p)
            tail = "".join(p[-1] for p in pure if p)
            decoded = None
            chain_dir = "?"
            for label, chain in (("full", full), ("full_rev", full[::-1]),
                                 ("head", head), ("head_rev", head[::-1]),
                                 ("tail", tail), ("tail_rev", tail[::-1])):
                r = _try_decode_chain(chain)
                if r:
                    decoded = r
                    chain_dir = label
                    break 

        result_lines = [
            f"解压深度: {len(names_chain)} 层",
            f"文件名链: {' -> '.join(names_chain[:20])}" + (" ..." if len(names_chain) > 20 else ""),
            f"最终文件内容: {final_content or '(空/二进制)'}",
        ]
        if zip_slip_err:
            result_lines.append(f"⚠️ 安全拦截（zip-slip 路径穿越，已拒绝解压）: {zip_slip_err}")
        if decoded:
            name, data = decoded
            result_lines.append(f"文件名链编码: {name}（{chain_dir}）")
            result_lines.append(f"解码结果: {data[:200]!r}")
        else:
            result_lines.append("文件名链编码: 未识别（尝试手工分析字符集/长度）")

        return ToolOutput(text="\n".join(result_lines), raw="\n".join(names_chain), ok=True)
