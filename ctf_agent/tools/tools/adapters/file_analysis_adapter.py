"""文件分析适配器：Python 实现 strings/file 签名检测/binwalk 替代。

本机 Windows 无 binwalk/strings 命令行工具，用 Python 实现等价能力：
- strings 替代：提取可打印字符串（含 UTF-16 宽字符）
- file 替代：magic bytes 签名识别（常见文件类型）
- binwalk 替代：扫描文件内嵌的常见文件头（PNG/ZIP/JPEG/GZIP 等）

输出过滤：只送发现结果摘要，不送全量内容进 LLM。
"""

from __future__ import annotations

import re
from typing import Optional

from tools.base import ToolAdapter, ToolOutput

# 常见文件 magic bytes 签名表
MAGIC_SIGNATURES = [
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("JPEG", b"\xff\xd8\xff"),
    ("GIF", b"GIF8"),
    ("ZIP", b"PK\x03\x04"),
    ("ZIP(空)", b"PK\x05\x06"),
    ("GZIP", b"\x1f\x8b"),
    ("PDF", b"%PDF"),
    ("ELF", b"\x7fELF"),
    ("BMP", b"BM"),
    ("RIFF(WAV/AVI)", b"RIFF"),
    ("TAR", b"ustar"),
    ("SQLite", b"SQLite format 3\x00"),
    ("7Z", b"7z\xbc\xaf\x27\x1c"),
]


class FileAnalysisAdapter(ToolAdapter):
    """文件分析适配器（strings/file/binwalk 的 Python 替代）。"""

    name = "file_analyze"
    categories = ["misc", "web", "reverse", "crypto"]

    async def run(self, params: dict) -> ToolOutput:
        path = str(params.get("path") or "").strip()
        if not path:
            return ToolOutput(text="未提供文件路径", ok=False)

        import os

        if not os.path.exists(path):
            return ToolOutput(text=f"路径不存在: {path}", ok=False)

        # 目录：返回目录树摘要（修复 2026-08-22 M2 归因——附件落盘常为「以扩展名
        # 结尾的目录」，旧逻辑 isfile() 直接判「文件不存在」导致 LLM 在 web 源码审计
        # 题上空转 180s）。列目录内容让 LLM 至少能看到真实文件/子目录再决定下一步。
        if os.path.isdir(path):
            return self._dir_summary(path)

        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            return ToolOutput(text=f"读取失败: {exc}", ok=False)

        size = len(data)
        lines = [f"文件: {path}  大小: {size} 字节"]
        lines.append(f"文件类型: {self._detect_type(data)}")

        # ── 内嵌文件头扫描（binwalk 替代）──
        embedded = self._scan_embedded(data)
        if embedded:
            lines.append("内嵌文件头: " + ", ".join(embedded[:8]))

        # ── 可打印字符串（strings 替代，前 20 条）──
        strings_found = self._extract_strings(data)
        if strings_found:
            lines.append("可打印字符串(前20):")
            for s in strings_found[:20]:
                lines.append(f"  {s}")
        if strings_found:
            _all_str = "\n".join(strings_found)
            # P0修复（2026-08-21）：匹配多种flag格式，大小写不敏感，直接提取
            _flag_m = re.search(r"(?i)(?:flag|ctf|dasctf)\{[^}\s]{4,}\}", _all_str)
            if _flag_m:
                lines.append(f"⚠️ 字符串中发现 flag: {_flag_m.group(0)}")

        return ToolOutput(text="\n".join(lines), ok=True)

    def _dir_summary(self, path: str) -> ToolOutput:
        """目录摘要：递归列出一层子项（文件+子目录），并给出顶层提示。

        不深挖海量源码（防 token 爆炸），只帮 LLM 看清「真实附件藏在哪」，
        让它在拿到目录时不再误判「文件不存在」。
        """
        import os as _os
        lines = [f"路径是目录: {path}"]
        try:
            entries = sorted(_os.listdir(path))
        except OSError as exc:
            return ToolOutput(text=f"{lines[0]}\n读取目录失败: {exc}", ok=False)
        files = [e for e in entries if _os.path.isfile(_os.path.join(path, e))]
        dirs = [e for e in entries if _os.path.isdir(_os.path.join(path, e))]
        if files:
            lines.append(f"文件({len(files)}):")
            for fn in files[:30]:
                fp = _os.path.join(path, fn)
                try:
                    sz = _os.path.getsize(fp)
                except OSError:
                    sz = -1
                lines.append(f"  {fn}  ({sz} bytes)" if sz >= 0 else f"  {fn}")
            if len(files) > 30:
                lines.append(f"  ... 其余 {len(files) - 30} 个文件")
        if dirs:
            lines.append(f"子目录({len(dirs)}): " + ", ".join(dirs[:20]))
            if len(dirs) > 20:
                lines.append(f"  ... 其余 {len(dirs) - 20} 个子目录")
        if not files and not dirs:
            lines.append("  (空目录)")
        lines.append("提示: 用 file_analyze 传入具体文件路径读取内容")
        return ToolOutput(text="\n".join(lines), ok=True)

    # ── 实现 ────────────────────────────────────────────

    @staticmethod
    def _detect_type(data: bytes) -> str:
        for name, magic in MAGIC_SIGNATURES:
            if data.startswith(magic):
                return name
        # 文本启发
        if len(data) > 0 and all(b == 0 or 32 <= b < 127 for b in data[:200]):
            return "纯文本/ASCII"
        return "未知"

    @staticmethod
    def _scan_embedded(data: bytes, max_results: int = 20) -> list[str]:
        """扫描内嵌文件头（简单版 binwalk）。"""
        found = []
        for name, magic in MAGIC_SIGNATURES:
            start = 0
            while True:
                idx = data.find(magic, start)
                if idx == -1 or len(found) >= max_results:
                    break
                # 跳过文件自身头部
                if idx > 4:
                    found.append(f"{name}@{idx:#x}")
                start = idx + len(magic)
        return found

    @staticmethod
    def _extract_strings(data: bytes, min_len: int = 5, max_count: int = 100) -> list[str]:
        """提取可打印字符串（含 UTF-16LE 宽字符串）。"""
        results = []

        def ascii_pass(buf: bytes):
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, buf):
                results.append(m.group(0).decode("ascii", errors="ignore"))

        def utf16_pass(buf: bytes):
            for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, buf):
                raw = m.group(0)
                results.append(raw.decode("utf-16-le", errors="ignore"))

        ascii_pass(data)
        utf16_pass(data)
        # 去重保序 + 限长（3000 字符：容纳 RSA 大数 n/e/c 等 617 位十进制参数 +
        # 多附件合并——2026-08-21 修复：600 上限会把 617 字符的大数全过滤，
        # 导致 crypto 参数文件 strings 提取为 0 条，LLM 看不到 n/c 无法解 RSA）
        seen = set()
        unique = []
        for s in results:
            if s not in seen and len(s) <= 3000:
                seen.add(s)
                unique.append(s)
            if len(unique) >= max_count:
                break
        return unique
