"""图片隐写适配器：PIL 实现 LSB 提取（zsteg 替代）。

本机 Windows 无 zsteg，用 Python PIL 实现等价能力：
- LSB 提取：PNG/BMP 图片 RGB 各通道最低位拼接还原隐藏文本
- 输出过滤：只送提取结果摘要 + flag 特征
"""

from __future__ import annotations

import re
from typing import Optional

from tools.base import ToolAdapter, ToolOutput


class StegoAdapter(ToolAdapter):
    """图片隐写适配器（zsteg 替代，LSB 提取）。"""

    name = "stego_lsb"
    categories = ["misc"]

    async def run(self, params: dict) -> ToolOutput:
        path = str(params.get("path") or "").strip()
        if not path:
            return ToolOutput(text="未提供图片路径", ok=False)

        import os

        if not os.path.isfile(path):
            return ToolOutput(text=f"文件不存在: {path}", ok=False)

        try:
            text, stats = self._extract_lsb(path)
        except Exception as exc:  # noqa: BLE001 - 解析异常兜底
            return ToolOutput(text=f"[LSB提取失败] {type(exc).__name__}: {exc}", ok=False)

        lines = [
            f"图片: {path} 尺寸: {stats['width']}x{stats['height']}",
            f"提取文本长度: {len(text)} 字符",
        ]
        # flag 特征
        m = re.search(r"flag\{[^}]+\}", text)
        if m:
            lines.append(f"发现 flag: {m.group(0)}")
        # 可读片段
        printable = "".join(c if 32 <= ord(c) < 127 or c in "\n\r\t" else "." for c in text)
        lines.append(f"文本片段(前300): {printable[:300]}")
        return ToolOutput(text="\n".join(lines), ok=True)

    @staticmethod
    def _extract_lsb(path: str) -> tuple[str, dict]:
        """提取 RGB 各通道 LSB，拼接为文本。"""
        from PIL import Image

        img = Image.open(path).convert("RGB")
        width, height = img.size
        px = img.load()

        bits = []
        for y in range(height):
            for x in range(width):
                r, g, b = px[x, y]
                bits.extend([r & 1, g & 1, b & 1])

        # 每 8 bit 转字节；检测 NUL 终止或前 512 字节
        chars = []
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for b in bits[i : i + 8]:
                byte = (byte << 1) | b
            if byte == 0:  # 空字节终止
                break
            chars.append(chr(byte))
            if len(chars) > 2048:  # 防止超长
                break

        return "".join(chars), {"width": width, "height": height}
