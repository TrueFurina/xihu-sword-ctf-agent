"""JPEG 尾部嵌入 PNG 检测与提取（玄盾杯 SignIN 模式）。

xz1.jpg 是 JPEG（FFD8 头 + FFD9 尾），FFD9 后直接接 PNG（89504E47 魔数）。
提取 PNG 后 flag 以视觉文字呈现。2026-08-22 M3 增强：自动调 tesseract OCR 文字，
按 flag_pattern 提取 flag 字符串供 presolve 直接命中。
"""
from __future__ import annotations
import os, re, struct, subprocess, tempfile


_FLAG_PAT = re.compile(rb"(?:flag|FLAG|Flag|DASCTF)\{[^}]{2,80}\}")
_TESSERACT = "tesseract"


def _ocr_text(png_path: str) -> str:
    """subprocess 调 tesseract 读 PNG 文字（不依赖 pytesseract 包装库）。"""
    try:
        r = subprocess.run(
            [_TESSERACT, png_path, "stdout", "-l", "eng", "--psm", "6"],
            capture_output=True, timeout=20,
        )
        return r.stdout.decode("utf-8", errors="ignore")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def run(params: dict) -> dict:
    path = params.get("path", "")
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "需要有效 path"}
    data = open(path, "rb").read()

    jpeg_end = data.rfind(b"\xff\xd9")
    png_magic = b"\x89PNG\r\n\x1a\n"
    png_idx = data.find(png_magic)
    iend = data.find(b"IEND")

    result = {
        "ok": True, "size": len(data), "jpeg_end": jpeg_end, "png_idx": png_idx,
        "is_jpeg": data[:2] == b"\xff\xd8",
    }
    if png_idx >= 0 and iend > png_idx:
        png_data = data[png_idx:iend + 8]
        result["png_extracted"] = True
        result["png_size"] = len(png_data)
        # IHDR 宽高
        if len(png_data) >= 24:
            w, h = struct.unpack(">II", png_data[16:24])
            result["png_dim"] = f"{w}x{h}"
        out_path = os.path.join(os.path.dirname(path), "_extracted.png")
        try:
            open(out_path, "wb").write(png_data)
            result["png_path"] = out_path
        except OSError:
            pass
        # 提取 PNG 内所有文本块
        import zlib
        pos = 8
        texts = []
        while pos < len(png_data):
            ln = struct.unpack(">I", png_data[pos:pos+4])[0]
            ctype = png_data[pos+4:pos+8]
            cdata = png_data[pos+8:pos+8+ln]
            if ctype in (b"tEXt", b"iTXt", b"zTXt"):
                texts.append(cdata[:200])
            pos += 12 + ln
        result["text_chunks"] = texts
        # 2026-08-22 M3：提取 PNG 后自动 tesseract OCR → flag_pattern 匹配
        try:
            text = _ocr_text(out_path)
            m = _FLAG_PAT.search(text.encode("utf-8", errors="ignore"))
            if m:
                result["flag"] = m.group(0).decode("utf-8", errors="ignore")
                result["flag_source"] = "ocr:tesseract"
        except Exception:
            pass
    else:
        result["png_extracted"] = False
    return result
