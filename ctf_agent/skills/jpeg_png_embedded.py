"""JPEG 尾部嵌入 PNG 检测与提取（玄盾杯 SignIN 模式）。

xz1.jpg 是 JPEG（FFD8 头 + FFD9 尾），FFD9 后直接接 PNG（89504E47 魔数）。
提取 PNG 后 flag 以视觉文字呈现。2026-08-22 M3 增强：自动调 tesseract OCR 文字，
按 flag_pattern 提取 flag 字符串供 presolve 直接命中。
"""
from __future__ import annotations
import os, re, struct, subprocess, tempfile, shutil


_FLAG_PAT = re.compile(rb"(?:flag|FLAG|Flag|DASCTF)\{[^}]{2,80}\}")

# tesseract 常见安装路径（conda / choco / 官方 installer）。venv 环境下 tesseract
# 通常不在 PATH，需显式定位。注：tesseract 是 Windows 原生程序，TESSDATA_PREFIX 必须
# 传 Windows 风格路径（D:/... 或 D:\\...），Git Bash 的 /d/... POSIX 路径会被它忽略并报
# "does not exist, ignore it" 导致加载不到 eng.traineddata。
_TESS_CANDIDATES = [
    r"D:/miniconda3_new/Library/bin/tesseract.exe",
    r"C:/Users/Lenovo/miniconda3/Library/bin/tesseract.exe",
    r"C:/Program Files/Tesseract-OCR/tesseract.exe",
    r"C:/Program Files (x86)/Tesseract-OCR/tesseract.exe",
    r"C:/tools/tesseract/tesseract.exe",
    r"C:/tools/Tesseract-OCR/tesseract.exe",
    r"C:/Users/Lenovo/AppData/Local/Programs/tesseract/tesseract.exe",
]


def _locate_tesseract():
    """定位 tesseract 可执行文件及其 tessdata 目录。返回 (exe, tessdata_dir) 或 (None, None)。"""
    exe = shutil.which("tesseract")
    if exe:
        exe = os.path.abspath(exe)
    else:
        for c in _TESS_CANDIDATES:
            if os.path.isfile(c):
                exe = c
                break
    if not exe:
        return None, None
    bindir = os.path.dirname(exe)
    for cand in (os.path.join(bindir, "..", "share", "tessdata"),
                 os.path.join(bindir, "tessdata")):
        d = os.path.abspath(cand)
        if os.path.isfile(os.path.join(d, "eng.traineddata")):
            return exe, d
    return exe, None


def _ocr_text(png_path: str) -> str:
    """subprocess 调 tesseract 读 PNG 文字（不依赖 pytesseract 包装库）。

    自动定位 tesseract，并以 Windows 风格路径设置 TESSDATA_PREFIX；若直出无 flag，
    再做一次二值化+放大重试，应对浅色/低对比视觉文字。
    """
    exe, tdata = _locate_tesseract()
    if not exe:
        return ""
    env = dict(os.environ)
    if tdata:
        env["TESSDATA_PREFIX"] = tdata.replace("\\", "/")
    try:
        r = subprocess.run(
            [exe, png_path, "stdout", "-l", "eng", "--psm", "6"],
            capture_output=True, timeout=20, env=env,
        )
        out = r.stdout.decode("utf-8", errors="ignore")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    if _FLAG_PAT.search(out.encode("utf-8", errors="ignore")):
        return out
    # 二次尝试：二值化 + 放大，提升低对比文字命中率
    try:
        from PIL import Image
        im = Image.open(png_path).convert("L")
        im = im.point(lambda p: 0 if p < 128 else 255)
        im = im.resize((im.width * 2, im.height * 2), Image.LANCZOS)
        tmp = os.path.join(tempfile.gettempdir(), "_xz_ocr_retry.png")
        im.save(tmp)
        r2 = subprocess.run(
            [exe, tmp, "stdout", "-l", "eng", "--psm", "6"],
            capture_output=True, timeout=20, env=env,
        )
        out = r2.stdout.decode("utf-8", errors="ignore")
    except Exception:
        pass
    return out


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
