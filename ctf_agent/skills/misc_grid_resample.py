"""misc_grid_resample —— 图像杂色点网格采样隐写揭示（确定性）。

适用题型：图片里散布着间隔几乎相等的杂色点，flag 文字编码在这些点的网格坐标里。
解法：把所有"非纯黑"像素按固定网格间距重采样重绘，隐藏文字即显（官方 writeup 称"缩放重采样"）。

与 LSB 隐写不同：标准 RGB-LSB 提取返回空，必须用网格重采样才能揭示。
最后"读文字"这一步依赖视觉能力（tesseract 读不了这类像素字体，需要视觉 LLM 或人工）。

纯算法部分是确定性的：给定网格参数 (gx, gy, ox, oy)，揭示结果可复现。
"""
from __future__ import annotations

import os
import re
import subprocess

import numpy as np
from PIL import Image

try:
    import numpy as _np  # noqa: F401
    import PIL as _pil  # noqa: F401
    HAS_DEPS = True
except Exception:  # noqa: BLE001
    HAS_DEPS = False

# flag 候选（仅用于 OCR 命中后的校验，不作为硬编码答案）
_FLAG_PAT = re.compile(rb"flag\{[^}]*\}|vnctf\{[^}]*\}|DASCTF\{[^}]*\}", re.IGNORECASE)


def _autodetect_grid(pts):
    """从点集推断网格步长与原点。pts: (N,2) 的 (x,y)。

    返回 (gx, gy, ox, oy)。"""
    if len(pts) < 10:
        return None
    xs = np.sort(pts[:, 0])
    ys = np.sort(pts[:, 1])
    # x 间隔直方图（取最小正间隔的众数）
    dx = np.diff(xs)
    dy = np.diff(ys)
    dx = dx[(dx > 1) & (dx < 500)]
    dy = dy[(dy > 1) & (dy < 500)]
    if len(dx) == 0 or len(dy) == 0:
        return None
    gx = int(np.median(dx))
    gy = int(np.median(dy))
    ox = int(round(xs.min())) % gx if gx else 0
    oy = int(round(ys.min())) % gy if gy else 0
    if gx <= 1 or gy <= 1:
        return None
    return gx, gy, ox, oy


def _ocr(path: str, tess: str) -> bytes:
    try:
        out = subprocess.run(
            [tess, path, "stdout", "--psm", "6"],
            capture_output=True, text=True, timeout=30,
        )
        return out.stdout.encode("utf-8", "ignore")
    except Exception:  # noqa: BLE001
        return b""


def run(params: dict) -> dict:
    if not HAS_DEPS:
        return {"ok": False, "error": "缺少 numpy/PIL 依赖"}
    path = params.get("file") or params.get("path")
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": f"文件不存在: {path}"}
    out_dir = params.get("out_dir") or os.path.dirname(os.path.abspath(path))

    img = Image.open(path).convert("RGB")
    arr = np.array(img)
    h, w = arr.shape[:2]
    # 非纯黑像素（杂色点；图标本身是纯黑 (0,0,0)）
    nonblack = np.argwhere(np.any(arr != (0, 0, 0), axis=2))  # (N,2) -> (y,x)
    if len(nonblack) < 20:
        return {"ok": False, "error": f"非黑像素过少({len(nonblack)})，不像网格点阵题"}
    pts = nonblack[:, ::-1]  # (x, y)

    # 候选网格：自动探测 + 经典 VNCTF 风格 (50,31,22,10)
    candidates = []
    auto = _autodetect_grid(pts)
    if auto:
        candidates.append(auto)
    candidates.append((50, 31, 22, 10))

    os.makedirs(out_dir, exist_ok=True)
    last_err = ""
    flag = None
    used = None
    reveal_path = None
    tess = params.get("tesseract") or r"C:\Users\Lenovo\miniconda3\Library\bin\tesseract.exe"
    have_tess = os.path.isfile(tess)

    for (gx, gy, ox, oy) in candidates:
        cols = max(1, (w - ox) // gx) + 1
        rows = max(1, (h - oy) // gy) + 1
        res = Image.new("RGB", (cols, rows), 255)
        px = img.load()
        for x in range(w):
            for y in range(h):
                p = px[x, y]
                if p != (0, 0, 0):
                    cx = (x - ox) // gx
                    cy = (y - oy) // gy
                    if 0 <= cx < cols and 0 <= cy < rows:
                        res.putpixel((cx, cy), p)
        ra = np.array(res)
        mask = np.any(ra < 250, axis=2)
        ys_i, xs_i = np.where(mask)
        if len(xs_i) == 0:
            last_err = "重采样后无墨迹"
            continue
        y0, y1, x0, x1 = ys_i.min(), ys_i.max(), xs_i.min(), xs_i.max()
        crop = mask[y0:y1 + 1, x0:x1 + 1]
        # 正确反色：填充格 = 黑点(0)，空背景 = 白(255)；原代码 (~uint8)*255 会 uint8 回绕成一片黑
        reveal_arr = (1 - crop.astype(np.uint8)) * 255
        reveal = Image.fromarray(reveal_arr)
        reveal_big = reveal.resize((crop.shape[1] * 6, crop.shape[0] * 6), Image.NEAREST)
        rp = os.path.join(out_dir, "_grid_reveal.png")
        reveal_big.save(rp)
        reveal_path = rp
        used = (gx, gy, ox, oy)
        if have_tess:
            # tesseract 默认读黑字白底；reveal 已是黑字白底，直接 OCR（之前误用 255- 反色）
            big_inv = reveal_big
            tmp = os.path.join(out_dir, "_grid_ocr.png")
            big_inv.save(tmp)
            text = _ocr(tmp, tess)
            m = _FLAG_PAT.search(text)
            if m:
                flag = m.group(0).decode("latin-1")
                break
        else:
            last_err = "无 tesseract，已揭示文字图待视觉/人工读取"

    if flag:
        return {"ok": True, "flag": flag, "method": f"grid_resample{gx,gy,ox,oy}",
                "reveal_path": reveal_path}
    return {"ok": False, "error": last_err or "网格重采样已揭示文字，但本环境 tesseract 读不出该像素字体",
            "method": f"grid_resample{used}" if used else None,
            "reveal_path": reveal_path}
