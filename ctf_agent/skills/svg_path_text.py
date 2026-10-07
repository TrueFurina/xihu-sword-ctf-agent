"""bzip2/Ascii85 包裹的 SVG path 文本 → 栅格化 → OCR 读出（确定性静态求解）。

适用题型（本框架新增能力，2026-10-07）：
    附件为 **bzip2 压缩的 Ascii85 文本**，解码得到一段 **SVG path 的 d 属性**
    （M/L/Q/A/Z 等指令、坐标为浮点），渲染出来是一行文字（通常是 flag）。
    这类题无法用「嗅探明文」解决——明文只存在于**图形**里，必须渲染 + 识别。

    例（NYU CTF Bench 2023f-for-floating_points，CSAW-Finals 2023）：
        floating_points --bzip2--> Ascii85 --> SVG path --> 渲染 -->
        csawctf{did_you_try_w3schools_path_d=}

为什么这样实现：
    · **渲染**只依赖「解析 SVG path 指令 + 多边形栅格化」，是公开标准的确定性
      算法，故手写纯 Python 实现（even-odd 异或填充正确处理字腔），零第三方
      图形库依赖 —— 契合本框架「确定性优先、依赖精简」的定位。
    · **识别**走系统 tesseract（可选外部依赖）：找不到就返回 None（不谎报），
      绝不把噪声当命中。多处描边粗细各渲染一次，取「最像 flag（含 {..}）」者。

诚实口径：
    · 本技能只做「解码 + 渲染 + OCR」，不做任何明文嗅探/grep；命中与否由下游
      flag_pattern + 答案校验（题面提供时）把关；
    · OCR 非 100% 保真，故多轮重试 + 形状判据；无把握一律返回 None。

接口对齐 skills/*.run：
    params:
        "path": bzip2 文件路径（最常见；与 raw 二选一）
        "raw":  bzip2（或 Ascii85 文本）bytes
        "data": 直接给定 SVG path 数据字符串（最高优先，测试用）
        "ocr":  bool，默认 True；False 时只做「容器解码 + path 校验」不 OCR
    返回: 识别出的文本 bytes；无把握 → None
"""
from __future__ import annotations

import bz2
import math
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional, Sequence, Tuple

# Ascii85 取值范围（'!'..'u'）
_A85_MIN = 33
_A85_MAX = 117

# SVG path 允许的字符（指令字母 + 数字/分隔符/指数）
_PATH_CHARS = set("0123456789+-.eE ,\t\r\n")
_PATH_CMDS = set("MmLlHhVvCcSsQqTtAaZz")

_TOKEN_RE = re.compile(r"[MmLlHhVvCcSsQqTtAaZz]|-?\d*\.?\d+(?:[eE][-+]?\d+)?")


# ------------------------------------------------------------------ 容器解码

def _looks_ascii85(s: str, min_ratio: float = 0.98) -> bool:
    """判断文本是否为 Ascii85 正文（几乎全落在 '!'..'u' 且含可打印字符）。"""
    if not s:
        return False
    ok = sum(1 for ch in s if _A85_MIN <= ord(ch) <= _A85_MAX)
    return ok / len(s) >= min_ratio


def _looks_path_data(s: str) -> bool:
    """判断字符串是否像一段 SVG path 的 d 属性（以 M/m 起、仅含指令与数字）。"""
    if not s or len(s) < 16:
        return False
    st = s.lstrip()
    if not st or st[0] not in "Mm":
        return False
    allowed = _PATH_CHARS | _PATH_CMDS
    if any(ch not in allowed for ch in s):
        return False
    if s.count("Z") + s.count("z") < 1:
        return False
    return True


def decode_container(raw: bytes) -> Optional[str]:
    """把「bzip2(Ascii85(SVG-path))」解到 SVG path 字符串。

    分两层容错：先试 bzip2 解压（magic ``BZh``），再试 Ascii85 解码；
    任一层失败则原样进入下一层判断（支持附件本来就是 Ascii85 文本的情形）。
    全链路只接受「确定性可识别」的形态，否则 None。
    """
    import base64

    text: Optional[str] = None
    if raw[:3] == b"BZh":
        try:
            text = bz2.decompress(raw).decode("latin-1")
        except Exception:  # noqa: BLE001
            return None
    else:
        # 非 bzip2：尝试直接当 Ascii85 文本
        try:
            text = raw.decode("latin-1")
        except Exception:  # noqa: BLE001
            return None

    if text is None:
        return None
    text = text.strip()
    # 已是 path 数据 → 直接返回
    if _looks_path_data(text):
        return text
    # Ascii85 → path 数据
    if not _looks_ascii85(text):
        return None
    try:
        dec = base64.a85decode(text.encode("latin-1", errors="ignore"))
        cand = dec.decode("latin-1").strip()
    except Exception:  # noqa: BLE001
        return None
    return cand if _looks_path_data(cand) else None


# ------------------------------------------------------------------ path 解析

def _num(tokens: Sequence[str], i: int) -> Tuple[float, int]:
    return float(tokens[i]), i + 1


def _arc_to_points(x1, y1, rx, ry, phi, laf, sf, x2, y2, n=48):
    """SVG 端点式椭圆弧 → 采样点（F.6.5 中心参数化）。"""
    if rx == 0 or ry == 0:
        return [(x2, y2)]
    phi = math.radians(phi)
    rx, ry = abs(rx), abs(ry)
    dx2, dy2 = (x1 - x2) / 2.0, (y1 - y2) / 2.0
    c, s = math.cos(phi), math.sin(phi)
    x1p, y1p = c * dx2 + s * dy2, -s * dx2 + c * dy2
    lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
    if lam > 1:
        f = math.sqrt(lam)
        rx *= f
        ry *= f
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p
    co = math.sqrt(max(0.0, num / den)) if den else 0.0
    if laf == sf:
        co = -co
    cxp, cyp = co * rx * y1p / ry, -co * ry * x1p / rx
    cx = c * cxp - s * cyp + (x1 + x2) / 2.0
    cy = s * cxp + c * cyp + (y1 + y2) / 2.0

    def ang(ux, uy, vx, vy):
        dot = ux * vx + uy * vy
        nrm = math.hypot(ux, uy) * math.hypot(vx, vy)
        a = math.acos(max(-1.0, min(1.0, dot / nrm if nrm else 1.0)))
        if ux * vy - uy * vx < 0:
            a = -a
        return a

    th1 = ang(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry)
    dth = ang((x1p - cxp) / rx, (y1p - cyp) / ry,
              (-x1p - cxp) / rx, (-y1p - cyp) / ry)
    if not sf and dth > 0:
        dth -= 2 * math.pi
    elif sf and dth < 0:
        dth += 2 * math.pi
    out = []
    for k in range(n + 1):
        t = th1 + dth * k / n
        out.append((cx + rx * math.cos(t) * c - ry * math.sin(t) * s,
                    cy + rx * math.cos(t) * s + ry * math.sin(t) * c))
    return out


def parse_subpaths(path_data: str) -> Optional[List[List[Tuple[float, float]]]]:
    """解析 SVG path → 闭合子路径点列（曲线/圆弧展平）。不支持指令 → None。"""
    toks = _TOKEN_RE.findall(path_data)
    if not toks:
        return None
    subpaths: List[List[Tuple[float, float]]] = []
    cur: List[Tuple[float, float]] = []
    x = y = 0.0
    sx = sy = 0.0
    start = None
    prev_ctrl = None          # S/T 的反射控制点
    prev_cmd = ""
    i = 0

    def push(v):
        nonlocal cur
        cur.append(v)

    while i < len(toks):
        t = toks[i]
        if t in _PATH_CMDS:
            cmd = t
            i += 1
        else:
            # 隐式重复：M→L，m→l，其余沿用上一指令
            if not prev_cmd:
                return None
            cmd = "L" if prev_cmd == "M" else ("l" if prev_cmd == "m" else prev_cmd)
        rel = cmd.islower()
        c = cmd.upper()
        if c == "M":
            nx, i = _num(toks, i); ny, i = _num(toks, i)
            if rel:
                nx += x; ny += y
            if cur:
                subpaths.append(cur)
            cur = [(nx, ny)]
            sx, sy = nx, ny
            x, y = nx, ny
            prev_ctrl = None
        elif c == "L":
            nx, i = _num(toks, i); ny, i = _num(toks, i)
            if rel:
                nx += x; ny += y
            push((nx, ny)); x, y = nx, ny; prev_ctrl = None
        elif c == "H":
            nx, i = _num(toks, i)
            if rel:
                nx += x
            push((nx, y)); x = nx; prev_ctrl = None
        elif c == "V":
            ny, i = _num(toks, i)
            if rel:
                ny += y
            push((x, ny)); y = ny; prev_ctrl = None
        elif c == "Q":
            cx1, i = _num(toks, i); cy1, i = _num(toks, i)
            nx, i = _num(toks, i); ny, i = _num(toks, i)
            if rel:
                cx1 += x; cy1 += y; nx += x; ny += y
            for k in range(1, 17):
                u = k / 16.0
                push(((1 - u) ** 2 * x + 2 * (1 - u) * u * cx1 + u * u * nx,
                      (1 - u) ** 2 * y + 2 * (1 - u) * u * cy1 + u * u * ny))
            prev_ctrl = (cx1, cy1); x, y = nx, ny
        elif c == "T":
            if prev_ctrl is None:
                cx1, cy1 = x, y
            else:
                cx1, cy1 = 2 * x - prev_ctrl[0], 2 * y - prev_ctrl[1]
            nx, i = _num(toks, i); ny, i = _num(toks, i)
            if rel:
                nx += x; ny += y
            for k in range(1, 17):
                u = k / 16.0
                push(((1 - u) ** 2 * x + 2 * (1 - u) * u * cx1 + u * u * nx,
                      (1 - u) ** 2 * y + 2 * (1 - u) * u * cy1 + u * u * ny))
            prev_ctrl = (cx1, cy1); x, y = nx, ny
        elif c == "C":
            c1x, i = _num(toks, i); c1y, i = _num(toks, i)
            c2x, i = _num(toks, i); c2y, i = _num(toks, i)
            nx, i = _num(toks, i); ny, i = _num(toks, i)
            if rel:
                c1x += x; c1y += y; c2x += x; c2y += y; nx += x; ny += y
            for k in range(1, 25):
                u = k / 24.0
                m = 1 - u
                push((m ** 3 * x + 3 * m * m * u * c1x + 3 * m * u * u * c2x + u ** 3 * nx,
                      m ** 3 * y + 3 * m * m * u * c1y + 3 * m * u * u * c2y + u ** 3 * ny))
            prev_ctrl = (c2x, c2y); x, y = nx, ny
        elif c == "S":
            if prev_ctrl is None:
                c1x, c1y = x, y
            else:
                c1x, c1y = 2 * x - prev_ctrl[0], 2 * y - prev_ctrl[1]
            c2x, i = _num(toks, i); c2y, i = _num(toks, i)
            nx, i = _num(toks, i); ny, i = _num(toks, i)
            if rel:
                c2x += x; c2y += y; nx += x; ny += y
            for k in range(1, 25):
                u = k / 24.0
                m = 1 - u
                push((m ** 3 * x + 3 * m * m * u * c1x + 3 * m * u * u * c2x + u ** 3 * nx,
                      m ** 3 * y + 3 * m * m * u * c1y + 3 * m * u * u * c2y + u ** 3 * ny))
            prev_ctrl = (c2x, c2y); x, y = nx, ny
        elif c == "A":
            rx, i = _num(toks, i); ry, i = _num(toks, i); rot, i = _num(toks, i)
            laf, i = _num(toks, i); sf, i = _num(toks, i)
            nx, i = _num(toks, i); ny, i = _num(toks, i)
            if rel:
                nx += x; ny += y
            cur += _arc_to_points(x, y, rx, ry, rot, int(laf), int(sf), nx, ny)
            x, y = nx, ny; prev_ctrl = None
        elif c == "Z":
            if cur:
                cur.append((sx, sy))
            x, y = sx, sy; prev_ctrl = None
        else:
            return None
        prev_cmd = cmd
    if cur:
        subpaths.append(cur)
    # 至少一个闭合子路径 + 点数下限（避免把噪声当图形）
    closed = sum(1 for s in subpaths if len(s) >= 3)
    if closed < 1 or sum(len(s) for s in subpaths) < 12:
        return None
    return subpaths


# ------------------------------------------------------------------ 渲染

def rasterize(subpaths, thickness: float = 1.6, scale: int = 8,
              pad: int = 24, max_side: int = 12000):
    """even-odd 异或填充 + 描边加粗 → PIL 灰度图。返回 (Image, bbox)。"""
    import numpy as np
    from PIL import Image, ImageDraw

    pts_all = [p for s in subpaths for p in s]
    if not pts_all:
        return None, None
    xs = [p[0] for p in pts_all]
    ys = [p[1] for p in pts_all]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    w = int((maxx - minx) * scale) + 2 * pad
    h = int((maxy - miny) * scale) + 2 * pad
    if w <= 0 or h <= 0:
        return None, None
    # 超长画布保护（例如异常宽的坐标范围）
    if max(w, h) > max_side:
        f = max_side / float(max(w, h))
        scale = max(1, int(scale * f))
        w = int((maxx - minx) * scale) + 2 * pad
        h = int((maxy - miny) * scale) + 2 * pad

    acc = np.zeros((h, w), dtype=bool)
    line_w = max(1, int(round(thickness * scale / 4.0)))
    for s in subpaths:
        if len(s) < 2:
            continue
        pix = [((px - minx) * scale + pad, (py - miny) * scale + pad) for px, py in s]
        im = Image.new("1", (w, h), 0)
        dr = ImageDraw.Draw(im)
        dr.polygon(pix, fill=1)
        if thickness > 0:
            dr.line(pix + [pix[0]], fill=1, width=line_w)
        acc ^= np.array(im, dtype=bool)
    img = Image.fromarray(np.where(acc, 0, 255).astype("uint8"))
    return img, (minx, miny, maxx, maxy)


# ------------------------------------------------------------------ OCR

def _find_tesseract() -> Optional[str]:
    p = os.environ.get("TESSERACT_BIN")
    if p and os.path.exists(p):
        return p
    p = shutil.which("tesseract")
    if p:
        return p
    for c in (
        "C:/Program Files/Tesseract-OCR/tesseract.exe",
        "C:/Program Files (x86)/Tesseract-OCR/tesseract.exe",
        "D:/miniconda3_new/Library/bin/tesseract.exe",
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
        "/opt/homebrew/bin/tesseract",
    ):
        if os.path.exists(c):
            return c
    return None


def _tessdata_for(bin_path: str) -> Optional[str]:
    base = os.path.dirname(bin_path)
    cands = [
        os.path.join(os.path.dirname(base), "share", "tessdata"),
        os.path.join(base, "tessdata"),
        os.path.join(os.path.dirname(base), "tessdata"),
    ]
    for c in cands:
        if os.path.isdir(c) and os.path.exists(os.path.join(c, "eng.traineddata")):
            return c
    return None


# OCR 候选评分：良构 flag（仅可打印 ASCII）> 全 ASCII > flag 更长 > 整体更长。
# 用于多 psm 投票，避免「先试的 psm 恰好含花括号就抢先返回」而选到含非 ASCII
# 噪声的坏候选（实测 CSAW2017 missed_registration 的 BMP 即 psm7 出 '§' 而 psm6 正确）。
_OCR_FLAG_RE = re.compile(r"[A-Za-z0-9_]{1,12}\{[!-~]{3,120}\}")


def _ocr_candidate_score(text: str) -> Tuple[int, int, int, int]:
    """给一个 OCR 候选打分，元组越大越好。"""
    m = _OCR_FLAG_RE.search(text)
    has_flag = 1 if m else 0
    ascii_only = 1 if text.isascii() else 0
    flag_len = len(m.group(0)) if m else 0
    return (has_flag, ascii_only, flag_len, len(text))


def _select_ocr_candidate(outs: Sequence[str]) -> Optional[str]:
    """从多 psm 候选里择优。返回 None 表示无候选。

    `max` 语义 = 并列时**保留先出现者**（历史实现 psm7 优先，此处保持）。
    """
    outs = [o for o in outs if o]
    if not outs:
        return None
    return max(outs, key=_ocr_candidate_score)


def ocr_image(img) -> Optional[str]:
    """对 PIL 灰度图跑 tesseract（psm 7/6 投票择优）。无 tesseract → None。

    历史坑：早期实现「按 psm 顺序、首个含花括号者即返回」——当 psm7 给出含非
    可打印字符（如 '§'）的伪命中时会抢先返回、丢掉 psm6 的正确结果。现改为
    收集全部候选后交 `_select_ocr_candidate` 择优。
    """
    binp = _find_tesseract()
    if not binp:
        return None
    fd, tmp = tempfile.mkstemp(suffix=".png", prefix="svg_ocr_")
    os.close(fd)
    try:
        img.save(tmp)
        env = dict(os.environ)
        if not env.get("TESSDATA_PREFIX"):
            td = _tessdata_for(binp)
            if td:
                env["TESSDATA_PREFIX"] = td
        outs: List[str] = []
        for psm in ("7", "6"):
            try:
                r = subprocess.run(
                    [binp, tmp, "stdout", "--psm", psm],
                    capture_output=True, text=True, env=env, timeout=60)
            except Exception:  # noqa: BLE001
                continue
            out = (r.stdout or "").strip()
            if out:
                outs.append(out)
        return _select_ocr_candidate(outs)
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


# ------------------------------------------------------------------ 顶层 run

_PREFERRED_EXTS = (".deb", ".gz", ".bz2", ".zip", ".tar", ".png", ".jpg", ".jpeg")
_SUPPORTED_EXT_HINTS = ("floating", "points", "svg", "path", "draw", "curve")


def run(params: dict) -> Optional[bytes]:
    """见模块 docstring。返回识别文本 bytes；无把握 → None。"""
    if not isinstance(params, dict):
        return None
    data = params.get("data")
    if data is None:
        raw = params.get("raw")
        if raw is None and params.get("path"):
            try:
                with open(str(params["path"]), "rb") as fh:
                    raw = fh.read()
            except OSError:
                return None
        if isinstance(raw, str):
            raw = raw.encode("latin-1", errors="ignore")
        if not isinstance(raw, (bytes, bytearray)):
            return None
        pstr = decode_container(bytes(raw))
    else:
        pstr = str(data).strip() if _looks_path_data(str(data)) else None
    if not pstr:
        return None

    subs = parse_subpaths(pstr)
    if not subs:
        return None
    if params.get("ocr") is False:
        return pstr.encode("latin-1", errors="ignore")   # 仅校验容器/path（测试用）

    texts = []
    for th in (1.6, 2.6, 3.6, 0.0):
        img, _ = rasterize(subs, thickness=th)
        if img is None:
            continue
        t = ocr_image(img)
        if t:
            texts.append(t)
            if "{" in t and "}" in t:
                return t.encode("utf-8", errors="ignore")
    for t in texts:
        if "{" in t:
            return t.encode("utf-8", errors="ignore")
    return texts[0].encode("utf-8", errors="ignore") if texts else None
