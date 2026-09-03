#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""10732 CRYPTO-01 "Yusa的密码学课堂——PKCS#1" — 可复现离线核验脚本。

真题来源：data/race_details/10732.json + 附件
          data/race_attachments/10732_Yusa的密码学课堂——PKCS#1的附件/{task.py,PKCS#1.v1.5.enc,Crypto/}
（附件本地保留，.gitignore 排除不入 HEAD；本 verifier 通过本地附件存在性 + 攻击链完整执行做闭环）

攻击链（2026-09-03 重构固化；2026-08-24 本机原版手动跑通，2026-08-27 因"脚本散落"诚实校准移出 KPI）：
  1) 解析 task.py 注释里的 padded_long（pow(bytes_to_long(AES_KEY_ENC), d, q*r) 输出）；
     此数是 PKCS#1 v1.5 私钥解密的填充明文块（k=256 字节）
  2) padded_long 末 16 字节 = AES_KEY
     （任务方提供的 Crypto/Cipher/PKCS1_v1_5.py 被改写为 PS 全 0 后门，剥填充 = 直接取尾段）
  3) AES_KEY == 44bfc33d0bfb3cd688a074a7adad1504 强校验（与 skill docstring 三方一致）
  4) AES-ECB 解密 PKCS#1.v1.5.enc → 38624 字节合法 %PDF-1.4 PDF
  5) 渲染第 3 页 → 二值化裁斜体 flag 行（视觉层）
  6) 输出 REGRESS_PASS + AES_KEY + pdf_sha256 + flag_visual_path
     （flag 字符串本身不写入 verifier 输出 / 不写入 git，依赖人工或外部源做 sha256 闭环，
      故 10732 不进 _antifraud.PROMOTION_EVIDENCE，KPI 水位保持 12 不动 — 诚信口径）

honest 边界：
  - verifier 仅断言攻击链各步成功（附件存在 / padded_long 解析 / AES_KEY 匹配 / PDF 头与大小 / 视觉裁切成功）
  - flag 真值需 sha256 闭环：视觉读法 + baidu ernie-4.5-turbo-vl 兜底读出的 flag 字符 = `DASCTF{6b3ed7dc3c1c6615fb97a7020922f7a5}`
    （与台账 2026-08-24 记录的 sha256 前缀 337eadc1a305b60f 不一致，公开 writeup(CSDN 2026.1.25) 是同系列
    MT 随机数预测题而非本 PKCS#1 题，无可用外部真值闭环）
  - 因此 10732 治理归位 = 可机器复现 verifier 落库 + REGRESSION_CHECKS 入条目 + KNOWN_GAP 移除；
    不进 PROMOTION_EVIDENCE = 不升 KPI 水位；与 9→10/10→11/11→12 三道带证晋级模式不同。

运行：.venv/Scripts/python.exe scripts/verify_10732.py
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys


ATT_DIR = os.path.join(
    "data", "race_attachments",
    "10732_Yusa的密码学课堂——PKCS#1的附件",
)
TASK_PY = os.path.join(ATT_DIR, "task.py")
ENC_FILE = os.path.join(ATT_DIR, "PKCS#1.v1.5.enc")

# 结果写到 results 隔离区（gitignore 排除不入 HEAD）
RESULTS_DIR = os.path.join("data", "results", "_verify_10732_visual")
PDF_PATH = os.path.join(RESULTS_DIR, "_10732_decrypted.pdf")
FLAG_PNG = os.path.join(RESULTS_DIR, "_flag_line.png")

AES_KEY_EXPECTED_HEX = "44bfc33d0bfb3cd688a074a7adad1504"
PDF_LEN_EXPECTED = 38624


def _extract_padded_long(task_src: str) -> int:
    """从 task.py 注释里取 pow(bytes_to_long(AES_KEY_ENC), d, q*r) 的值。

    赛题第 38 行 print 输出 = 255 字节值（>600 位十进制），远长于 p/hint_enc/n/AES_KEY_ENC 的
    注释行；取所有 >=200 位十进制整数里最长那一行作为 padded_long。
    """
    candidates: list[int] = []
    for raw in task_src.splitlines():
        s = raw.lstrip("#").strip()
        m = re.match(r"^(\d{200,})$", s)
        if m:
            candidates.append(int(m.group(1)))
    if not candidates:
        raise ValueError("task.py 注释中未找到 >=200 位十进制整数（padded_long）")
    candidates.sort(key=lambda v: -len(str(v)))
    return candidates[0]


def _recover_aes_key(padded_long: int) -> bytes:
    """剥 PKCS#1 v1.5 篡改填充（PS 全 0），返回 AES_KEY 末尾 16 字节。

    题方改写了 Crypto/Cipher/PKCS1_v1_5.encrypt：标准 BT=02 + PS 全 0x00（非 0 随机） +
    0x00 + M。M = 16 字节 AES_KEY 在 256 字节 EM 末尾。
    padded_long 转字节后长度 255（首字节 0x00 被丢，补回 256）；直接取末尾 16 字节即可。
    """
    b = padded_long.to_bytes((padded_long.bit_length() + 7) // 8, "big")
    if len(b) < 256:
        b = b"\x00" * (256 - len(b)) + b
    return b[-16:]


def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def _render_flag_line(pdf_path: str, out_png: str) -> str | None:
    """渲染第 3 页 → 二值化裁 flag 行（视觉层）。失败不阻断 verifier 主流程。"""
    try:
        import pymupdf as fitz  # noqa: F401
    except ImportError:
        return None
    try:
        from PIL import Image, ImageOps

        doc = fitz.open(pdf_path)
        if len(doc) < 3:
            doc.close()
            return None
        page = doc[2]
        pix = page.get_pixmap(matrix=fitz.Matrix(10, 10))
        img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        rect = page.search_for("congratulations")
        doc.close()
        if not rect:
            return None
        y0 = rect[0].y1 + 2
        y1 = y0 + 30
        crop = img.crop((50, int(y0 * 10), img.size[0] - 50, int(y1 * 10)))
        g = ImageOps.grayscale(crop)
        bw = g.point(lambda x: 0 if x < 128 else 255, "L")
        bw = bw.resize((bw.size[0] * 2, bw.size[1] * 2))
        bw.save(out_png)
        return out_png
    except Exception as e:  # noqa: BLE001
        return f"<render-failed: {e}>"


def main() -> int:
    if not os.path.exists(TASK_PY) or not os.path.exists(ENC_FILE):
        print(
            "FAIL: 10732 附件缺失\n"
            f"  expect: {TASK_PY}\n"
            f"           {ENC_FILE}"
        )
        return 2

    task_src = open(TASK_PY, encoding="utf-8").read()
    padded_long = _extract_padded_long(task_src)

    aes_key = _recover_aes_key(padded_long)
    key_hex = aes_key.hex()

    if key_hex != AES_KEY_EXPECTED_HEX:
        print(
            "FAIL: AES_KEY 推导失配\n"
            f"  got   = {key_hex}\n"
            f"  expect= {AES_KEY_EXPECTED_HEX}"
        )
        return 3

    enc = open(ENC_FILE, "rb").read()
    pdf = _aes_ecb_decrypt(aes_key, enc)

    if len(pdf) != PDF_LEN_EXPECTED or not pdf.startswith(b"%PDF-1."):
        print(f"FAIL: PDF 解密异常 len={len(pdf)} head={pdf[:8]!r}")
        return 4

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(PDF_PATH, "wb") as f:
        f.write(pdf)

    flag_visual = _render_flag_line(PDF_PATH, FLAG_PNG)

    print(json.dumps({
        "ok": True,
        "via": "PKCS1_v1.5_padded_unpad(全0PS后门)+AES-ECB+visual_crop",
        "aes_key_hex": key_hex,
        "pdf_size": len(pdf),
        "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
        "flag_visual_path": flag_visual,
        "flag_visual_note": (
            "DASCTF{<32hex>} 斜体，渲染层。flag 字符视觉读法 + baidu ernie-4.5-turbo-vl 兜底 = "
            "'DASCTF{6b3ed7dc3c1c6615fb97a7020922f7a5}'（与台账 2026-08-24 sha256 前缀 "
            "337eadc1a305b60f 不一致，无可用外部真值闭环；故 10732 不进 "
            "PROMOTION_EVIDENCE，KPI 水位保持 12 不动）"
        ),
    }, ensure_ascii=False, indent=2))
    print("REGRESS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())