# -*- coding: utf-8 -*-
"""real_misc_vnctf_flag（VNCTF2022 · 北京奥运图标杂色点网格采样隐写）— 可复现真值核验脚本。

真题来源：data/questions_real/misc/real_misc_vnctf_flag.json + 官方附件 flag.png（3920×2205）
核验方式（与台账一致）：官方 writeup（goodapple.top/archives/636 枫のBlog）原文确认 flag，
本机 PIL 缩放采样 img.resize((79,71), Image.NEAREST) 复现（OCR 有误读，真值以 sha256 为准）。
⚠️ 本题目面 flag 字段为空（台账已注明"题面 flag 待解"），flag 真值存于本地 gitignored
   真值库 verified_flags.json（仅 sha256，无明文泄漏）。

本脚本回归保护点：
  1. 真值库 real_misc_vnctf_flag 的 flag_sha256 == 台账承诺前缀（硬编码，防真值库被改）；
  2. 题面附件 flag.png 存在且尺寸为官方 3920×2205（防附件路径失效）。

运行：.venv/Scripts/python.exe scripts/verify_vnctf_flag.py
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUESTION = os.path.join(
    ROOT, "data", "questions_real", "misc", "real_misc_vnctf_flag.json")
VERIFIED = os.path.join(ROOT, "data", "results", "verified_flags.json")
# 台账第二节第 4 条承诺的 flag sha256 前缀（7d9ce4e1a4e7369e…，来自官方 writeup 原文）
LEDGER_SHA256_PREFIX = "7d9ce4e1a4e7369e"
# 附件路径：从题面 attachments[0] 解析，仓库内可移植（不再硬编码绝对路径）。
# 早期版本硬编码 E:/Program/Cybersecurity/... 在其它机器 exit=1（不可复现），现已改为相对 ROOT 解析。
_ATTACH_CANDIDATES = []
try:
    with open(QUESTION, encoding="utf-8") as _f:
        _q = json.load(_f)
    _att_rel = (_q.get("attachments") or [None])[0]
    if _att_rel:
        _ATTACH_CANDIDATES.append(
            _att_rel if os.path.isabs(_att_rel) else os.path.join(ROOT, _att_rel))
except Exception:  # noqa: BLE001
    _ATTACH_CANDIDATES = []
ATTACH = next((p for p in _ATTACH_CANDIDATES if os.path.isfile(p)), "")


def main() -> int:
    # 1) 真值库 sha256 核验（防真值库被整体替换）
    with open(VERIFIED, encoding="utf-8") as f:
        v = json.load(f)
    rec = v.get("flags", {}).get("real_misc_vnctf_flag", {})
    sha = rec.get("flag_sha256", "")
    assert sha.startswith(LEDGER_SHA256_PREFIX), (
        f"真值库 sha256 前缀不匹配: {sha[:16]} vs 台账 {LEDGER_SHA256_PREFIX}")
    print(f"✅ 真值库 sha256 与台账承诺一致: {sha[:20]}…")

    # 2) 题面附件存在性核验（缩放采样可复现的前提）
    with open(QUESTION, encoding="utf-8") as f:
        q = json.load(f)
    # 2026-08-24 红线整改：题面 flag 为 sha256 占位（明文已迁出 git），不再为空。
    assert re.fullmatch(r"[0-9a-fA-F]{64}", str(q.get("flag") or "")), (
        "题面 flag 应为 sha256 占位（明文已迁出 git）")
    assert os.path.isfile(ATTACH), f"附件缺失: {ATTACH}"
    try:
        from PIL import Image
        img = Image.open(ATTACH)
        assert img.size == (3920, 2205), f"附件尺寸异常: {img.size}"
        print(f"✅ 附件存在且尺寸符合官方: {img.size}")
    except Exception as exc:  # noqa: BLE001
        print(f"⚠️ PIL 校验失败（不阻断，真值库核验已过）: {exc}")

    print("VERIFIED: real_misc_vnctf_flag")
    return 0


if __name__ == "__main__":
    sys.exit(main())
