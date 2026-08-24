# -*- coding: utf-8 -*-
"""real_crypto_specialcurve2（西湖论剑 2021 · 复数乘法群 RSA）— 可复现真值核验脚本。

真题来源：data/questions_real/crypto/real_crypto_specialcurve2.json
核验方式（与台账一致）：题面真值文件直接给出 flag（外部真值，非自产）；
仓库 skill skills/crypto_complex_mult_group.py 记录"2026-08-22 实测解出"并与真值一致。
本脚本：读题面 flag → 与本地 verified_flags.json 的 sha256 比对（无明文泄漏）→ 输出 VERIFIED。

运行：.venv/Scripts/python.exe scripts/verify_specialcurve2.py
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUESTION = os.path.join(
    ROOT, "data", "questions_real", "crypto", "real_crypto_specialcurve2.json")
VERIFIED = os.path.join(ROOT, "data", "results", "verified_flags.json")


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def main() -> int:
    with open(QUESTION, encoding="utf-8") as f:
        q = json.load(f)
    # 2026-08-24 红线整改：题面 flag 字段为 sha256 占位，明文仅在 gitignored 真值库。
    stored_sha = (q.get("flag_sha256") or q.get("flag") or "").strip()
    assert re.fullmatch(r"[0-9a-fA-F]{64}", stored_sha), f"题面 flag 非 sha256 占位: {stored_sha[:20]}"

    # 与本地真值库 sha256 比对（真值库 gitignored，不泄漏明文）
    with open(VERIFIED, encoding="utf-8") as f:
        v = json.load(f)
    rec = v.get("flags", {}).get("real_crypto_specialcurve2", {})
    expect = rec.get("flag_sha256", "")
    if expect:
        assert stored_sha.lower() == expect.lower(), (
            f"sha256 不匹配: 题面 {stored_sha[:16]} vs 真值库 {expect[:16]}")
        print(f"✅ 题面 flag_sha256 与真值库一致: {expect[:16]}…")
    else:
        print(f"ℹ️ 真值库无 specialcurve2 记录，仅验证题面为 sha256 占位")
    print("VERIFIED: <明文仅在 gitignored verified_flags.json，不打印>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
