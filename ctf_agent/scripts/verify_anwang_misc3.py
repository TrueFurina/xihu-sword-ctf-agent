"""独立复现验证：2022安网杯 misc3（HTTP上传文件提取flag）。

验证方式：从外部真题附件 pcapng → 二进制扫描 flag 模式 → 比对 sha256。
本脚本可由 merge gate 的回归集引用。

用法：python scripts/verify_anwang_misc3.py
"""
import hashlib, re, sys
from pathlib import Path

# 真题附件路径（仓库内部;2026-08-27 将功补过尝试重建,但原始 pcapng 公开渠道不可得,缺失则优雅 SKIP）
_ATTACH_ROOT = Path(__file__).resolve().parents[1] / "data/questions_real/_attachments/anwang_misc3"
ATTACHMENT = _ATTACH_ROOT / "1.pcapng"
EXPECTED_SHA16 = "cc8b059e92735e36"  # sha256("flag{Fl4g_h@s_three_Sect1ons}")[:16]（2026-08-26 实测修正）


def main():
    if not ATTACHMENT.is_file():
        print("=== 外部真题源已失效 (EXTERNAL-SOURCE-MISSING) ===")
        print(f"  缺失: {ATTACHMENT}")
        print("=== 说明: 附件应位于仓库 data/questions_real/_attachments/anwang_misc3/1.pcapng (2026-08-27 将功补过尝试重建),")
        print("===       但原始 pcapng 公开渠道不可得,缺失则优雅跳过;本题为外部真题(非平台题),不计入严格 KPI。退出码 2。")
        return 2
    data = ATTACHMENT.read_bytes()
    hits = [m.group(0) for m in re.finditer(rb'[Ff][Ll1][Aa@][Gg]\{[^}\x00]{4,80}\}', data)]
    if not hits:
        print('[misc3] FAIL: no flag pattern found')
        return 1
    f = hits[0].decode(errors='replace')
    sha = hashlib.sha256(f.encode()).hexdigest()[:16]
    ok = sha == EXPECTED_SHA16
    print(f'[misc3] {"OK" if ok else "MISMATCH"} {f!r} sha16={sha}')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
