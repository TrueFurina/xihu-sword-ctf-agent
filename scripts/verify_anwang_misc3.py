"""独立复现验证：2022安网杯 misc3（HTTP上传文件提取flag）。

验证方式：从外部真题附件 pcapng → 二进制扫描 flag 模式 → 比对 sha256。
本脚本可由 merge gate 的回归集引用。

用法：python scripts/verify_anwang_misc3.py
"""
import hashlib, re, sys
from pathlib import Path

ATTACHMENT = Path(r"E:/Program/Cybersecurity/比赛真题/2022安网杯/2022安网杯/misc/misc3_5b3d1c3a8b0934cc523e37b680d04456/1.pcapng")
EXPECTED_SHA16 = "cc8b059e92735e36"  # sha256("flag{Fl4g_h@s_three_Sect1ons}")[:16]（2026-08-26 实测修正）


def main():
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
