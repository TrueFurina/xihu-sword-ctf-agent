"""批量解压所有题库（2026-08-22——疯狂刷题准备）。

遍历 data/ 全部 .zip——安全解压（大小限制防炸弹）——解压成功后
删除原压缩包（用户已授权「解压后原有的压缩包可以删除」）。
用文件方式执行（python scripts/_extract_all.py——内嵌 -c 脚本在
本环境会被吞——文件方式可靠）。日志写 data/results/extract_log.txt。
"""
import glob
import os
import sys
import zipfile

ROOTS = ["data/attachments", "data/results", "data"]
MAX_TOTAL = 300_000_000  # 300MB 上限（防 zip 炸弹）
LOG_PATH = "data/results/extract_log.txt"


def main() -> int:
    zips = []
    for r in ROOTS:
        zips.extend(glob.glob(os.path.join(r, "**", "*.zip"), recursive=True))
    zips = sorted(set(zips))
    log = open(LOG_PATH, "w", encoding="utf-8")
    print(f"发现 {len(zips)} 个 zip", file=log, flush=True)
    ok_cnt = skip_cnt = fail_cnt = 0
    for zp in zips:
        try:
            with zipfile.ZipFile(zp) as z:
                total = sum(i.file_size for i in z.infolist())
                if total > MAX_TOTAL:
                    print(f"SKIP {zp}（{total//1024//1024}MB 超大）", file=log, flush=True)
                    skip_cnt += 1
                    continue
                d = zp[:-4] + "_x/"
                os.makedirs(d, exist_ok=True)
                z.extractall(d)
                ok_cnt += 1
                print(f"OK {os.path.basename(zp)} -> {os.path.basename(d)}", file=log, flush=True)
            # 解压成功后删原包（用户授权）
            os.remove(zp)
            print(f"DEL {os.path.basename(zp)}", file=log, flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"FAIL {os.path.basename(zp)}: {type(e).__name__} {str(e)[:60]}", file=log, flush=True)
            fail_cnt += 1
    print(f"RESULT ok={ok_cnt} skip={skip_cnt} fail={fail_cnt} total={len(zips)}", file=log, flush=True)
    log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
