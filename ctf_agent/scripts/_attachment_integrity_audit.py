# -*- coding: utf-8 -*-
"""外部题池附件完整性审计（¥0、确定性）。

背景
----
能力缺口清单把 `electric-mayhem×2`（侧信道）与 `abc-arm-and-amd`（跨架构）归类为
「工具链/需靶机，离线不可做」。实测发现它们的附件**根本不是有效载荷**：
- electric-mayhem：21–27 字节的空 `.tgz`；
- abc-arm-and-amd：24–28 字节，内容是符号链接目标路径文本
  （如 `../challenge/chal-aarch64`）。

即：这些题是**数据缺陷**（抓取器把软链接当文本抓下、或抓到占位空包），
不是「缺工具链」也不是「缺靶机」。把它们算进"能力不足"会系统性低估能力分母，
故本脚本全池扫描，给出可复核的判定。

判定口径（任一命中即 DEFECT）
---------------------------
1. 文件 < 64 字节（不可能含有意义的二进制/数据集）；
2. 内容是路径文本：以 `../`、`./`、`/` 开头且不含换行/二进制字节；
3. git-lfs 指针（`version https://git-lfs`）或 HTML 错误页（`<html`/`404`）；
4. 0 字节。

用法::

    python scripts/_attachment_integrity_audit.py            # 打印报告
    python scripts/_attachment_integrity_audit.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

POOL = os.path.join(_ROOT, "data", "questions_external")
MIN_BYTES = 64


def _classify(path: str) -> str:
    """返回 'OK' 或缺陷原因。"""
    try:
        size = os.path.getsize(path)
    except OSError:
        return "MISSING"
    if size == 0:
        return "EMPTY"
    if size < MIN_BYTES:
        return f"TOO_SMALL({size}B)"
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return "UNREADABLE"
    if head.startswith(b"version https://git-lfs"):
        return "GIT_LFS_POINTER"
    low = head[:200].lower()
    if b"<html" in low or b"<!doctype" in low or b"404 not found" in low:
        return "HTML_ERROR_PAGE"
    # 路径文本（软链接目标）：纯可打印、无空格、以路径符开头或以已知扩展名结尾
    if head[:3] in (b"../", b"./\x00", b"./") or (
            head[:1] == b"/" and b"\n" not in head[:64]):
        try:
            txt = head.split(b"\n")[0].decode("ascii")
        except UnicodeDecodeError:
            return "OK"
        if txt.startswith(("../", "./", "/")) and " " not in txt:
            return f"SYMLINK_TEXT({txt[:40]})"
    return "OK"


def audit(pool: str = POOL) -> Dict:
    rows: List[Dict] = []
    if not os.path.isdir(pool):
        return {"pool": pool, "error": "目录不存在", "rows": []}
    for cat in sorted(os.listdir(pool)):
        cdir = os.path.join(pool, cat)
        if not os.path.isdir(cdir):
            continue
        for fn in sorted(os.listdir(cdir)):
            if not fn.endswith(".json"):
                continue
            meta = json.load(open(os.path.join(cdir, fn), encoding="utf-8"))
            qid = meta.get("id", fn[:-5])
            adir = os.path.join(cdir, qid, "_attachments")
            files: List[str] = []
            if os.path.isdir(adir):
                for root, _, fs in os.walk(adir):
                    for f in fs:
                        files.append(os.path.join(root, f))
            verdicts = {f: _classify(f) for f in files}
            bad = {f: v for f, v in verdicts.items() if v != "OK"}
            rows.append({
                "id": qid,
                "category": meta.get("category"),
                "n_attachments": len(files),
                "defects": bad,
                "has_defect": bool(bad) or (files and len(bad) == len(files)),
                "no_attachment_at_all": not files,
            })
    defect_q = [r for r in rows if r["defects"]]
    return {
        "pool": pool,
        "n_questions": len(rows),
        "n_questions_with_defect": len(defect_q),
        "rows": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="外部题池附件完整性审计")
    ap.add_argument("--pool", default=POOL)
    ap.add_argument("--json", dest="json_out")
    a = ap.parse_args()
    rep = audit(a.pool)
    if rep.get("error"):
        print("❌", rep["error"])
        return 1
    print(f"题库: {rep['pool']}")
    print(f"题目数: {rep['n_questions']} | 含附件缺陷: "
          f"{rep['n_questions_with_defect']}")
    print("-" * 70)
    for r in rep["rows"]:
        if not r["defects"]:
            continue
        print(f"❌ {r['id']} ({r['category']}) 附件 {r['n_attachments']} 个")
        for f, v in r["defects"].items():
            print(f"     {os.path.basename(f)}: {v}")
    if a.json_out:
        json.dump(rep, open(a.json_out, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print(f"\n已写出 {a.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
