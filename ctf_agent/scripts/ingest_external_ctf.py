#!/usr/bin/env python3
"""
外部 CTF 平台题源注入器（P0-① 扩 strict held-out 真·未见池的离线脚手架，2026-09-22）。

为什么存在
----------
真·未见池当前只有 2 题（dnui_keyboard / real_reverse_js），统计无效。
开放 CTF 平台（picoCTF / CTFtime / RingZer0 / crackmes.one / pwnable.kr …）
是廉价拿到「有官方 flag 可校验 + 类别多样」题源的唯一渠道。本脚本把外部
题源灌入本地题库，使其能被 `benchmark_heldout.py` 的既有排除链统一筛选。

三条诚实红线（与 held-out 口径一致，违反即拒绝入库）
---------------------------------------------------
1. ground-truth 只存 `flag_sha256`，明文 flag 永不落盘。
   若 staging 给了明文 `flag`，本脚本现场算 sha256 后**丢弃明文**再写文件。
2. `description` 必须由挑战 brief 撰写，不得照 writeup 反推。
   写入时强制 `provenance=real_past_ctf` + `external_source` 标注来源；
   若 staging 显式 `source_reconstructed_from_writeup=true` 则拒收（交给既有排除链）。
3. attachments 不得含明文 flag。整链 `_has_plaintext_flag_in_source()` 会在
   `benchmark_heldout.py` 选题时确定性拦截；本脚本做 best-effort 预检告警。

用法
----
  # 1) 看字段格式（自文档）
  python scripts/ingest_external_ctf.py --emit-example > staging.example.json

  # 2) 灌库（默认落到 data/questions_external/）
  python scripts/ingest_external_ctf.py --staging staging.json

  # 3) 仅校验不写
  python scripts/ingest_external_ctf.py --staging staging.json --dry-run
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL_DIR = ROOT / "data" / "questions_external"
VALID_CATS = ("web", "crypto", "misc", "reverse", "pwn")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_FLAG_RE = re.compile(r"(?:flag|dasctf|ctf|xctf|d0g3|d0gz)\{[^{}]*\}", re.I)


def _path_rel(p) -> str:
    """相对 ROOT 显示；若不在 ROOT 下（外部题源可能在仓库外）则回退绝对路径。"""
    p = Path(p)
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.strip().encode("utf-8")).hexdigest()


def validate(q: dict) -> list[str]:
    """返回错误列表；空列表表示可入库。同时就地补全 flag_sha256 / provenance。"""
    errs: list[str] = []
    qid = q.get("id")
    if not qid or not isinstance(qid, str):
        errs.append("missing/empty id")
        qid = "<no-id>"
    if not q.get("title"):
        errs.append(f"{qid}: missing title")
    cat = (q.get("category") or "").lower()
    if cat not in VALID_CATS:
        errs.append(f"{qid}: bad category {cat!r} (want one of {VALID_CATS})")
    if not q.get("description"):
        errs.append(f"{qid}: missing description")

    # 红线②：来源与重建标记
    prov = q.get("provenance", "real_past_ctf")
    if prov != "real_past_ctf":
        errs.append(f"{qid}: provenance must be 'real_past_ctf' (got {prov!r})")
    if not q.get("external_source"):
        errs.append(f"{qid}: missing external_source (e.g. 'picoctf-2023')")
    if q.get("source_reconstructed_from_writeup"):
        errs.append(f"{qid}: source_reconstructed_from_writeup=true refused (红线②)")

    # 红线①：ground-truth 只存 sha256
    fs = q.get("flag_sha256")
    plain = q.get("flag")
    if fs:
        if not _SHA256_RE.match(str(fs)):
            errs.append(f"{qid}: flag_sha256 not 64-hex")
    elif plain:
        # 红线①：现场算哈希后丢弃明文，明文永不落盘
        if _FLAG_RE.search(str(plain)):
            q["flag_sha256"] = sha256_hex(str(plain))
            q.pop("flag", None)
        else:
            errs.append(f"{qid}: flag not a flag-format string and no flag_sha256")
    else:
        errs.append(f"{qid}: need flag_sha256 or flag(明文, 现场哈希)")

    # 红线③：best-effort 预检 attachment 明文 flag
    for a in (q.get("attachments") or []):
        p = ROOT / str(a)
        if p.is_file():
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeError):
                continue
            if _FLAG_RE.search(text):
                errs.append(f"{qid}: attachment {a} 含明文 flag 串（红线③）")
    return errs


def ingest_one(q: dict, out_dir: Path, dry_run: bool) -> tuple[bool, str]:
    errs = validate(q)
    if errs:
        return False, "; ".join(errs)
    cat = (q.get("category") or "").lower()
    qid = str(q["id"])
    # 写盘前删掉任何残留明文 flag / 重建标记，防误留
    q.pop("flag", None)
    q.pop("source_reconstructed_from_writeup", None)
    q.setdefault("provenance", "real_past_ctf")
    q.setdefault("flag_pattern", r"flag\{[^}]+\}")
    q.setdefault("difficulty", "unknown")
    dest = out_dir / cat / f"{qid}.json"
    if dry_run:
        return True, f"[dry-run] would write {dest.relative_to(ROOT)}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(q, ensure_ascii=False, indent=1), encoding="utf-8")
    return True, f"wrote {_path_rel(dest)}"


def emit_example() -> dict:
    return {
        "_comment": "staging schema for ingest_external_ctf.py。flag_sha256 与 flag(明文) 二选一；"
                    "给 flag 会现场哈希后丢弃明文。external_source 必填。",
        "questions": [
            {
                "id": "ext_picoctf2023_hello",
                "title": "Hello World (示例)",
                "category": "misc",
                "description": "按挑战 brief 撰写（不要照 writeup 反推）。本题要求…",
                "flag_sha256": "REPLACE_WITH_64HEX_SHA256_OF_PLAINTEXT_FLAG",
                "external_source": "picoctf-2023",
                "attachments": [],
                "difficulty": "EASY",
            },
            {
                "id": "ext_ringzer0_xss_demo",
                "title": "XSS demo (明文 flag 现场哈希示例)",
                "category": "web",
                "description": "由 brief 撰写：某页面存在反射型 XSS…",
                "flag": "flag{THIS_IS_A_PLACEHOLDER_REPLACE_ME}",
                "external_source": "ringzer0",
                "attachments": [],
            },
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="外部 CTF 题源注入器（离线脚手架）")
    ap.add_argument("--staging", help="staging JSON 路径（含 {questions:[...]}）")
    ap.add_argument("--emit-example", action="store_true",
                    help="打印 staging 示例 schema 到 stdout 并退出")
    ap.add_argument("--external-dir", default=str(EXTERNAL_DIR),
                    help=f"输出目录（默认 {EXTERNAL_DIR}）")
    ap.add_argument("--dry-run", action="store_true", help="只校验不写盘")
    args = ap.parse_args()

    if args.emit_example:
        print(json.dumps(emit_example(), ensure_ascii=False, indent=2))
        return 0
    if not args.staging:
        ap.error("需要 --staging 或 --emit-example")
    staging_path = Path(args.staging)
    if not staging_path.is_file():
        print(f"[ingest] staging 不存在: {staging_path}", file=sys.stderr)
        return 2
    try:
        blob = json.loads(staging_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[ingest] staging JSON 解析失败: {exc}", file=sys.stderr)
        return 2
    qs = blob.get("questions") if isinstance(blob, dict) else blob
    if not isinstance(qs, list):
        print("[ingest] staging 顶层需为 {questions:[...]} 或 [...] 列表", file=sys.stderr)
        return 2

    out_dir = Path(args.external_dir).resolve()
    ok, fail = 0, 0
    for q in qs:
        if not isinstance(q, dict):
            print(f"[ingest] 跳过非对象条目: {q!r}")
            fail += 1
            continue
        good, msg = ingest_one(q, out_dir, args.dry_run)
        if good:
            ok += 1
            print(f"[ingest] OK  {msg}")
        else:
            fail += 1
            print(f"[ingest] FAIL {msg}", file=sys.stderr)
    print(f"[ingest] 完成：{ok} 成功 / {fail} 失败"
          + ("（dry-run，未写盘）" if args.dry_run else ""))
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
