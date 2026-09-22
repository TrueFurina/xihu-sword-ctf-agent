#!/usr/bin/env python3
"""
Google CTF 官方题源抓取器（P0-① 扩 strict held-out 真·未见池，2026-09-22）。

为什么是 Google CTF
-------------------
`github.com/google/google-ctf` 历年（2021-2025）真题的 `metadata.yaml` 同时含：
  - `description`：**官方原始 brief**（非 writeup 反推）→ 满足红线②
  - `flag`：**固定明文**（非 per-instance 随机，故可算 sha256 做真值）→ 满足红线①
  - `category`：crypto / pwn / rev / web / misc
选手文件在 `attachments/`（**只取这个目录**；`solution/` `src/` `challenge/` 可能含解法，一律排除）。
注入本地后，明文 flag 交由 `ingest_external_ctf.py` 现场哈希并丢弃、永不落盘。

三条诚实红线（与 ingest 一致，抓取阶段先做确定性预检）
---------------------------------------------------
1. ground-truth 只存 `flag_sha256`：staging 里给明文 `flag`，ingest 现场哈希后丢弃。
2. brief 来自官方 `description`（非 writeup）。
3. **attachments 字节级不含明文 flag**：逐文件 byte-search，命中即整题剔除（
   `_is_leaked_attachment` 的路径启发式与 `_has_plaintext_flag_in_source` 的
   web/misc 闸都覆盖不到外部 crypto/rev，故必须在此确定性把关）。

用法
----
  python scripts/fetch_google_ctf.py --dry-run                 # 只枚举+预检，不下载
  python scripts/fetch_google_ctf.py --years 2023,2024 --categories crypto,rev,misc --max 20
  # 产物: data/questions_external/<cat>/<id>/_attachments/** + staging JSON
  # 然后: python scripts/ingest_external_ctf.py --staging <staging.json>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "google/google-ctf"
BRANCH = "main"
EXTERNAL_DIR = ROOT / "data" / "questions_external"
STAGING_OUT = ROOT / "data" / "results" / "google_ctf_staging.json"
# Google 用 "rev"，本仓统一用 "reverse"
CAT_MAP = {"crypto": "crypto", "pwn": "pwn", "rev": "reverse", "web": "web", "misc": "misc"}
_FLAG_RE = re.compile(r"(?:flag|CTF|dasctf|ctf|xctf|d0g3|d0gz)\{[^{}]*\}", re.I)
_SLUG_RE = re.compile(r"[^0-9a-z]+")


def _opener():
    # 强制直连：本机 Windows 注册表有失效系统代理（Clash 7890），走代理会 URLError
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _api(op, path: str, timeout: int = 30):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github+json"})
    with op.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "ignore"))


def _raw(op, path: str, cap: int = 4_000_000, timeout: int = 60) -> bytes:
    req = urllib.request.Request(
        f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/{path}",
        headers={"User-Agent": "Mozilla/5.0"})
    with op.open(req, timeout=timeout) as r:
        return r.read(cap)


def parse_metadata(text: str) -> dict:
    """容错解析 metadata.yaml（只用 name/description/flag/category，避免 yaml 依赖）。"""
    out: dict = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = re.match(r"^(\w+):\s*(.*)$", ln)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key not in ("name", "description", "flag", "category"):
                i += 1
                continue
            if key == "description" and val in ("|", "|+", "|-", ">", ">+", ">-", ""):
                # 多行块：取后续缩进行
                block = []
                j = i + 1
                while j < len(lines) and (lines[j].startswith(" ") or lines[j].startswith("\t")):
                    block.append(lines[j].strip())
                    j += 1
                out[key] = "\n".join(block).strip()
                i = j
                continue
            out[key] = val.strip("'\"")
        i += 1
    return out


def _slug(s: str) -> str:
    return _SLUG_RE.sub("-", (s or "").lower()).strip("-")[:40]


def enumerate_challenges(op, tree: list[dict], years: set[str], cats: set[str]):
    """返回 [(ch_dir, meta, player_files)]；player_files 仅取 attachments/ 下的 blob。"""
    metas = [e["path"] for e in tree if e["path"].endswith("/metadata.yaml")]
    result = []
    for mp in sorted(metas):
        parts = mp.split("/")
        year = parts[0]
        if year not in years:
            continue
        ch_dir = mp.rsplit("/", 1)[0]
        rel = f"{ch_dir}/metadata.yaml"
        # 只取 attachments/ 下的给选手文件（排除 solution/src/challenge 等）
        player = [e for e in tree
                  if e["path"].startswith(f"{ch_dir}/attachments/") and e["type"] == "blob"]
        if not player:
            continue
        try:
            meta = parse_metadata(_raw(op, rel, cap=100_000).decode("utf-8", "ignore"))
        except Exception as exc:  # noqa: BLE001
            print(f"  [skip] {ch_dir}: metadata 读取失败 {exc}")
            continue
        raw_cat = (meta.get("category") or "").strip().lower()
        cat = CAT_MAP.get(raw_cat)
        if not cat or cat not in cats:
            continue
        if not meta.get("description"):
            print(f"  [skip] {ch_dir}: 无 description")
            continue
        result.append((ch_dir, meta, cat, player))
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Google CTF 官方题源抓取器")
    ap.add_argument("--years", default="2023,2024", help="逗号分隔年份（2021-2025）")
    ap.add_argument("--categories", default="crypto,rev,misc",
                    help="逗号分隔类别（本仓口径：crypto,reverse,web,misc,pwn）")
    ap.add_argument("--max", type=int, default=20, help="最多抓取题数")
    ap.add_argument("--max-file-mb", type=float, default=1.5, help="单附件大小上限（MB）")
    ap.add_argument("--dry-run", action="store_true", help="只枚举+预检，不下载/不写盘")
    args = ap.parse_args()

    years = {y.strip() for y in args.years.split(",") if y.strip()}
    cats = {c.strip() for c in args.categories.split(",") if c.strip()}
    max_bytes = int(args.max_file_mb * 1024 * 1024)

    op = _opener()
    print(f"[fetch] 拉取 {REPO} 树 …")
    tree = _api(op, f"/repos/{REPO}/git/trees/{BRANCH}?recursive=1").get("tree", [])
    tree = [e for e in tree if e.get("type") == "blob"]
    print(f"[fetch] 树 {len(tree)} blobs")

    chals = enumerate_challenges(op, tree, years, cats)
    print(f"[fetch] 命中 {len(chals)} 题（years={sorted(years)} cats={sorted(cats)}）")

    staging: list[dict] = []
    leak_skipped: list[str] = []
    for ch_dir, meta, cat, player in chals:
        if len(staging) >= args.max:
            break
        flag = (meta.get("flag") or "").strip()
        if not _FLAG_RE.fullmatch(flag):
            print(f"  [skip] {ch_dir}: flag 非法/空 ({flag!r})")
            continue
        flag_bytes = flag.encode("utf-8")
        year = ch_dir.split("/")[0]
        cid = f"ext_gctf{year}_{_slug(meta.get('name') or ch_dir.split('/')[-1])}"

        # 下载 + 字节级查泄露（红线③）
        downloads: list[tuple[str, bytes]] = []
        skip_this = False
        for e in player:
            rel_in_ch = e["path"][len(ch_dir) + 1:]        # attachments/xxx
            if e.get("size", 0) > max_bytes:
                print(f"  [skip] {ch_dir}: 附件过大 {e['path']} ({e['size']}B)")
                skip_this = True
                break
            if args.dry_run:
                continue
            try:
                blob = _raw(op, e["path"], cap=max_bytes + 1024)
            except Exception as exc:  # noqa: BLE001
                print(f"  [skip] {ch_dir}: 下载失败 {e['path']} {exc}")
                skip_this = True
                break
            if flag_bytes in blob:
                leak_skipped.append(f"{cid}:{rel_in_ch}")
                skip_this = True
                break
            downloads.append((rel_in_ch, blob))
        if skip_this:
            continue

        # 落盘 attachments
        att_rel_paths: list[str] = []
        if not args.dry_run:
            base = EXTERNAL_DIR / cat / cid / "_attachments"
            for rel_in_ch, blob in downloads:
                dest = base / rel_in_ch[len("attachments/"):] if rel_in_ch.startswith("attachments/") else base / rel_in_ch
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(blob)
                att_rel_paths.append(str(dest.relative_to(ROOT)))

        staging.append({
            "id": cid,
            "title": meta.get("name") or cid,
            "category": cat,
            "description": meta.get("description"),
            "flag": flag,                       # 明文 → ingest 现场哈希后丢弃
            "external_source": f"google-ctf-{year}",
            "source_repo": f"https://github.com/{REPO}/tree/{BRANCH}/{ch_dir}",
            "license": "Apache-2.0",
            "attachments": att_rel_paths,
            "difficulty": "unknown",
        })
        print(f"  [ok] {cid} [{cat}] attachments={len(downloads)}")

    if leak_skipped:
        print(f"[fetch] 泄露剔除 {len(leak_skipped)} 题: {leak_skipped}")
    print(f"[fetch] staging = {len(staging)} 题")
    if args.dry_run:
        print("[fetch] dry-run：未下载未写盘")
        return 0
    STAGING_OUT.parent.mkdir(parents=True, exist_ok=True)
    STAGING_OUT.write_text(
        json.dumps({"questions": staging}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[fetch] staging 写出 → {STAGING_OUT}（含明文 flag，跑完 ingest 后须删除）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
