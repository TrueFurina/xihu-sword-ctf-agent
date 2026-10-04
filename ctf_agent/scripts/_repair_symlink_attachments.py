# -*- coding: utf-8 -*-
"""修复「附件是软链接路径文本」的抓取缺陷（2026-10-04）。

背景
----
`scripts/fetch_google_ctf.py` 对 ``attachments/`` 下每个 blob 直接 raw 下载，
而 GitHub 对**软链接**（tree 里 ``mode == "120000"``）返回的是**目标路径文本**
（几十字节），不是真实文件。结果外部池 **21/40 道题的"附件"只是路径字符串**，
这些题实际是「不可测」而非「不可解」（见 ``_attachment_integrity_audit.py``）。

修复思路（只修坏文件，不重跑全量、不碰完好的题）
----------------------------------------------
坏文件的内容**恰好就是软链接目标**，配合题面 JSON 的 ``source_repo``
（形如 ``.../tree/main/2021/quals/misc-shellcode``）即可还原真实路径：

    ch_dir = 2021/quals/misc-shellcode
    软链位置 = ch_dir/attachments/chal-aarch64
    目标文本 = ../challenge/chal-aarch64
    => 真实路径 = 2021/quals/misc-shellcode/challenge/chal-aarch64

真实路径会与 GitHub tree 交叉校验（存在性 + 大小），下载后二次校验
（不得又是路径文本、大小须与 tree 一致），通过才写回。

安全约束
--------
* 反注水：basename 命中 flag/solution/writeup 等答案类名字 → **跳过不写**
  （明文 flag 已不在本地，只能做名字级守卫；字节级守卫仍在原抓取流程里）。
* 默认 ``--dry-run`` 预演，确认无误后再实写。
* 只重写审计判定为缺陷的文件，完好的题一个字节都不动。

用法::

    python scripts/_repair_symlink_attachments.py            # 预演
    python scripts/_repair_symlink_attachments.py --apply    # 实写
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POOL = ROOT / "data" / "questions_external"
REPO = "google/google-ctf"
BRANCH = "main"
RAW = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/" + "{path}"
TREE_API = f"https://api.github.com/repos/{REPO}/git/trees/{BRANCH}?recursive=1"

# 名字级答案排除（与 fetch_google_ctf / _bench_adapter 同口径）
ANSWER_EXACT = {
    "flag.txt", "flag", "flag.md", "flag.png", "flag.jpg", "flag.jpeg",
    "solve.py", "solver.py", "solution.py", "soln.py", "sol.py", "writeup.py",
    "solution.md", "writeup.md", "exploit.py", "answer.txt", "answer",
}
ANSWER_PREFIX = ("writeup", "solution", "solver", "solve_", "answer", "exploit")


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get(op, url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ctf-agent-repair"})
    return op.open(req, timeout=timeout).read()


def norm_join(base: str, target: str) -> str:
    t = target.lstrip("/") if target.startswith("/") else \
        ((base + "/" + target) if base else target)
    parts: list[str] = []
    for seg in t.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/".join(parts)


def resolve_chain(op, sym_dir: str, target: str, by_path: dict,
                  max_depth: int = 5) -> tuple[str | None, dict | None]:
    """跟随**链式**软链接（A -> B -> 真实文件），返回 (真实路径, tree 节点)。"""
    cur_dir, cur_target = sym_dir, target
    seen: set[str] = set()
    for _ in range(max_depth):
        real = norm_join(cur_dir, cur_target)
        if real in seen:
            return None, None
        seen.add(real)
        node = by_path.get(real)
        if node is None:
            return None, None
        if str(node.get("mode")) != "120000":
            return real, node
        try:
            txt = _get(op, RAW.format(path=urllib.parse.quote(real)),
                       timeout=60).decode("utf-8", "ignore").strip()
        except Exception:  # noqa: BLE001
            return None, None
        if not txt or len(txt) > 512 or "\n" in txt:
            return None, None
        # 下一跳：以当前软链接所在目录为基准
        cur_dir = real.rsplit("/", 1)[0] if "/" in real else ""
        cur_target = txt
    return None, None


def is_answer_name(name: str) -> bool:
    low = name.lower()
    return low in ANSWER_EXACT or low.startswith(ANSWER_PREFIX)


def looks_like_path_text(data: bytes) -> bool:
    try:
        t = data.decode("ascii").strip()
    except Exception:  # noqa: BLE001
        return False
    return bool(t) and " " not in t and (
        t.startswith("../") or t.startswith("./") or t.startswith("/"))


def audit_defects() -> dict:
    """复用完整性审计，返回 {qid: [缺陷文件绝对路径]}。"""
    sys.path.insert(0, str(ROOT))
    from scripts._attachment_integrity_audit import audit  # 延迟导入避免循环
    rep = audit(str(POOL))
    return {r["id"]: list(r["defects"].keys()) for r in rep["rows"] if r["defects"]}


def find_json(qid: str) -> Path | None:
    hits = glob.glob(str(POOL / "*" / f"{qid}.json"))
    return Path(hits[0]) if hits else None


def ch_dir_from(source_repo: str) -> str | None:
    m = re.search(r"/tree/[^/]+/(.+)$", str(source_repo or ""))
    return m.group(1).rstrip("/") if m else None


def main() -> int:
    ap = argparse.ArgumentParser(description="修复软链接型附件缺陷")
    ap.add_argument("--apply", action="store_true", help="实写（默认预演）")
    ap.add_argument("--limit", type=int, default=0, help="最多处理几题（0=全部）")
    ap.add_argument("--max-file-mb", type=float, default=1.5,
                    help="单附件上限（MB），与 fetch_google_ctf 默认一致")
    args = ap.parse_args()
    max_bytes = int(args.max_file_mb * 1024 * 1024)

    defects = audit_defects()
    print(f"审计判定缺陷题: {len(defects)}")
    if not defects:
        return 0

    op = _opener()
    print("[repair] 拉取 GitHub 树 …")
    tree = json.loads(_get(op, TREE_API, timeout=120)).get("tree", [])
    by_path = {e["path"]: e for e in tree if e.get("type") == "blob"}
    print(f"[repair] 树 {len(by_path)} blobs")

    stats = {"repaired": 0, "skipped_answer": 0, "unresolved": 0,
             "fetch_fail": 0, "still_text": 0, "size_mismatch": 0,
             "question_skipped": 0}
    details: list[str] = []
    for i, (qid, files) in enumerate(sorted(defects.items())):
        if args.limit and i >= args.limit:
            break
        jp = find_json(qid)
        if jp is None:
            details.append(f"❓ {qid}: 找不到 JSON")
            continue
        meta = json.loads(jp.read_text(encoding="utf-8"))
        ch_dir = ch_dir_from(meta.get("source_repo", ""))
        if not ch_dir:
            details.append(f"❓ {qid}: source_repo 无法解析 ch_dir")
            continue
        # ---- 第一遍：整题预检（任一文件超限/无法解析 → 整题跳过，保持 NO_INPUT）
        plan: list[tuple[str, str, bytes, int]] = []
        blocked: list[str] = []
        for fp in sorted(files):
            rel_in_att = os.path.relpath(fp, jp.parent / qid / "_attachments")
            raw = Path(fp).read_bytes()
            if not looks_like_path_text(raw):
                continue
            target = raw.decode("ascii").strip()
            sym_dir = f"{ch_dir}/attachments"
            sub = os.path.dirname(rel_in_att).replace("\\", "/")
            if sub:
                sym_dir = f"{sym_dir}/{sub}"
            real, node = resolve_chain(op, sym_dir, target, by_path)
            if real is None or node is None:
                blocked.append(f"目标无法解析/不在 tree ({norm_join(sym_dir, target)})")
                continue
            if is_answer_name(os.path.basename(real)):
                blocked.append(f"答案类文件 ({real})")
                continue
            size = int(node.get("size", 0))
            if size > max_bytes:
                blocked.append(f"超 {args.max_file_mb}MB 上限 ({real} {size}B)")
                continue
            plan.append((rel_in_att, real, raw, size))
        if blocked:
            stats["question_skipped"] += 1
            details.append(f"  ⊘ {qid}: 整题跳过 —— " + "；".join(blocked[:3]))
            continue

        # ---- 第二遍：下载 + 校验 + 写回
        for rel_in_att, real, raw, size in plan:
            fp = jp.parent / qid / "_attachments" / rel_in_att
            try:
                blob = _get(op, RAW.format(path=urllib.parse.quote(real)), timeout=120)
            except Exception as exc:  # noqa: BLE001
                stats["fetch_fail"] += 1
                details.append(f"  ✗ {qid}/{rel_in_att}: 下载失败 {type(exc).__name__}")
                continue
            if looks_like_path_text(blob) and len(blob) < 64:
                stats["still_text"] += 1
                details.append(f"  ✗ {qid}/{rel_in_att}: 目标仍是路径文本")
                continue
            if size and abs(len(blob) - size) > 1024:
                stats["size_mismatch"] += 1
                details.append(
                    f"  ✗ {qid}/{rel_in_att}: 大小不符 ({len(blob)} vs tree {size})")
                continue
            if args.apply:
                Path(fp).write_bytes(blob)
            stats["repaired"] += 1
            details.append(
                f"  ✓ {qid}/{rel_in_att}: {len(raw)}B -> {len(blob)}B ({real})")

    print("\n".join(details))
    print("-" * 60)
    print(f"{'实写' if args.apply else '预演'}统计: {stats}")
    if not args.apply:
        print("（加 --apply 才会写盘）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
