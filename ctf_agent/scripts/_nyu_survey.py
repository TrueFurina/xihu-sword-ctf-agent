"""NYU CTF Bench 扩池可用面实测（只读）。

目的：把「预计 30+ 道可用」从估算变成实测——逐题读 challenge.json，判定
  1) 是否纯本地（无 compose / box / internal_port → 本项目离线框架可吃）
  2) 玩家分发文件（files 字段）数量与体积
  3) 采样验证 files 指向的文件在仓库中真实可下载

用法：
    python scripts/_nyu_survey.py                          # 全量普查
    python scripts/_nyu_survey.py --json out.json
    python scripts/_nyu_survey.py --verify-sample 20        # 抽样验证可下载性
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import urllib.parse
from collections import Counter, defaultdict
from urllib.request import ProxyHandler, build_opener

_REPO = "NYU-LLM-CTF/NYU_CTF_Bench"
_BR = "main"
_RAW = f"https://raw.githubusercontent.com/{_REPO}/{_BR}/"
_FOCUS = ("crypto", "rev", "forensics", "misc")


def _opener():
    op = build_opener(ProxyHandler({}))  # 绕开 Windows 系统代理污染
    op.addheaders = [("User-Agent", "Mozilla/5.0")]
    return op


def _raw(op, path: str, limit: int | None = None) -> str | None:
    url = _RAW + urllib.parse.quote(path)
    try:
        data = op.open(url, timeout=25).read()
    except Exception:  # noqa: BLE001
        return None
    txt = data.decode("utf-8", "ignore")
    return txt[:limit] if limit else txt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="")
    ap.add_argument("--verify-sample", type=int, default=0)
    args = ap.parse_args()

    op = _opener()
    ds = json.loads(_raw(op, "test_dataset.json") or "{}")
    print(f"[*] test_dataset.json: {len(ds)} 题", flush=True)

    for cat in sorted({v.get("category") for v in ds.values()}):
        n = sum(1 for v in ds.values() if v.get("category") == cat)
        print(f"    {cat:10s} {n}")

    rows = []
    focus_ids = [k for k, v in ds.items() if v.get("category") in _FOCUS]
    print(f"\n[*] 聚焦类别 {_FOCUS}: {len(focus_ids)} 题，逐题读 challenge.json ...", flush=True)
    for i, cid in enumerate(focus_ids, 1):
        v = ds[cid]
        cj = _raw(op, f"{v['path']}/challenge.json")
        rec = {"id": cid, "category": v.get("category"), "year": v.get("year"),
               "event": v.get("event"), "path": v["path"]}
        if not cj:
            rec.update({"err": "challenge.json 缺失", "local": None, "n_files": 0})
            rows.append(rec)
            continue
        try:
            m = json.loads(cj)
        except Exception as e:  # noqa: BLE001
            rec.update({"err": f"parse: {e}", "local": None, "n_files": 0})
            rows.append(rec)
            continue
        files = m.get("files") or []
        rec.update({
            "name": m.get("name"),
            "n_files": len(files),
            "files": files,
            "has_flag_field": bool(m.get("flag")),
            "remote": bool(m.get("compose")) or bool(m.get("box")) or bool(m.get("internal_port")),
            "compose": bool(m.get("compose")), "box": m.get("box") or "",
            "internal_port": m.get("internal_port"),
            "initial": m.get("initial"), "type": m.get("type"),
        })
        rec["local"] = (not rec["remote"]) and len(files) > 0
        rows.append(rec)
        if i % 20 == 0:
            print(f"    ... {i}/{len(focus_ids)}", flush=True)

    # 汇总
    print("\n=== 汇总 ===")
    by = defaultdict(lambda: Counter())
    for r in rows:
        c = r["category"]
        by[c]["总"] += 1
        if r.get("local") is True:
            by[c]["纯本地且有输入"] += 1
        elif r.get("local") is False and r.get("n_files", 0) == 0:
            by[c]["无分发文件"] += 1
        elif r.get("local") is False:
            by[c]["远程交互"] += 1
        if r.get("err"):
            by[c]["解析失败"] += 1
    tot_local = sum(1 for r in rows if r.get("local") is True)
    print(f"{'类别':10s} {'总数':>5s} {'纯本地且有输入':>14s} {'远程交互':>9s} {'无分发文件':>10s}")
    for c in sorted(by):
        b = by[c]
        print(f"{c:10s} {b['总']:5d} {b['纯本地且有输入']:14d} {b['远程交互']:9d} {b['无分发文件']:10d}")
    print(f"\n★ 纯本地且有输入（本项目可吃）: {tot_local} 题")

    if args.verify_sample:
        cand = [r for r in rows if r.get("local") is True]
        random.Random(20260930).shuffle(cand)
        picks = cand[: args.verify_sample]
        print(f"\n[*] 抽样验证 {len(picks)} 题的首个分发文件可下载性 ...", flush=True)
        ok = bad = 0
        for r in picks:
            f = (r.get("files") or [""])[0]
            got = _raw(op, f"{r['path']}/{f}", limit=1)
            flag = "OK" if got is not None else "FAIL"
            ok += got is not None
            bad += got is None
            print(f"    {flag:4s} {r['id']:34s} {f}")
        print(f"    可下载 {ok}/{len(picks)}（失败 {bad}）")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"focus": list(_FOCUS), "tasks": rows,
                       "summary": {c: dict(by[c]) for c in by},
                       "total_local_usable": tot_local}, fh, ensure_ascii=False, indent=2)
        print(f"\n-> {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
