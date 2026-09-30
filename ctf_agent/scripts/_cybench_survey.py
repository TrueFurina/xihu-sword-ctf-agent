"""Cybench 开源基准调研（只读）：盘点 40 题的类别/难度/是否需联网/真输入文件数。

用法：
    python scripts/_cybench_survey.py            # 打印摘要表
    python scripts/_cybench_survey.py --json out.json

目的：回答「开源标杆能否作为本项目扩池弹药」——重点是每题 challenge/ 下
真输入文件数与 internet.necessary（离线静态分析框架只能吃本地题）。
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from urllib.request import ProxyHandler, build_opener

_REPO = "andyzorigin/cybench"
_BRANCH = "main"
_RAW = f"https://raw.githubusercontent.com/{_REPO}/{_BRANCH}/"
_API = f"https://api.github.com/repos/{_REPO}"


def _opener():
    # 强制直连：绕开 Windows 注册表系统代理污染（本机已知坑）
    op = build_opener(ProxyHandler({}))
    op.addheaders = [("User-Agent", "Mozilla/5.0")]
    return op


def _raw(op, path: str) -> str:
    url = _RAW + urllib.parse.quote(path)
    return op.open(url, timeout=30).read().decode("utf-8", "ignore")


def _tree(op) -> dict:
    """一次性取全仓文件清单，避免逐目录 contents API 触发限流。"""
    d = json.load(op.open(f"{_API}/git/trees/{_BRANCH}?recursive=1", timeout=60))
    return d


def _files_by_task(tree: dict) -> dict:
    """从全仓 tree 里按题目目录聚合各类文件。

    ⚠️ 2026-09-30 修正：输入目录形态不统一，早期只认 `challenge/` 导致
    「17 题无真输入」误报。实测三种形态：
      - `challenge/`（sekaictf / hackthebox crypto）→ 玩家分发文件
      - `release/`、`dist/`（hackthebox rev / forensics）→ 玩家分发压缩包
      - `assets/`（hackthebox rev / forensics）→ **writeup 配图，内含 flag.png=答案**
    另有 GlacierCTF 未提交进本仓（tree 中 0 路径）→ 子模块/上游仓库，需单独取。
    """
    INPUT_DIRS = ("challenge", "release", "dist", "files")
    out: dict = {}
    for node in tree.get("tree", []):
        p = node.get("path", "")
        if node.get("type") != "blob" or not p.startswith("benchmark/"):
            continue
        rec = None
        for d in INPUT_DIRS:
            idx = p.find(f"/{d}/")
            if idx != -1:
                out.setdefault(p[:idx], {"inputs": [], "solution": [], "assets": []})
                out[p[:idx]]["inputs"].append(
                    {"path": p, "name": p.split("/")[-1], "size": node.get("size", 0), "dir": d})
                rec = True
                break
        if rec:
            continue
        for d, key in (("metadata/solution", "solution"), ("assets", "assets")):
            idx = p.find(f"/{d}/")
            if idx != -1:
                out.setdefault(p[:idx], {"inputs": [], "solution": [], "assets": []})
                out[p[:idx]][key].append(
                    {"path": p, "name": p.split("/")[-1], "size": node.get("size", 0), "dir": d})
                break
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    op = _opener()
    tasks = [ln.strip() for ln in _raw(op, "task_list.txt").splitlines() if ln.strip()]
    print(f"[*] task_list.txt: {len(tasks)} 题", flush=True)

    tree = _tree(op)
    print(f"[*] repo tree: {len(tree.get('tree', []))} 节点 truncated={tree.get('truncated')}", flush=True)
    files = _files_by_task(tree)

    rows = []
    for t in tasks:
        meta = {}
        try:
            meta = json.loads(_raw(op, f"{t}/metadata/metadata.json"))
        except Exception as e:  # noqa: BLE001
            meta = {"_err": f"{type(e).__name__}: {e}"}
        f = files.get(t, {"inputs": [], "solution": [], "assets": []})
        internet = meta.get("internet") or {}
        rows.append({
            "task": t,
            "competition": t.split("/")[1] if len(t.split("/")) > 1 else "?",
            "categories": meta.get("categories") or [],
            "difficulty": meta.get("difficulty"),
            "internet_necessary": bool(internet.get("necessary")),
            "internet_useful": bool(internet.get("useful")),
            "target_host": meta.get("target_host") or "",
            "n_subtasks": len(meta.get("subtasks") or []),
            "input_files": [x["name"] for x in f["inputs"]],
            "n_input_files": len(f["inputs"]),
            "input_bytes": sum(x["size"] for x in f["inputs"]),
            "input_dirs": sorted({x["dir"] for x in f["inputs"]}),
            "solution_files": [x["name"] for x in f["solution"]],
            "asset_flag_leak": any("flag" in x["name"].lower() for x in f["assets"]),
            "not_in_repo": not f["inputs"] and not f["solution"] and not f["assets"],
            "has_flag_txt": any(x["name"] == "flag.txt" for x in f["solution"]),
            "has_solver": any("solver" in x["name"] or x["name"].endswith(".sh") for x in f["solution"]),
            "err": meta.get("_err", ""),
        })
        r = rows[-1]
        print(f"    {t.split('/',1)[1][:56]:56s} cat={','.join(r['categories']):11s} "
              f"d={r['difficulty']} net={'Y' if r['internet_necessary'] else 'n'} "
              f"in={r['n_input_files']}{r['input_dirs']} sub={r['n_subtasks']}"
              f"{' [NOT-IN-REPO]' if r['not_in_repo'] else ''}"
              f"{' [assets有flag]' if r['asset_flag_leak'] else ''}", flush=True)

    # 汇总
    local = [r for r in rows if not r["internet_necessary"] and not r["target_host"]]
    usable = [r for r in local if r["n_input_files"] > 0]
    print("\n=== 汇总 ===")
    print(f"总题数                  : {len(rows)}")
    print(f"本地（无需联网/靶机）    : {len(local)}")
    print(f"  └ 其中真有输入文件      : {len(usable)}   ← 本项目可吃")
    print(f"需联网/靶机             : {len(rows) - len(local)}")
    print(f"未提交进本仓(子模块)     : {len([r for r in rows if r['not_in_repo']])}")
    print(f"assets/ 内含 flag 图    : {len([r for r in rows if r['asset_flag_leak']])}  ← 基准自身的答案泄露面")
    by_cat: dict = {}
    for r in usable:
        for c in (r["categories"] or ["?"]):
            by_cat.setdefault(c, []).append(r)
    print("\n可吃题按类别（难度分布 / 平均输入文件数）：")
    for c, rs in sorted(by_cat.items(), key=lambda kv: -len(kv[1])):
        ds = sorted(str(x["difficulty"]) for x in rs)
        print(f"  {c:12s} {len(rs):2d} 题  难度={ds}  "
              f"平均输入={sum(x['n_input_files'] for x in rs)/len(rs):.1f}  "
              f"总体积={sum(x['input_bytes'] for x in rs)/1024:.0f}KB")
    noin = [r for r in local if r["n_input_files"] == 0]
    if noin:
        print(f"\n⚠️ 本地但无输入文件: {len(noin)}")
        for r in noin:
            print(f"    {'[未提交]' if r['not_in_repo'] else '[仅提示词]'} {r['task']}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"tasks": rows, "summary": {
                "total": len(rows), "local": len(local), "usable": len(usable),
                "by_category_usable": {c: len(v) for c, v in by_cat.items()}}},
                f, ensure_ascii=False, indent=2)
        print(f"\n-> {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
