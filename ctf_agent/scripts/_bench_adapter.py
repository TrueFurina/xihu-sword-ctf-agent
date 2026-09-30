"""开源 CTF 基准适配器：把 NYU CTF Bench / Cybench 的真输入题转成本项目 Question JSON。

设计依据（2026-09-30 对标调研，见 deliverables/规划手册/开源基准对标与扩池方案_20260930.md）：
  - Cybench 的 `challenge/` vs `metadata/solution/` 是「输入 / 答案物理分离」范本；
  - NYU 的 `challenge.json.files` 显式列出玩家可获得的分发文件，`flag` 另存字段。

安全红线（本脚本存在的理由 —— 把「答案泄进题包」从约定变成机器强制）：
  R1 答案文件一律不进 attachments：名字级（flag.txt/solve.py/README.md/writeup…）
     + 目录级（/solution/ /answers/ /metadata/）；
  R2 明文 flag 不落盘、不进 JSON：只写 sha256（沿用本项目 cases.py 真 flag 红线）；
  R3 下载后反注水校验（fail-closed）：任何附件的 sha256 == flag_sha256，
     或文本内容含明文 flag，则丢弃该附件并记账 —— 因为「附件即答案」的题不可测；
  R4 字节预算硬顶：单文件 + 单题 + 全局三层封顶（默认 20MB/60MB/300MB），
     防止误拉 2.4GB 全仓；
  R5 只落盘不执行：下载的二进制/脚本绝不运行。

用法：
    python scripts/_bench_adapter.py --source nyu --limit 5            # 试点 5 题
    python scripts/_bench_adapter.py --source nyu --ids a,b,c          # 指定题
    python scripts/_bench_adapter.py --source nyu --list               # 只列清单，不下载
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

# 能力信封分档（同目录零依赖模块）：落盘时给每题打 A/B/C/D1/D2
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _envelope_band  # noqa: E402

# ---------------------------------------------------------------- 常量

RAW = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"
TREE_API = "https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"

SOURCES = {
    "nyu": {
        "repo": "NYU-LLM-CTF/NYU_CTF_Bench",
        "branch": "main",
        "survey": "../logs/nyu_survey_20260930.json",
        "license": "GPL-2.0",
    },
    "cybench": {
        "repo": "andyzorigin/cybench",
        "branch": "main",
        "survey": "../logs/cybench_survey_20260930.json",
        "license": "Apache-2.0",
    },
}

# R1 名字级答案排除（不区分大小写，按 basename 判定）
ANSWER_EXACT = {
    "flag.txt", "flag", "flag.md", "flag.png", "flag.jpg", "flag.jpeg",
    "solve.py", "solver.py", "solution.py", "soln.py", "sol.py", "writeup.py",
    "readme.md", "readme.txt", "readme", "solution.md", "writeup.md",
    "challenge.json", ".gitignore", ".gitmodules", "docker-compose.yml",
    "docker-compose.yaml", "metadata.json",
}
ANSWER_PREFIX = ("writeup", "solution", "solver", "solve_", "answer", "exploit")
# R1 目录级答案排除
ANSWER_DIRS = ("/solution/", "/solutions/", "/answers/", "/metadata/", "/writeup/",
               "/writeups/", "/assets/", "/docs/")

FLAG_SHAPE = re.compile(r"[A-Za-z0-9_]{1,12}\{[^}\s]{3,120}\}")

# R4 字节预算
MAX_FILE_MB = 20
MAX_TASK_MB = 60
MAX_TOTAL_MB = 300
_TEXT_EXT = {".py", ".txt", ".md", ".json", ".yml", ".yaml", ".cfg", ".ini",
             ".sh", ".c", ".h", ".go", ".js", ".ts", ".java", ".rs", ".pem", ".asm"}
_TEXT_SNIFF = 4096  # 内容级校验最多读这么多字节


def _opener():
    """绕过 Windows 系统代理（本项目实锤：代理污染会伪装成网络不可达）。"""
    op = build_opener(ProxyHandler({}))
    op.addheaders = [("User-Agent", "Mozilla/5.0")]
    return op


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _is_answer_name(name: str) -> bool:
    low = name.lower()
    if low in ANSWER_EXACT:
        return True
    return any(low.startswith(p) for p in ANSWER_PREFIX)


def _is_answer_path(path: str) -> bool:
    norm = "/" + path.replace("\\", "/").lower().strip("/") + "/"
    return any(d in norm for d in ANSWER_DIRS)


# ---------------------------------------------------------------- 取数

def fetch_tree(op, src: dict) -> dict:
    url = TREE_API.format(repo=src["repo"], branch=src["branch"])
    d = json.load(op.open(url, timeout=120))
    if d.get("truncated"):
        raise RuntimeError("tree 被截断，需降级为逐目录 API —— 本仓未预期")
    return {n["path"]: n for n in d.get("tree", []) if n.get("type") == "blob"}


def fetch_raw(op, src: dict, path: str, limit: int = 1_000_000) -> bytes:
    url = RAW.format(repo=src["repo"], branch=src["branch"],
                     path=urllib.parse.quote(path))
    return op.open(url, timeout=60).read(limit)


def resolve_files(tree: dict, task_path: str, declared: list[str]) -> tuple[list[str], list[str]]:
    """把 challenge.json 声明的文件名解析成 tree 里的真实路径。

    返回 (resolved, notes)。三级回退：
      1) task_path + 声明名 精确命中（去掉 ./ 前缀）
      2) task_path 子树内 basename 相同
      3) 全仓 basename 相同（取唯一命中，多命中放弃 —— 宁可记账不猜）
    """
    resolved: list[str] = []
    notes: list[str] = []
    prefix = task_path.rstrip("/") + "/"

    for decl in declared:
        want = decl.replace("\\", "/").lstrip("./").strip()
        cand = prefix + want
        if cand in tree:
            resolved.append(cand)
            continue
        base = want.split("/")[-1]
        # 2) 子树内同名
        subs = [p for p in tree if p.startswith(prefix) and p.split("/")[-1] == base]
        if len(subs) == 1:
            resolved.append(subs[0])
            notes.append(f"{decl} -> {subs[0]} (子树同名回退)")
            continue
        # 3) 全仓同名且唯一
        glob = [p for p in tree if p.split("/")[-1] == base]
        if len(glob) == 1:
            resolved.append(glob[0])
            notes.append(f"{decl} -> {glob[0]} (全仓唯一同名回退)")
            continue
        notes.append(f"UNRESOLVED {decl} (子树{len(subs)}命中/全仓{len(glob)}命中)")
    return resolved, notes


# ---------------------------------------------------------------- 校验

def audit_attachment(data: bytes, name: str, flag_plain: str | None) -> str | None:
    """R3 反注水校验。返回拒绝原因，None 表示通过。"""
    if flag_plain:
        # 附件字节级就是答案（如 flag.txt 改名）
        if _sha256_bytes(data) == _sha256_bytes(flag_plain.encode("utf-8")):
            return "附件 sha256 == flag sha256（附件即答案）"
    ext = Path(name).suffix.lower()
    if ext in _TEXT_EXT or len(data) < 64 * 1024:
        try:
            head = data[:_TEXT_SNIFF].decode("utf-8", "ignore")
            if flag_plain and flag_plain in head:
                return "文本内容含明文 flag"
        except Exception:
            pass
    return None


# ---------------------------------------------------------------- 主流程

def build_one(op, src: dict, tree: dict, rec: dict, out_dir: Path,
              att_root: Path, budget: dict) -> dict:
    """处理一道题：解析文件 → 下载 → 校验 → 落盘 → 返回元数据记录。"""
    tid = rec["id"]
    cat = rec["category"]
    tpath = rec["path"]
    result = {"id": tid, "category": cat, "source": src["repo"], "status": "?", "notes": []}

    # 1) 拉 challenge.json / flag
    flag_plain = None
    declared = list(rec.get("files") or [])
    for cand in (f"{tpath}/challenge.json", f"{tpath}/flag.txt", f"{tpath}/flag"):
        if cand not in tree:
            continue
        try:
            raw = fetch_raw(op, src, cand, limit=200_000)
        except Exception as exc:
            result["notes"].append(f"{cand} 拉取失败 {type(exc).__name__}")
            continue
        if cand.endswith("challenge.json"):
            try:
                meta = json.loads(raw.decode("utf-8", "ignore"))
            except Exception:
                result["notes"].append("challenge.json 解析失败")
                continue
            # NYU 的 files 字段更权威（survey 里的 files 来自它，但可能被截断）
            if isinstance(meta.get("files"), list) and meta["files"]:
                declared = [str(x) for x in meta["files"]]
            if meta.get("flag"):
                flag_plain = str(meta["flag"]).strip()
                result["notes"].append("flag 取自 challenge.json")
            if meta.get("description"):
                result["description"] = str(meta["description"])[:1500]
        else:
            # 2026-09-30 修复：challenge.json 的 flag 字段是权威真值，flag.txt/flag
            # 仅作回退。此前 flag.txt 会覆盖 challenge.json.flag，且 flag.txt 可能
            # 是包装文本（如 1nsayne 的 'hi! flag is: flag{...}'）——整段 hash 出
            # 错误答案。回退时也只提取 flag 形状，不整段采信。
            if flag_plain:
                result["notes"].append(f"跳过 {Path(cand).name}（challenge.json 已给权威 flag）")
                continue
            text = raw.decode("utf-8", "ignore").strip()
            m = FLAG_SHAPE.search(text)
            flag_plain = m.group(0) if m else text
            result["notes"].append(f"flag 取自 {Path(cand).name}" + ("（形状提取）" if m else "（原样，无形状）"))

    if not flag_plain:
        result["status"] = "NO_FLAG"
        result["notes"].append("未找到 flag 真值，跳过（无法判定对错）")
        return result

    result["flag_sha256"] = _sha256_bytes(flag_plain.encode("utf-8"))

    # 2) 解析分发文件
    resolved, notes = resolve_files(tree, tpath, declared)
    result["notes"].extend(notes)

    # R1 过滤（解析后仍要过滤：子树回退可能捞到 README）
    keep = []
    for p in resolved:
        bn = p.split("/")[-1]
        if _is_answer_name(bn) or _is_answer_path(p):
            result["notes"].append(f"R1 剔除答案类文件 {p}")
            continue
        keep.append(p)

    # 3) 下载 + R3/R4 校验
    task_dir = att_root / cat / tid
    task_bytes = 0
    saved = []
    for p in keep:
        size = tree[p].get("size", 0)
        if size > MAX_FILE_MB * 1024 * 1024:
            result["notes"].append(f"R4 单文件超限跳过 {p} ({size/1048576:.1f}MB)")
            continue
        if task_bytes + size > MAX_TASK_MB * 1024 * 1024:
            result["notes"].append(f"R4 单题预算超限，停止下载 {p}")
            break
        if budget["used"] + size > MAX_TOTAL_MB * 1024 * 1024:
            result["status"] = "BUDGET_STOP"
            result["notes"].append("R4 全局预算超限，停止")
            return result
        try:
            data = fetch_raw(op, src, p, limit=size + 1024)
        except Exception as exc:
            result["notes"].append(f"下载失败 {p}: {type(exc).__name__}")
            continue
        reason = audit_attachment(data, p.split("/")[-1], flag_plain)
        if reason:
            result["status"] = "DISCARDED"
            result["notes"].append(f"R3 反注水丢弃 {p}: {reason}")
            return result
        task_dir.mkdir(parents=True, exist_ok=True)
        (task_dir / Path(p).name).write_bytes(data)
        task_bytes += len(data)
        budget["used"] += len(data)
        saved.append(p)

    if not saved:
        result["status"] = "NO_INPUT"
        result["notes"].append("无任何可用真输入文件（不可测）")
        return result

    # 4) 写本项目 Question JSON
    rel_atts = [str((att_root / cat / tid / Path(p).name)).replace("\\", "/")
                for p in saved]

    # 能力信封分档（零 LLM 成本）：落盘即自带 band，免得每次人肉诊断。
    # 2026-10-01：首测「0/5」里 4/5 题在信封外（pcap/视觉/qemu/ELF），
    # 把「框架边界」误读成了「解题能力」。固化后任何批次都能自动分层汇报。
    try:
        band, band_reason = _envelope_band.classify(
            rel_atts, result.get("description", ""), cat, base=Path.cwd())
    except Exception as exc:                       # 分档失败不阻断落盘
        band, band_reason = "?", f"分档异常 {type(exc).__name__}"
    doc = {
        "id": f"ext_{src['repo'].split('/')[-1].lower()}_{tid.replace('-', '_')}",
        "provenance": "real_past_ctf",
        "category": cat,
        "title": f"{rec.get('event','')} {rec.get('year','')} {rec.get('name', tid)}".strip(),
        "description": result.get("description") or f"{rec.get('event','')} {rec.get('year','')} {cat} 真实赛题，输入文件见附件。",
        "flag": result["flag_sha256"],          # R2 只存 sha256
        "flag_sha256": result["flag_sha256"],
        "flag_pattern": r"[A-Za-z0-9_]{1,12}\{[^}\s]{3,120}\}",
        "attachments": rel_atts,
        "difficulty": "MEDIUM",
        "extra": {
            "upstream": src["repo"], "upstream_path": tpath,
            "upstream_license": src["license"],
            "event": rec.get("event"), "year": rec.get("year"),
            "envelope_band": band,          # A/B/C/D1/D2，见 scripts/_envelope_band.py
            "envelope_reason": band_reason,
        },
    }
    out_file = out_dir / cat / f"{doc['id']}.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")

    result["status"] = "OK"
    result["envelope_band"] = band
    result["n_saved"] = len(saved)
    result["bytes"] = task_bytes
    result["json"] = str(out_file)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="nyu", choices=sorted(SOURCES))
    ap.add_argument("--survey", default=None, help="清单 JSON（默认取 source 约定路径）")
    ap.add_argument("--limit", type=int, default=0, help="最多处理几题（0=全部）")
    ap.add_argument("--ids", default="", help="逗号分隔的题 id，指定则忽略 limit")
    ap.add_argument("--list", action="store_true", help="只列清单不下载")
    ap.add_argument("--out-dir", default="data/questions_ext")
    ap.add_argument("--att-root", default="data/questions_ext/_attachments")
    args = ap.parse_args()

    src = SOURCES[args.source]
    survey_path = args.survey or src["survey"]
    survey = json.loads(Path(survey_path).read_text(encoding="utf-8"))
    tasks = survey.get("tasks", [])

    # 只取「本地可吃」的题；cybench 用 internet_necessary 字段
    if args.source == "nyu":
        cand = [t for t in tasks if t.get("local") and t.get("files")]
    else:
        cand = [t for t in tasks
                if not t.get("internet_necessary") and not t.get("target_host")
                and t.get("n_challenge_files")]

    if args.ids:
        want = {x.strip() for x in args.ids.split(",") if x.strip()}
        cand = [t for t in cand if t["id"] in want]
    elif args.limit:
        cand = cand[: args.limit]

    print(f"来源 {src['repo']} ({src['license']}) | 候选 {len(cand)} 题")
    if args.list:
        for t in cand:
            print(f"  {t['category']:9s} {t['id']:32s} {t.get('files')}")
        return 0

    op = _opener()
    t0 = time.time()
    print("拉取 tree ...", end="", flush=True)
    tree = fetch_tree(op, src)
    print(f" {len(tree)} blobs ({time.time()-t0:.1f}s)")

    out_dir = Path(args.out_dir)
    att_root = Path(args.att_root)
    budget = {"used": 0}
    results = []
    for i, rec in enumerate(cand, 1):
        r = build_one(op, src, tree, rec, out_dir, att_root, budget)
        results.append(r)
        mb = budget["used"] / 1048576
        print(f"[{i:2d}/{len(cand)}] {r['status']:12s} {r['id']:32s} "
              f"saved={r.get('n_saved','-')} {r.get('bytes',0)/1024:.0f}KB "
              f"| 累计 {mb:.1f}MB", flush=True)
        for n in r["notes"][:4]:
            print(f"        · {n}")

    # 汇总
    from collections import Counter
    print("\n=== 汇总 ===")
    print("状态:", dict(Counter(r["status"] for r in results)))
    ok = [r for r in results if r["status"] == "OK"]
    print(f"可测题: {len(ok)}/{len(results)} | 落盘 {budget['used']/1048576:.2f}MB | "
          f"耗时 {time.time()-t0:.1f}s")
    print("按类别:", dict(Counter(r["category"] for r in ok)))
    bands = Counter(r.get("envelope_band", "?") for r in ok)
    print("按能力信封:", dict(sorted(bands.items())))
    print(f"  -> A 档（纯静态，唯一可解释的能力分母）= {bands.get('A', 0)}；"
          f"信封外 = {sum(v for k, v in bands.items() if k != 'A')}")

    report = Path("../logs")
    report.mkdir(exist_ok=True)
    rp = report / f"bench_adapter_{args.source}_{time.strftime('%Y%m%d-%H%M%S')}.json"
    rp.write_text(json.dumps({"source": src["repo"], "results": results},
                             ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"-> {rp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
