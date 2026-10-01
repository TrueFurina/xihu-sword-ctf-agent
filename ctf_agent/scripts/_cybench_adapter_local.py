"""Cybench 本地适配器：把已克隆到本机的 Cybench 基准转成本项目 Question JSON。

与 `_bench_adapter.py` 的区别 —— 本脚本 **完全离线**：
  Cybench 官方 harness 需要 Docker + Python3.9-3.10 + WSL（本机三个阻塞），
  但本项目只做**静态分析**，不需要它的容器环境；只要把「玩家可见的分发文件」
  抽出来即可。因此直接读本地 `2027-prep/cybench` 仓库，零网络、零 LLM、零成本。

安全红线（与 `_bench_adapter.py` 同源，把「答案泄进题包」从约定变成机器强制）：
  R1 答案文件一律不进 attachments：名字级（flag.*/solve.py/README.md/…）+ 目录级（/solution/ /metadata/）
  R2 明文 flag 不落盘、不进 JSON：只写 sha256
  R3 内容级反注水（fail-closed）：任何附件若字节含明文 flag、或 sha256 == flag sha256，
     一律剔除并记账。**若全题附件都被剔除 → 判 CONTAMINATED 跳过**（附件即答案的题不可测）
  R4 只落盘不执行：二进制/脚本绝不运行；解包只读、防 zip-slip
  R5 字节预算：单文件 + 单题封顶

用法：
    python scripts/_cybench_adapter_local.py --list
    python scripts/_cybench_adapter_local.py
    python scripts/_cybench_adapter_local.py --repo ../2027-prep/cybench --out-dir data/questions_ext_cybench
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _envelope_band  # noqa: E402

# ---------------------------------------------------------------- 常量

# R1 名字级答案排除
ANSWER_EXACT = {
    "flag.txt", "flag", "flag.md", "flag.py", "flag.png", "flag.jpg", "flag.jpeg",
    "solve.py", "solver.py", "solution.py", "soln.py", "sol.py", "writeup.py",
    "readme.md", "readme.txt", "readme", "solution.md", "writeup.md",
    "challenge.json", ".gitignore", ".gitmodules", "docker-compose.yml",
    "docker-compose.yaml", "metadata.json",
}
ANSWER_PREFIX = ("writeup", "solution", "solver", "solve_", "answer", "exploit", "flag")
ANSWER_DIRS = ("/solution/", "/solutions/", "/answers/", "/metadata/", "/writeup/",
               "/writeups/", "/assets/", "/docs/")

FLAG_SHAPE = re.compile(r"[A-Za-z0-9_]{1,12}\{[^}\s]{3,120}\}")

MAX_FILE_MB = 20
MAX_TASK_MB = 60

# Cybench 类别 → 本项目类别
CAT_MAP = {"reverse": "rev", "reversing": "rev"}
# Cybench 难度（0-5 数字）→ 文本标签
DIFF_LABEL = {0: "EASY", 1: "EASY", 2: "MEDIUM", 3: "MEDIUM", 4: "HARD", 5: "HARD"}


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _is_answer_name(name: str) -> bool:
    low = name.lower()
    if low in ANSWER_EXACT:
        return True
    return any(low.startswith(p) for p in ANSWER_PREFIX)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


# ---------------------------------------------------------------- 输入收集

def collect_inputs(base: Path) -> tuple[list[Path], list[Path], str]:
    """返回 (普通文件列表, 需解包的 zip 列表, 来源说明)。

    优先 `challenge/`（HTB 玩家工作目录）→ `dist/` → `files/` → `release/`。
    release 下若存在 *.zip，则只解包这些 zip（玩家下载的即 zip），忽略同目录已解开的副本。
    """
    for d in ("challenge", "dist", "files"):
        p = base / d
        if p.exists():
            files = [x for x in p.rglob("*") if x.is_file()]
            if files:
                return files, [], f"dir:{d}"
    rel = base / "release"
    if rel.exists():
        zips = sorted(rel.glob("*.zip"))
        if zips:
            return [], zips, "zip:release"
        files = [x for x in rel.rglob("*") if x.is_file()]
        if files:
            return files, [], "dir:release"
    return [], [], "none"


def safe_extract_names(zf: zipfile.ZipFile) -> list[str]:
    """zip 内合法成员名（防 zip-slip / 目录项）。"""
    out = []
    for n in zf.namelist():
        if n.endswith("/"):
            continue
        norm = n.replace("\\", "/")
        if norm.startswith("/") or ".." in norm.split("/"):
            continue
        out.append(norm)
    return out


# ---------------------------------------------------------------- 主流程

def build_one(base: Path, meta: dict, out_dir: Path, att_root: Path) -> dict:
    tid = base.relative_to(base.parents[len(base.parts) - 1]) if False else None  # noqa
    slug = _slug(str(base).replace("\\", "/").split("benchmark/", 1)[-1])
    qid = f"ext_cybench_{slug}"
    cats = meta.get("categories") or ["?"]
    cat = CAT_MAP.get(cats[0], cats[0])
    result = {"id": qid, "category": cat, "status": "?", "notes": []}

    # 1) flag 真值（metadata/solution/flag.txt）
    flag_file = base / "metadata" / "solution" / "flag.txt"
    if not flag_file.exists():
        result["status"] = "NO_FLAG"
        result["notes"].append("无 metadata/solution/flag.txt")
        return result
    text = flag_file.read_text(encoding="utf-8", errors="ignore").strip()
    m = FLAG_SHAPE.search(text)
    flag_plain = m.group(0) if m else text
    if not flag_plain:
        result["status"] = "NO_FLAG"
        result["notes"].append("flag.txt 为空")
        return result
    result["flag_sha256"] = _sha256_bytes(flag_plain.encode("utf-8"))

    # 2) 收集玩家可见文件
    files, zips, src_kind = collect_inputs(base)
    result["input_source"] = src_kind
    if not files and not zips:
        result["status"] = "NO_INPUT"
        result["notes"].append("无挑战输入文件")
        return result

    # 3) 逐个入库（R1 名字过滤 → R3 内容校验 → 落盘）
    task_dir = att_root / cat / slug
    saved: list[str] = []
    dropped: list[str] = []
    flag_in: list[str] = []

    def _store(name: str, data: bytes) -> None:
        nonlocal saved
        base_name = name.split("/")[-1]
        if _is_answer_name(base_name) or any(d in "/" + name.lower() + "/" for d in ANSWER_DIRS):
            dropped.append(f"R1 {name}")
            return
        if len(data) > MAX_FILE_MB * 1024 * 1024:
            dropped.append(f"R4 单文件超限 {name}")
            return
        # R3：内容含明文 flag / sha 相同。
        # ⚠️ 2026-10-01 决策：**记录但保留**，不剔除 —— 因为 CTF 里「flag 就在二进制/文本里」
        # 往往是题目本意（如 Cybench LootStash 就是 strings 扒二进制的 Very Easy 题）。
        # 硬剔除会把「我方能解」的题压成「不可测」，系统性低估能力。
        # 名字级答案文件（flag.* / solver 等）仍由上面的 R1 硬剔除 —— 那才是真污染。
        if flag_plain.encode("utf-8") in data or _sha256_bytes(data) == result["flag_sha256"]:
            flag_in.append(name)
        task_dir.mkdir(parents=True, exist_ok=True)
        (task_dir / base_name).write_bytes(data)
        saved.append(f"{att_root.as_posix()}/{cat}/{slug}/{base_name}")

    for p in files:
        _store(p.name, p.read_bytes())
    for zp in zips:
        with zipfile.ZipFile(zp) as zf:
            for n in safe_extract_names(zf):
                _store(n, zf.read(n))

    if not saved:
        result["status"] = "CONTAMINATED"
        result["notes"].append("全部附件被 R1/R3 剔除 → 附件即答案，不可测")
        result["notes"].extend(dropped)
        return result

    # 4) 能力信封分档（零成本）
    desc = meta.get("hard_prompt") or meta.get("easy_prompt") or ""
    try:
        band, band_reason = _envelope_band.classify(saved, desc, cat, base=Path.cwd())
    except Exception as exc:  # noqa: BLE001
        band, band_reason = "?", f"分档异常 {type(exc).__name__}"

    diff_num = meta.get("difficulty")
    try:
        diff_num = int(diff_num)
    except Exception:  # noqa: BLE001
        diff_num = None

    doc = {
        "id": qid,
        "provenance": "real_past_ctf",
        "category": cat,
        "title": f"Cybench {cat} {slug.split('_')[-1]}",
        "description": desc[:1500],
        "flag": result["flag_sha256"],
        "flag_sha256": result["flag_sha256"],
        "flag_pattern": r"[A-Za-z0-9_]{1,12}\{[^}\s]{3,120}\}",
        "attachments": saved,
        "difficulty": DIFF_LABEL.get(diff_num, "MEDIUM"),
        "extra": {
            "upstream": "andyzorigin/cybench",
            "upstream_path": str(base).replace("\\", "/").split("benchmark/", 1)[-1],
            "upstream_license": "Apache-2.0",
            "difficulty_raw": diff_num,
            "envelope_band": band,
            "envelope_reason": band_reason,
            "dropped_attachments": dropped,
            "flag_in_attachment": flag_in,     # 非空 = 答案在题面文件里（多为题目本意）
        },
    }
    out_file = out_dir / cat / f"{qid}.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")

    result["status"] = "OK"
    result["envelope_band"] = band
    result["n_saved"] = len(saved)
    result["dropped"] = dropped
    result["flag_in_attachment"] = flag_in
    result["json"] = str(out_file)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="../2027-prep/cybench")
    ap.add_argument("--out-dir", default="data/questions_ext_cybench")
    ap.add_argument("--att-root", default="data/questions_ext_cybench/_attachments")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    repo = Path(args.repo)
    tl = repo / "task_list.txt"
    if not tl.exists():
        print(f"找不到 {tl} —— 先克隆 Cybench 到 {repo}")
        return 2
    tasks = [l.strip() for l in tl.read_text(encoding="utf-8").splitlines() if l.strip()]

    cand = []
    for t in tasks:
        base = repo / t
        mf = base / "metadata" / "metadata.json"
        if not mf.exists():
            continue
        meta = json.loads(mf.read_text(encoding="utf-8"))
        host = meta.get("target_host") or ""
        net = (meta.get("internet") or {}).get("necessary")
        files, zips, kind = collect_inputs(base)
        if host or net or (not files and not zips):
            continue
        cand.append((base, meta))

    print(f"Cybench 本地可吃题: {len(cand)}")
    if args.list:
        for base, meta in cand:
            files, zips, kind = collect_inputs(base)
            c0 = (meta.get("categories") or ["?"])[0]
            print(f"  {CAT_MAP.get(c0, c0):9s} "
                  f"d={meta.get('difficulty')} {kind:12s} {str(base).split('benchmark/')[-1]}")
        return 0

    out_dir = Path(args.out_dir)
    att_root = Path(args.att_root)
    results = []
    for base, meta in cand:
        r = build_one(base, meta, out_dir, att_root)
        results.append(r)
        print(f"  {r['status']:12s} {r['id'][:56]:56s} band={r.get('envelope_band','-'):2s} "
              f"saved={r.get('n_saved','-')}")
        for n in r["notes"][:3]:
            print(f"        · {n}")

    from collections import Counter
    ok = [r for r in results if r["status"] == "OK"]
    print("\n=== 汇总 ===")
    print("状态:", dict(Counter(r["status"] for r in results)))
    print("可测题:", len(ok), "/", len(results))
    print("按类别:", dict(Counter(r["category"] for r in ok)))
    print("按能力信封:", dict(sorted(Counter(r.get("envelope_band", "?") for r in ok).items())))
    fim = [r["id"] for r in ok if r.get("flag_in_attachment")]
    print(f"答案就在题面文件里（题目本意，记录不算污染）: {len(fim)} 题")
    for x in fim:
        print("   ·", x)
    rp = Path("../logs") / f"cybench_adapter_local_{time.strftime('%Y%m%d-%H%M%S')}.json"
    rp.write_text(json.dumps({"results": results}, ensure_ascii=False, indent=2), encoding="utf-8")
    print("->", rp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
