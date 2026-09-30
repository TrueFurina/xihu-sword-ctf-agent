"""能力信封分档（capability envelope band）—— 零 LLM 成本，纯本地判据。

为什么需要它（2026-10-01 实锤的误读）：
    NYU 首测抽了 5 题判「LLM 主链路 0/5」，但其中 4 题要求的根本不是解题能力，
    而是「跑 qemu / 解析 pcap / 看 jpg」——这些是本框架**架构上就没有**的能力。
    拿「4/5 在信封外」的样本测「解题水平」，测出来的是框架边界，不是能力。
    固化成本模块后，任何批次都能自动分层汇报，防止同类误读复发。

分档定义（互斥，按判定优先级从上到下）：
    D2  qemu      需模拟器（qemu/bochs/dosbox/磁盘镜像 + 题面关键词）
    D1  elf       需反汇编/执行二进制（附件魔数 ELF / PE / Mach-O）
    B   pcap      需抓包解析工具链（tshark 级）
    C   visual    需视觉/图像判读
    A   static    纯静态分析 —— **本框架唯一可解释的能力分母**

⚠️ 口径纪律：
    - A 档题数记为 `nyu_static_envelope`，是**独立口径**；
      禁止与 `heldout_candidates=2`（真值源里唯一合法的能力分母）相加或合并成一个率，
      也禁止与整池 34 混算（34 里含 14 题架构外题）。
    - 分档只描述「题型要求的外部能力」，不预测「能否解出」。

判据来源：`deliverables/锐评质检/扩池首测0of5的信封错位诊断_20261001.md` 第三节
（初版按「无扩展名即可执行」分档是错的，会把 `ciphertext` 这种纯文本误判 D1，
已用**魔数**修正）。

用法：
    python scripts/_envelope_band.py --pool data/questions_ext          # 扫池出分档表
    python scripts/_envelope_band.py --pool data/questions_ext --json x.json
    python scripts/_envelope_band.py --band A --pool data/questions_ext # 只列 A 档
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------- 判据表

BANDS = ("D2", "D1", "B", "C", "A")          # 优先级从高到低
BAND_LABEL = {
    "A": "纯静态分析（信封内，唯一可解释分母）",
    "B": "需 pcap 抓包解析工具链",
    "C": "需视觉/图像判读",
    "D1": "需反汇编/执行二进制（ELF/PE/Mach-O）",
    "D2": "需模拟器（qemu/bochs/dosbox）",
}

# D2：题面关键词（大小写不敏感）
QEMU_WORDS = ("qemu", "qemu-system", "bochs", "dosbox", "-drive ", "bochsbios",
              "virtualbox", "vmware")
# D2 兜底：磁盘镜像 + 题面提到启动/运行
DISK_EXT = {".img", ".iso", ".qcow2", ".vmdk", ".vdi", ".raw", ".bin"}
BOOT_WORDS = ("boot", "启动", "运行镜像", "emulate", "模拟器", "floppy", "mbr")

# D1：可执行魔数
ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce")

# B：抓包
PCAP_EXT = {".pcap", ".pcapng", ".cap"}
PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",          # pcap LE/BE
              b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",          # pcap 纳秒
              b"\x0a\x0d\x0d\x0a")                                # pcapng

# C：视觉（svg 是文本，不算视觉）
VISUAL_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
              ".webp", ".ico", ".ppm", ".pgm", ".xcf", ".psd"}

_MAGIC_READ = 16
_SNIFF = 4096                       # 文本性/归档窥探最多读这么多
_ARCHIVE_PEEK_MB = 20               # 归档清单窥探的字节上限（防 zip bomb）

# 归档：只读内部**文件名清单**，绝不解压落盘、绝不执行（R5）
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}

# 归档内部被视为「可执行」的形状（无扩展名的类 Unix 二进制也算）
EXEC_SHAPE = {".elf", ".so", ".out", ".o", ".bin", ".exe", ".dll", ".com", ".ko", ""}


# ---------------------------------------------------------------- 核心判定

def _read_head(path: Path, n: int = _MAGIC_READ) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(n)
    except Exception:
        return b""


def _looks_binary(head: bytes) -> bool:
    """内容级判「裸二进制」：NUL 多 / 不可打印字节多。

    修掉了两个方向的历史错误：
      - 初版按「无扩展名即可执行」→ 把 `ciphertext` 这种纯文本误判 D1；
      - 只信魔数 → 漏掉 `stage-2.bin` 这种无魔数的裸 x86 机器码（题面明写
        「Open stage2 in disassembler」，确实属于信封外）。
    """
    if not head:
        return False
    nul = head.count(b"\x00")
    if nul > max(1, len(head) // 20):        # NUL 占比 > 5%
        return True
    printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b <= 126)
    return printable < len(head) * 0.8       # 可打印 < 80%


def _peek_archive_names(path: Path) -> list[str] | None:
    """只读归档内部文件名清单。返回 None 表示窥探不了（不猜）。"""
    try:
        if path.stat().st_size > _ARCHIVE_PEEK_MB * 1024 * 1024:
            return None
    except Exception:
        return None
    suf = path.suffix.lower()
    try:
        import zipfile
        if suf == ".zip" and zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                return zf.namelist()
        import tarfile
        if suf in {".tar", ".tgz", ".gz", ".bz2", ".xz"} and tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                return tf.getnames()
    except Exception:
        return None
    return None


def _is_exec_magic(head: bytes) -> bool:
    if head.startswith(ELF_MAGIC):
        return True
    if head.startswith(MACHO_MAGICS):
        return True
    # PE/MZ：单凭 "MZ" 太松，必须后跟 DOS stub（0x3C 处有 e_lfanew 指针且文件够长）
    if head[:2] == PE_MAGIC and len(head) >= 8:
        return True
    return False


def _is_pcap_magic(head: bytes) -> bool:
    return head.startswith(PCAP_MAGIC)


def classify(attachments: list[str] | None,
             description: str = "",
             category: str = "",
             base: str | Path = ".") -> tuple[str, str]:
    """返回 (band, reason)。失败/无附件一律保守判 A 并在 reason 里说明。

    attachments 可以是相对路径（相对 base，默认 ctf_agent/）或绝对路径。
    """
    desc = (description or "").lower()
    atts = [a for a in (attachments or []) if a]
    if not atts:
        return "A", "无附件（纯题面）"

    root = Path(base)
    items: list[tuple[str, Path | None, bytes]] = []
    for a in atts:
        p = Path(a)
        cand = p if p.is_absolute() else (root / a)
        if not cand.exists():
            # 兜底：按 basename 在 attachments 常见根下找
            hits = []
            for gr in ("data/questions_ext/_attachments", "data/questions_ext",
                       "data/questions"):
                hits.extend((root / gr).rglob(p.name))
            cand = hits[0] if len(hits) == 1 else None
        items.append((p.name, cand, _read_head(cand, _SNIFF) if cand else b""))

    # --- D2 模拟器：题面关键词（最强信号，优先于魔数）
    for w in QEMU_WORDS:
        if w in desc:
            return "D2", f"题面要求模拟器（关键词 {w!r}）"
    if any(Path(n).suffix.lower() in DISK_EXT for n, _, _ in items):
        if any(w in desc for w in BOOT_WORDS):
            return "D2", "磁盘镜像 + 题面要求启动/模拟"

    # --- D1 可执行二进制：魔数
    for n, _, h in items:
        if _is_exec_magic(h):
            return "D1", f"附件 {n} 是可执行二进制（魔数）"

    # --- 归档：只读内部清单（不解压落盘、不执行），按内部形状递归一层
    # 归档本身的头（PK\x03\x04 / \x1f\x8b）必然是二进制，**绝不能**被后面的
    # 裸二进制兜底误吞——否则「内含纯文本的 zip」会被误判成需反汇编。
    archive_names: set[str] = set()
    unpeekable: list[str] = []
    for n, path, _ in items:
        if Path(n).suffix.lower() not in ARCHIVE_EXT or path is None:
            continue
        archive_names.add(n)
        names = _peek_archive_names(path)
        if names is None:
            unpeekable.append(n)
            continue
        inner_exec = [x for x in names
                      if Path(x).suffix.lower() in EXEC_SHAPE]
        if inner_exec:
            return "D1", f"归档 {n} 内含可执行形状文件（{inner_exec[0]}）"
        for x in names:
            if Path(x).suffix.lower() in PCAP_EXT:
                return "B", f"归档 {n} 内含抓包 {x}"
        for x in names:
            if Path(x).suffix.lower() in VISUAL_EXT:
                return "C", f"归档 {n} 内含图像 {x}"
    # 窥探不了的归档（7z/rar/损坏）内容未知 → 保守判信封外
    if unpeekable:
        return "D1", f"归档 {unpeekable[0]} 无法窥探内部清单，保守判需解包/专用工具"

    # --- B 抓包
    for n, _, h in items:
        if Path(n).suffix.lower() in PCAP_EXT or _is_pcap_magic(h):
            return "B", f"附件 {n} 是抓包文件（需 tshark 级解析）"

    # --- C 视觉
    vis = [n for n, _, _ in items if Path(n).suffix.lower() in VISUAL_EXT]
    if vis:
        return "C", f"附件 {vis[0]} 是图像（需视觉判读）"

    # --- D1 兜底：既无已知魔数、又不是文本的裸二进制（如 stage-2.bin 裸 x86 码）
    for n, _, h in items:
        if n in archive_names:      # 归档自身是二进制，不算「裸二进制」
            continue
        if _looks_binary(h):
            return "D1", f"附件 {n} 是裸二进制（无已知魔数但内容非文本，需反汇编）"

    # --- A 纯静态
    missing = [n for n, path, _ in items if path is None]
    tail = f"（{len(missing)} 个附件读不到，保守按纯静态）" if missing else ""
    return "A", f"全部附件为文本/数据，纯静态可分析{tail}"


# ---------------------------------------------------------------- 扫池

def classify_pool(pool_dir: str | Path, base: str | Path = ".") -> list[dict]:
    """扫一个题目录（如 data/questions_ext），逐题分档。跳过 _attachments。"""
    pool = Path(pool_dir)
    root = Path(base)
    out: list[dict] = []
    for jf in sorted(pool.rglob("*.json")):
        rel = jf.relative_to(pool)
        if any(part in {"_attachments", "answers", "_keys", "_solutions"}
               for part in rel.parts):
            continue
        try:
            doc = json.loads(jf.read_text(encoding="utf-8"))
        except Exception:
            continue
        band, reason = classify(doc.get("attachments") or [],
                                doc.get("description", ""),
                                doc.get("category", ""),
                                base=root)
        out.append({
            "id": doc.get("id") or jf.stem,
            "category": doc.get("category", "?"),
            "band": band,
            "reason": reason,
            "title": doc.get("title", ""),
            "n_att": len(doc.get("attachments") or []),
            "json": str(jf),
        })
    return out


def summary(rows: list[dict]) -> dict:
    from collections import Counter
    by_band = Counter(r["band"] for r in rows)
    by_cat_band: dict[str, dict[str, int]] = {}
    for r in rows:
        by_cat_band.setdefault(r["category"], {})
        by_cat_band[r["category"]][r["band"]] = \
            by_cat_band[r["category"]].get(r["band"], 0) + 1
    return {
        "total": len(rows),
        "by_band": {b: by_band.get(b, 0) for b in BANDS},
        "static_envelope": by_band.get("A", 0),
        "by_category": by_cat_band,
    }


# ---------------------------------------------------------------- CLI

def backfill(pool_dir: str | Path, base: str | Path = ".") -> int:
    """把 band 写回题 JSON 的 extra 字段（幂等，可重复跑）。返回写入题数。"""
    pool = Path(pool_dir)
    rows = classify_pool(pool, base=base)
    n = 0
    for r in rows:
        p = Path(r["json"])
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        ex = doc.setdefault("extra", {})
        ex["envelope_band"] = r["band"]
        ex["envelope_reason"] = r["reason"]
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
        n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="data/questions_ext")
    ap.add_argument("--base", default=".", help="attachments 相对路径的基准目录")
    ap.add_argument("--band", default="", choices=BANDS, help="只列该档")
    ap.add_argument("--json", default="", help="把分档表写到该路径")
    ap.add_argument("--write", action="store_true",
                    help="把 band 回填进题 JSON 的 extra（幂等）")
    args = ap.parse_args()

    if args.write:
        n = backfill(args.pool, base=args.base)
        print(f"已回填 envelope_band 到 {n} 题")

    rows = classify_pool(args.pool, base=args.base)
    s = summary(rows)

    print(f"题池 {args.pool} | 共 {s['total']} 题")
    print("分档：", end="")
    for b in BANDS:
        print(f"  {b}={s['by_band'][b]}", end="")
    print(f"   | A 档（静态信封）= {s['static_envelope']}")
    print()
    for cat in sorted(s["by_category"]):
        print(f"  {cat:10s} {s['by_category'][cat]}")

    if args.band:
        rows = [r for r in rows if r["band"] == args.band]
        print(f"\n=== {args.band} 档 {BAND_LABEL[args.band]}：{len(rows)} 题 ===")
    else:
        print("\n=== 逐题 ===")
    print(f"{'band':5s} {'cat':10s} {'id':46s} {'att':>3s}  reason")
    for r in rows:
        print(f"{r['band']:5s} {r['category']:10s} {r['id']:46s} "
              f"{r['n_att']:>3d}  {r['reason']}")

    if args.json:
        Path(args.json).write_text(
            json.dumps({"summary": s, "rows": rows}, ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"\n-> {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
