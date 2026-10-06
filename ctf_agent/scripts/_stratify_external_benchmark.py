#!/usr/bin/env python3
"""外部真题基准静态分层（2026-10-06 · 零 token 成本）。

为什么做
--------
2026-10-06 的 5 题盲测探针实测：引擎"解出 3/5"，但其中 2 题是**附件里答案直读**
（每题仅耗约 1k token，等于测文件读取而非推理）。若不先分层就全量跑，
"裸 LLM 在外部真题上的解出率"会被读文件能力注水——这正是反注水纪律要挡的事。

本脚本对基准里每道题做**纯静态**判定（不调 LLM、不花 token）：
  L0 直读型：附件字节里能直接扫到真值（sha256 命中）——测文件读取，不测推理
  L1 单候选型：附件里有 flag 形态字符串，但不是真值（需判断/变形/解码）
  L2 纯推理型：附件里没有任何 flag 形态字符串——必须真解题
  Lx 无载荷型：题面声明无附件（payload_status=no_attachment_needed）

同时给出附件类型分布（pcap / zip / 二进制 / 文本 / 图片），用于判断"哪类题需要补工具链"。

输出（写入基准目录）：
  STRATA.json     机器可读分层结果
  STRATA.md       人读摘要（表格 + 全量跑法建议）

用法
----
  python scripts/_stratify_external_benchmark.py --bench <benchmark.json> [--out-dir <同目录>]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

FLAG_RE = re.compile(rb"[A-Za-z0-9_]{1,20}\{[^}\s]{4,120}\}")

MAGIC = {
    "pcap": [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"],
    "pcapng": [b"\x0a\x0d\x0d\x0a"],
    "zip": [b"PK\x03\x04"],
    "gzip": [b"\x1f\x8b"],
    "png": [b"\x89PNG"],
    "jpg": [b"\xff\xd8\xff"],
    "elf": [b"\x7fELF"],
    "pdf": [b"%PDF"],
}


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def matches_truth(candidate: bytes, truth_digest: str) -> bool:
    """候选字节是否与真值摘要相符——全串与内文两种登记口径都试。

    注意方向：真值在题库里只能拿到 **sha256 摘要**（明文已迁出），
    因此必须"对候选算摘要"去比对真值，不能"对真值算摘要"（那是恒不相等的死路，
    2026-10-06 初版就是这么写的 → L0 层永不触发，分层表静默失真）。
    """
    truth = str(truth_digest or "").strip().lower()
    if not truth:
        return False
    if sha256_hex(candidate) == truth:
        return True
    m = re.search(rb"\{(.+)\}", candidate, re.DOTALL)
    return bool(m) and sha256_hex(m.group(1)) == truth


def detect_kind(head: bytes, name: str) -> str:
    low = name.lower()
    for kind, magics in MAGIC.items():
        if any(head.startswith(m) for m in magics):
            return kind
    for ext, kind in ((".pcap", "pcap"), (".pcapng", "pcapng"), (".zip", "zip"),
                      (".gz", "gzip"), (".tar", "tar"), (".png", "png"),
                      (".jpg", "jpeg"), (".jpeg", "jpeg"), (".elf", "elf"),
                      (".pdf", "pdf"), ((".txt", ".text"), "text"), ((".md",), "text")):
        if low.endswith(ext):
            return kind
    return "other"


def stratify(bench_path: Path, att_root: Path) -> dict:
    doc = json.loads(bench_path.read_text(encoding="utf-8"))
    problems = doc.get("problems", {})
    rows, kinds, cats = [], Counter(), Counter()
    for qid, p in sorted(problems.items()):
        atts = list(p.get("attachments") or ([p["attachment"]] if p.get("attachment") else []))
        truth = str(p.get("flag_sha256") or "").lower()
        scanned, direct_hit, cand_count, kinds_here = 0, False, 0, Counter()
        for a in atts:
            fp = (att_root / a)
            if not fp.is_file():
                continue
            raw = fp.read_bytes()
            scanned += 1
            kinds_here[detect_kind(raw[:16], fp.name)] += 1
            for c in FLAG_RE.findall(raw):
                cand_count += 1
                if matches_truth(c, truth):
                    direct_hit = True
            # 裸答案候选（2026-10-06 实锤补漏）：FLAG_RE 要求 `xxx{...}` 花括号形态，
            # 而部分题的答案是没有花括号的纯明文（如 `80`/`Cisc0`/`145`/32 位 hex），
            # 会被整题漏掉 → 答案明明躺在附件里却被判成 L2「纯推理层」，污染能力分母。
            # 仅对 <=4KB 附件做（真答案文件都是几十字节），不对 pcap/二进制全文做无意义比对；
            # 仍走 matches_truth 精确摘要比对，且未命中不计入 cand_count（不影响 L1/L2 判定）。
            if len(raw) <= 4096:
                for c in [raw.strip()] + [ln.strip() for ln in raw.splitlines()]:
                    if c and matches_truth(c, truth):
                        direct_hit = True
                        cand_count += 1
                        break
        if not atts:
            level = "L3_no_payload"          # 题面本就无附件
        elif scanned == 0:
            # 声明有附件但本机一份都没读到——不能记成"无附件"，那会把
            # "载荷缺失"伪装成"题简单"（2026-10-05 我方吃过这类亏：软链路径文本）
            level = "LX_attachment_unavailable"
        elif direct_hit:
            level = "L0_direct_read"
        elif cand_count > 0:
            level = "L1_single_candidate"
        else:
            level = "L2_pure_reasoning"
        kinds[level] += 1
        cats[p.get("category", "?")] += 1
        rows.append({"id": qid, "category": p.get("category", ""), "level": level,
                     "flag_shaped_strings_in_attachments": cand_count,
                     "attachments_scanned": scanned,
                     "attachment_kinds": dict(kinds_here),
                     "trained_in_westlake": bool(p.get("trained_in_westlake"))})
    return {"generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "benchmark": str(bench_path), "total": len(rows),
            "by_level": dict(kinds), "by_category": dict(cats),
            "unseen_pool": {k: v for k, v in kinds.items()},
            "rows": rows}


def to_markdown(rep: dict) -> str:
    total = rep["total"] or 1
    lines = [
        "# 外部真题基准 · 静态分层结果（自动生成）",
        "",
        f"> 生成时间：{rep['generated_at']}｜题目总数：{rep['total']}",
        "> 方法：纯静态扫描（读附件字节 + SHA-256 比对），**零 LLM 调用、零 token 成本**。",
        "",
        "## 一、分层口径与结果",
        "",
        "| 层级 | 含义 | 题数 | 占比 | 能否代表推理能力 |",
        "|------|------|------|------|----------------|",
    ]
    desc = {
        "L0_direct_read": ("附件里能直接扫到真值", "❌ 不能（测的是读文件）"),
        "L1_single_candidate": ("附件有 flag 形态串但非真值（需判断/解码）", "⚠️ 部分（需排除抄错候选）"),
        "L2_pure_reasoning": ("附件无 flag 形态串，必须真解题", "✅ 能"),
        "L3_no_payload": ("题面声明无附件", "✅ 能（但样本少）"),
        "LX_attachment_unavailable": ("声明有附件但本机读不到", "⚠️ 不可用（须先补齐载荷）"),
    }
    for k in ("L0_direct_read", "L1_single_candidate", "L2_pure_reasoning",
              "L3_no_payload", "LX_attachment_unavailable"):
        n = rep["by_level"].get(k, 0)
        d, judge = desc[k]
        lines.append(f"| {k} | {d} | {n} | {n/total:.1%} | {judge} |")
    lines += [
        "",
        f"题型分布：{rep['by_category']}",
        "",
        "## 二、对外报数规则（反注水）",
        "",
        "1. **L0 必须剔除**：附件直含真值的题，裸 LLM 一读即中，报出去等于用文件读取冒充推理。",
        "2. **L1 必须标注**：附件含多个 flag 形态候选时，agent 可能抄到错候选（需真值仲裁兜底）。",
        "3. **只有 L2/L3 是有效推理分母**；报数时写「L2+L3 共 N 题，解出 M 题」。",
        "4. 与「求解器体系」口径（如 176 求解器 / 静态确定性 34.5%）**不可相加**：那是不同能力线。",
        "",
        "## 三、逐题明细",
        "",
        "| 题 id | 题型 | 层级 | 附件 flag 形态串数 | 附件类型 | 已训练 |",
        "|-------|------|------|------------------|---------|--------|",
    ]
    for r in rep["rows"]:
        lines.append(f"| {r['id']} | {r['category']} | {r['level']} | "
                     f"{r['flag_shaped_strings_in_attachments']} | "
                     f"{','.join(r['attachment_kinds']) or '-'} | "
                     f"{'是' if r['trained_in_westlake'] else '否'} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="外部基准静态分层")
    ap.add_argument("--bench", required=True)
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--att-root", default=".",
                    help="附件相对路径的解析根（默认当前目录）")
    args = ap.parse_args()
    bench = Path(args.bench)
    out = Path(args.out_dir) if args.out_dir else bench.parent
    rep = stratify(bench, Path(args.att_root))
    (out / "STRATA.json").write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "STRATA.md").write_text(to_markdown(rep), encoding="utf-8")
    print(f"[strata] 总 {rep['total']} 题 → {json.dumps(rep['by_level'], ensure_ascii=False)}")
    print(f"[strata] 题型 {json.dumps(rep['by_category'], ensure_ascii=False)}")
    print(f"[strata] 已写出 {out/'STRATA.json'} 与 {out/'STRATA.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
