#!/usr/bin/env python3
"""外部真题基准集导出器（西湖论剑 CTF-Agent → SecAutoMind 互操作，2026-10-05）。

为什么存在
----------
SecAutoMind 的自建工件基准接近全绿（执行 17/17、附件 10/10、自研 70/72），
外部公开真题仅 19/55=34.5%，且 36 个 miss 的归因靠人工判读"缺载荷"。
本项目持有 92 道真题语料（data/questions_real/，逐题带 flag_sha256 真值），
可导出为一个「非自建、载荷完整、真值可机器判定」的外部基准。

口径纪律（反注水）
-----------------
1. 载荷完整性硬门：任一附件在磁盘不存在 → 排除（不导出）。理由=缺载荷题必然 0，
   导出会制造"假 miss"，正是对方 36 miss 问题的成因。逐条原因入 manifest。
2. 真值可判定硬门：无 flag_sha256（64 hex）→ 排除（无法机器判真伪）。
3. 污染题排除：answer_disclosed=True（题面自带明文答案）、self_authored_training
   （自产训练题）不外送。
4. 不泄露明文答案：只导出 flag_sha256，绝不导出明文 flag。
5. 边界声明：属本项目已训练/KPI 池的题打 trained_in_westlake=true，
   对方若声明"未见题"分母必须剔除此标记（防两边同时注水）。

用法
----
  .venv/Scripts/python.exe scripts/_export_external_benchmark.py \
      --out "E:/Program/2026挑战杯：SecAutoMind-v1.7.17-share/data/ctf_benchmark/external_westlake"
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # ctf_agent/
SRC = ROOT / "data" / "questions_real"
HEX64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
SELF_AUTHORED = ("self_authored_training", "self-authored", "training")

VERSION = "external-westlake-ctf-1.0"
NOTE = (
    "西湖论剑 CTF-Agent 外部真题基准（2026-10-05 导出）。特点："
    "①全部为真实历史赛事题（非自建）；②每题带 flag_sha256 真值，可机器判真伪；"
    "③载荷完整性导出前已机器校验（附件必须落盘），避免'缺载荷必然 0'的假 miss；"
    "④trained_in_westlake=true 的题属导出方已训练池，对方声明未见题能力时必须剔除。"
    "判定纪律同贵方：只认 SHA-256，禁止'看起来像'计命中。"
)

# ── 随导出一并落盘的判定脚本（纯标准库，纪律对齐贵方 judge_*：只认 SHA-256）──
JUDGE_SRC = r'''# -*- coding: utf-8 -*-
"""外部真题基准（西湖论剑 CTF-Agent）独立判定器。

纪律（与贵方 judge_* 一致）：
  1. 只认 SHA-256——禁止"看起来像 flag"计命中；
  2. 纯标准库，不调 Go、不读对方结果，两侧可独立复算互为印证；
  3. 允许两种形态：完整 flag 串 / 仅内文（求解器常只吐内文），二者都只按哈希比对。

用法：
  python judge_external_westlake.py --self-check
      校验导出集自身完整性：真值格式、载荷字段、与 manifest 对账。
  python judge_external_westlake.py --results results.json
      判定外部结果。results.json 形如 {"<qid>": "flag{...}"} 或 {"<qid>": ["a","b"]}。
"""
import hashlib
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(BASE, "benchmark.json")
MANIFEST = os.path.join(BASE, "export_manifest.json")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
INNER_RE = re.compile(r"\{(.+)\}", re.DOTALL)


def sha(s):
    return hashlib.sha256(s if isinstance(s, bytes) else str(s).encode("utf-8")).hexdigest()


def matches(candidate, truth):
    """候选是否命中真值：完整串或内文任一形态的 SHA-256 相等即命中。"""
    if not candidate:
        return False
    cands = [str(candidate).strip()]
    m = INNER_RE.search(cands[0])
    if m:
        cands.append(m.group(1))
    return any(sha(c) == truth for c in cands if c)


def load():
    with open(BENCH, encoding="utf-8") as f:
        return json.load(f)


def self_check():
    bench = load()
    probs = bench["problems"]
    bad = []
    for qid, p in probs.items():
        t = str(p.get("flag_sha256", ""))
        if not HEX64.match(t):
            bad.append((qid, "flag_sha256 非法"))
        if not str(p.get("description") or "").strip():
            bad.append((qid, "题面为空"))
        atts = p.get("attachments") or ([p["attachment"]] if p.get("attachment") else [])
        if p.get("payload_status") == "verified_on_disk" and not atts:
            bad.append((qid, "声明有载荷但无附件字段"))
    trained = sum(1 for p in probs.values() if p.get("trained_in_westlake"))
    print(f"[self-check] 题数={len(probs)} trained_in_westlake={trained} 问题={len(bad)}")
    for qid, why in bad:
        print("  ❌", qid, why)
    if os.path.exists(MANIFEST):
        man = json.load(open(MANIFEST, encoding="utf-8"))
        print(f"[self-check] manifest: 纳入 {man.get('included_count')} / 排除 {man.get('excluded_count')}")
    return 1 if bad else 0


def judge(results_path):
    bench = load()
    probs = bench["problems"]
    res = json.load(open(results_path, encoding="utf-8"))
    hit, miss, unknown = [], [], []
    for qid, p in probs.items():
        if qid not in res:
            unknown.append(qid)
            continue
        got = res[qid]
        got = [got] if isinstance(got, str) else list(got or [])
        (hit if any(matches(g, p["flag_sha256"]) for g in got) else miss).append(qid)
    total = len(probs)
    print(f"[judge] 命中 {len(hit)}/{total} = {len(hit)/total:.1%}")
    print(f"  未命中 {len(miss)}｜未提交 {len(unknown)}")
    unseen_pool = {q: p for q, p in probs.items() if not p.get("trained_in_westlake")}
    if unseen_pool:
        h = len([q for q in hit if q in unseen_pool])
        print(f"  剔除 trained_in_westlake 后的未见题子集：{h}/{len(unseen_pool)} = {h/len(unseen_pool):.1%}")
    out = {"hit": sorted(hit), "miss": sorted(miss), "not_submitted": sorted(unknown),
           "total": total, "hit_rate": round(len(hit) / total, 4) if total else 0}
    with open(os.path.join(BASE, "judge_result.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("  结果已写 judge_result.json")
    return 0


if __name__ == "__main__":
    if "--results" in sys.argv:
        raise SystemExit(judge(sys.argv[sys.argv.index("--results") + 1]))
    raise SystemExit(self_check())
'''


PROVENANCE_SRC = """# PROVENANCE — 外部真题基准（西湖论剑 CTF-Agent 导出，2026-10-05）

## 这是什么
一套**非自建**的真实历史赛事 CTF 题基准，来源：西湖论剑 CTF-Agent 项目的
`data/questions_real/` 题库（西湖论剑/Anxuan/VNCTF/DASCTF 等系列真题）。
每题带 `flag_sha256` 真值，可机器判真伪；导出前已做**载荷完整性机器校验**。

## 为什么不自建
贵方自建工件基准接近全绿（执行 17/17、附件取证 10/10、自研 70/72=97.2%），
外部公开真题 19/55=34.5% 且 36 个 miss 靠人工判读"缺载荷"。本套补的正是
**外部真值 + 载荷完整**这一格，让"能力数字"不依赖自建工件难度。

## 口径与红线（引用前必读）
1. **只认 SHA-256**：判定见 `judge_external_westlake.py`，禁止"看起来像 flag"计命中。
2. **`trained_in_westlake=true` 的题必须剔除**才能进入贵方"未见题"分母——
   这些题在导出方属已训练/KPI 池，重复计入会让两边同时注水。judge 脚本已
   自动输出剔除该标记后的子集成绩。
3. **载荷完整性已前置校验**：附件未落盘的题在导出阶段即被排除（见
   `export_manifest.json` 的 `payload_missing_on_disk` 条目），避免"缺载荷必然 0"
   的假 miss 重演。
4. **无明文答案**：本目录不含任何明文 flag，只有 SHA-256。
5. **规模与题型**：见 `export_manifest.json` 的 `by_category`（以导出实跑为准）。
6. 附件路径 `attachment(s)` 为**导出方仓库内相对路径**（前缀
   `data/race_attachments/...`）。接贵方引擎时需做路径重定位（复制或挂载附件），
   路径与存在性以 `payload_status` 字段为准。

## 怎么用
```bash
# 1) 校验导出集自身完整性
python judge_external_westlake.py --self-check
# 2) 对结果判真伪（results.json: {"<qid>": "flag{...}"} 或 {"<qid>": ["a","b"]}）
python judge_external_westlake.py --results results.json
```
输出 `judge_result.json`：总命中、未命中、未提交，以及"剔除已训练题后的未见题子集"成绩。

## 维护
- 本目录由导出方脚本 `ctf_agent/scripts/_export_external_benchmark.py` 生成，勿手改
  `benchmark.json`（手改会让导出 manifest 与实际不一致）。
- 需要扩池时请回导出方重新导出，走同一条载荷/真值硬门。
"""


def _resolve(att: str, root: Path | None = None) -> Path | None:
    """把题面里的附件路径解析成本地绝对路径；附件路径相对 ctf_agent/ 根。"""
    base = root or ROOT
    p = (base / att).resolve()
    return p if p.is_file() else None


def _authorized_kpi_ids() -> set[str]:
    """本项目已训练/KPI 授权题集合（供 trained_in_westlake 标记，避免对方把已训练题
    计入"未见题"分母造成两边同时注水）。取不到时返回空集——宁可不标，不可错标。"""
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from _antifraud import AUTHORIZED_KPI_SOLVES  # type: ignore

        return {str(x) for x in AUTHORIZED_KPI_SOLVES}
    except Exception as exc:  # noqa: BLE001
        print(f"[export] ⚠️ 读 AUTHORIZED_KPI_SOLVES 失败，trained 标记留空: {exc}")
        return set()


def collect(include_trained: bool = True, src: Path | None = None,
            att_root: Path | None = None) -> tuple[dict, dict]:
    problems: dict[str, dict] = {}
    included, excluded = [], []
    trained = _authorized_kpi_ids()
    src_dir = src or SRC        # 测试可注入 src
    base = att_root or ROOT     # 附件相对 ctf_agent/ 根解析（测试可注入 att_root）
    if not src_dir.is_dir():
        raise SystemExit(f"[export] 源目录不存在: {src_dir}")

    for fp in sorted(src_dir.rglob("*.json")):
        try:
            q = json.loads(fp.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            excluded.append({"file": fp.name, "reason": f"parse_error: {exc}"})
            continue
        qid = str(q.get("id") or fp.stem)

        def drop(reason: str, detail: str = "") -> None:
            excluded.append({"file": fp.name, "id": qid,
                             "reason": reason, "detail": detail})

        # ① 真值可判定
        truth = str(q.get("flag_sha256") or "").strip().lower()
        if not HEX64.match(truth):
            drop("no_verifiable_truth", "缺 flag_sha256，无法机器判定真伪")
            continue
        # ② 污染题
        if q.get("answer_disclosed"):
            drop("answer_disclosed", "题面自带明文答案")
            continue
        prov = str(q.get("provenance") or "").lower()
        if any(s in prov for s in SELF_AUTHORED):
            drop("self_authored", f"provenance={q.get('provenance')}")
            continue
        # ③ 载荷完整性（硬门）：有附件声明就必须全部落盘
        atts = [str(a) for a in (q.get("attachments") or []) if str(a).strip()]
        missing = [a for a in atts if _resolve(a, base) is None]
        if missing:
            drop("payload_missing_on_disk", f"{len(missing)}/{len(atts)} 个附件未落盘")
            continue

        entry = {
            "id": qid,
            "category": str(q.get("category") or "misc"),
            "title": str(q.get("title") or "")[:160],
            "description": str(q.get("description") or ""),
            "flag_sha256": truth,
            "provenance": str(q.get("provenance") or ""),
            "difficulty": str(q.get("difficulty") or ""),
            "payload_status": "verified_on_disk" if atts else "no_attachment_needed",
            "source_ref": f"westlake_ctf_agent/data/questions_real/{fp.relative_to(src_dir).as_posix()}",
        }
        if atts:
            # 对方 schema 用单数 attachment（相对其仓库根）；多附件保留数组
            if len(atts) == 1:
                entry["attachment"] = atts[0]
            else:
                entry["attachments"] = atts
        if qid in trained:
            entry["trained_in_westlake"] = True
        problems[qid] = entry
        included.append(qid)

    return {"version": VERSION, "note": NOTE, "problems": problems}, {
        "source_root": str(SRC),
        "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "included_count": len(included),
        "excluded_count": len(excluded),
        "included": sorted(included),
        "excluded": excluded,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="导出外部真题基准到 SecAutoMind")
    ap.add_argument("--out", required=True, help="输出目录（SecAutoMind 的 data/ctf_benchmark/external_westlake）")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    bench, manifest = collect()
    cats: dict[str, int] = {}
    for p in bench["problems"].values():
        cats[p["category"]] = cats.get(p["category"], 0) + 1
    manifest["by_category"] = cats

    print(f"[export] 纳入 {manifest['included_count']} 题，排除 {manifest['excluded_count']} 题")
    print(f"[export] 题型分布: {cats}")
    reasons: dict[str, int] = {}
    for e in manifest["excluded"]:
        reasons[e["reason"]] = reasons.get(e["reason"], 0) + 1
    print(f"[export] 排除原因: {reasons}")
    if args.dry_run:
        return 0

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "benchmark.json").write_text(
        json.dumps(bench, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "export_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "judge_external_westlake.py").write_text(JUDGE_SRC, encoding="utf-8")
    (out / "PROVENANCE.md").write_text(PROVENANCE_SRC, encoding="utf-8")
    print(f"[export] 已写出 4 个文件到 {out}")
    print(f"[export] 其中 trained_in_westlake 题数 = "
          f"{sum(1 for p in bench['problems'].values() if p.get('trained_in_westlake'))}"
          f"（对方算未见题分母时须剔除）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
