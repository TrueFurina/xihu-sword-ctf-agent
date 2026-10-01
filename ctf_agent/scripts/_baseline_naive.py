"""朴素基线求解器（zero-effort baseline）：只有「正则找 flag 形状」+「strings 扒二进制」。

为什么要它 —— 这是「真实对比」的对照组：
  本项目自称「确定性优先的静态分析框架」，那么必须回答一个问题：
  **它相对『任何人一小时能写出来的 grep』到底强多少？**
  没有这个基线，presolve 的命中率（如 Cybench 2/13）无法解读 ——
  可能全是「flag 字面写在文件里」的白给分，也可能有真分析成分。有了基线就能分辨。

实现刻意保持「零努力」：
  1) 文本：把附件按 utf-8/latin-1 尽力解码，正则 `TOKEN{...}`；
  2) 二进制：抽可打印 ASCII 连续段（strings 式），再正则；
  3) 归档：在内存里只读遍历 zip 成员（防 zip-slip），同样扫描。
  不做任何密码学求解、不做反汇编、不解码 base64/rot13。**这是下限，不是上限。**

判定：候选集里若有任一候选的 sha256 == 该题真值 sha256 → 记 hit。
  hit_any   = 候选集命中（对基线最宽容，代表「零努力搜索的天花板」）
  hit_first = 第一个候选就是对的（更严，代表「直接用」）
全程零 LLM、零网络、零成本。

用法：
    python scripts/_baseline_naive.py --dir data/questions_ext_cybench
    python scripts/_baseline_naive.py --dir data/questions_ext --json ../logs/baseline_nyu34.json
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.cases import load_questions  # noqa: E402

FLAG_SHAPE = re.compile(rb"[A-Za-z0-9_]{1,12}\{[^}\s]{3,120}\}")
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _candidates_from_bytes(data: bytes) -> list[str]:
    """从任意字节里抽候选 flag：直接正则 + strings 式可打印段。"""
    out: list[str] = []
    out += [m.group(0).decode("latin-1") for m in FLAG_SHAPE.finditer(data)]
    for m in _PRINTABLE.finditer(data):
        for mm in FLAG_SHAPE.finditer(m.group(0)):
            out.append(mm.group(0).decode("latin-1"))
    return out


def solve_question(q) -> dict:
    """对一道题跑朴素基线，返回候选与判定。"""
    cands: list[str] = []
    scanned_bytes = 0
    for a in getattr(q, "attachments", []) or []:
        p = Path(a)
        if not p.exists():
            # 兜底：按 basename 在题库下找
            hits = list(Path("data").rglob(p.name))
            p = hits[0] if len(hits) == 1 else p
        if not p.exists():
            continue
        data = p.read_bytes()
        scanned_bytes += len(data)
        cands += _candidates_from_bytes(data)
        # 归档：内存只读遍历
        if data[:2] == b"PK" or p.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for n in zf.namelist():
                        if n.endswith("/") or ".." in n.split("/"):
                            continue
                        try:
                            cands += _candidates_from_bytes(zf.read(n))
                        except Exception:  # noqa: BLE001
                            continue
            except Exception:  # noqa: BLE001
                pass

    expected = getattr(q, "flag_sha256", None) or ""
    shas = {_sha(c.encode("utf-8")): c for c in cands}
    hit_any = expected in shas
    hit_first = bool(cands) and _sha(cands[0].encode("utf-8")) == expected
    return {
        "id": getattr(q, "id", "?"),
        "category": getattr(q, "category", "?"),
        "n_candidates": len(cands),
        "hit_any": hit_any,
        "hit_first": hit_first,
        "scanned_bytes": scanned_bytes,
        "sample_candidates": cands[:5],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    qs = load_questions(args.dir)
    rows = []
    for q in qs:
        r = solve_question(q)
        rows.append(r)
        print(f"  {r['id'][:52]:52s} cat={r['category']:9s} "
              f"cands={r['n_candidates']:3d} hit={r['hit_any']}", flush=True)

    n = len(rows)
    hit_any = sum(r["hit_any"] for r in rows)
    hit_first = sum(r["hit_first"] for r in rows)
    by_cat: dict = {}
    for r in rows:
        d = by_cat.setdefault(r["category"], [0, 0])
        d[0] += 1
        d[1] += int(r["hit_any"])
    print("\n=== 朴素基线汇总 ===")
    print(f"题库 {args.dir} | {n} 题")
    print(f"  hit_any  （候选集命中，零努力搜索天花板）: {hit_any}/{n}")
    print(f"  hit_first（首个候选即正确）              : {hit_first}/{n}")
    for c, (tot, h) in sorted(by_cat.items()):
        print(f"    {c:10s} {h}/{tot}")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"dir": args.dir, "n": n, "hit_any": hit_any, "hit_first": hit_first,
             "rows": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
        print("->", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
