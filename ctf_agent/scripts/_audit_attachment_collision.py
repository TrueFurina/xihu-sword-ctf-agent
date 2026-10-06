"""同名附件内容冲突检测（2026-10-06）

动机：审计「有效推理分母」时发现
`real_misc_sheng2022_traffic_telnet_pwd` 有两份同名 JSON
（questions_ext_L2_pure_reasoning/ 与 questions_real/misc/），真值一致，但
后者目录下同名 `flag.txt` 内容是**占位值** `flag{dhb_7th}`（13B），与真值
`Cisc0` 不符 → 按目录名 glob 附件的工具会命中错误的那份。

全库普查结果：**71 份附件都叫 `flag.txt` 但内容各异** —— 说明「按 basename
找附件」在本仓是系统性风险，任何这么做的地方都可能拿到别人的答案/占位符。

本检测器（只读、零依赖）：
按「题面 JSON 的 attachments 字段」精确解析 vs「按 basename glob」模糊解析，
逐题比对两者指向的**文件内容是否一致**，不一致者报 CONFLICT。
——只报告不改数据。
"""
import glob
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict


def _flag_sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_questions(roots):
    out = []
    for root in roots:
        for p in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
            if os.sep + "results" + os.sep in p or os.sep + "heldout" in p:
                continue
            try:
                d = json.load(open(p, encoding="utf-8"))
            except Exception:
                continue
            if isinstance(d, dict) and (d.get("attachments") or d.get("attachment")):
                out.append((p, d))
    return out


def _basename_index(att_root: str):
    """basename -> 全部实际路径（复现「按文件名 glob」的错误做法）。"""
    idx = defaultdict(list)
    for f in glob.glob(os.path.join(att_root, "**", "*"), recursive=True):
        if os.path.isfile(f):
            idx[os.path.basename(f)].append(f)
    return idx


def main():
    att_root = sys.argv[1] if len(sys.argv) > 1 else "."
    data_root = os.path.join(att_root, "ctf_agent", "data")
    qs = load_questions([data_root])
    bmap = _basename_index(att_root)

    exact_paths, conflicts, multi = set(), [], 0
    basenames = Counter()

    for jpath, q in qs:
        atts = list(q.get("attachments") or ([q["attachment"]] if q.get("attachment") else []))
        for a in atts:
            rel = str(a).replace("\\", "/")
            # 精确解析（正确做法）：拼路径
            exact = None
            for cand in (os.path.join(att_root, rel),
                         os.path.join(att_root, "ctf_agent", rel)):
                if os.path.isfile(cand):
                    exact = cand
                    break
            bn = os.path.basename(rel)
            basenames[bn] += 1
            g = bmap.get(bn, [])
            if len(g) > 1:
                multi += 1
            if exact is None:
                continue
            exact_paths.add(exact)
            if not g:
                continue
            # 模糊解析是否可能命中别的内容（basename 相同但内容不同）
            eh = _flag_sha(open(exact, "rb").read())
            others = [p for p in g if p != exact
                      and _flag_sha(open(p, "rb").read()) != eh]
            if others:
                conflicts.append({
                    "json": jpath,
                    "id": q.get("id") or os.path.basename(jpath),
                    "basename": bn,
                    "exact": exact,
                    "exact_sha8": eh[:8],
                    "collide_with": [o for o in others[:3]],
                    "collide_count": len(others),
                })

    print("=== 同名附件冲突检测 ===")
    print("题面 JSON: %d道" % len(qs))
    print("引用的同名附件 basename: %d %s" % (len(basenames),
          "TOP5=%s" % basenames.most_common(5)))
    print("basename 在库中有多份副本的引用数: %d" % multi)
    print("🔴 精确路径与 basename 模糊解析**内容冲突**的题: %d" % len(conflicts))
    for c in conflicts[:20]:
        print("  [%s] %s" % (c["id"], c["basename"]))
        print("       exact=%s (sha %s)" % (c["exact"], c["exact_sha8"]))
        print("       可能误命中 %d 份，例: %s" % (c["collide_count"],
                                                c["collide_with"][0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
