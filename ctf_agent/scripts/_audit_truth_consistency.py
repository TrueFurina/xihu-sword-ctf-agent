"""题面 flag_sha256 一致性审计（2026-10-06）

动机：接线实证时发现 ext_gctf2023_primes 的 `chal.sage` 里**直含明文 flag**，
但该明文的 sha256 与题面 `flag_sha256` **不一致**：
    附件明文 CTF{YkDOL...}  → sha256 = b92b5b9b...
    题面 flag_sha256        = df18e59d...
两者不是编码/前缀/重复等变体关系 → 题面真值与附件内容**不一致**。

影响面：本仓所有「解出后 sha256 逐字匹配才算数」的判定都依赖 flag_sha256。
若该字段本身错误，则对应题目的「已实证解出」结论不可信。必须全库排查。

本审计器（只读、零外部依赖）：
1. 扫全部题库 JSON 的 flag_sha256 + attachments；
2. 对每个可读附件，用 FLAG_RE 抓 flag 形态候选 + 裸明文行做 sha256 比对；
3. 报告三类：
   A. MATCH      —— 附件某候选 == flag_sha256（L0 送分层证据成立）
   B. MISMATCH   —— 附件有 flag 形态候选但**无一对** sha256 匹配（🔴 数据缺陷嫌疑）
   C. NO_CAND    —— 附件无 flag 形态候选（正常，可能真需推理）
只报告不改数据；结论须人工复核后才写回。
"""
import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter

FLAG_RE = re.compile(
    rb"(?:flag|FLAG|Flag|dasctf|DASCTF|ctf|CTF|nssctf|NSSCTF|ISCTF|isctf)"
    rb"\{[ -~]{1,300}\}"
)
MAX_SMALL = 4096  # 与 _stratify_external_benchmark 一致：只对 <=4KB 附件做裸明文比对

# 口径对齐 `_stratify_external_benchmark.py:36` 的 FLAG_RE：前缀用字符类
# `[A-Za-z0-9_]{1,20}` 覆盖 `csawctf` 这类带赛事前缀的 flag。
# （本审计器初版误用了简化正则 `(?:flag|ctf|...)\{`，会从 `csawctf{` 中间起匹配、
#   截断前缀 → sha256 必然不符 → 把 L0 题误判成 MISMATCH。已修正。）
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{1,20}\{[^}\s]{4,120}\}")
INNER_RE = re.compile(rb"\{(.+?)\}", re.DOTALL)


def _candidates(raw: bytes):
    """产出候选（口径对齐分层工具的 matches_truth：全串 + 内文两种）。"""
    out = list(FLAG_RE.findall(raw))
    return out


def matches_truth(candidate: bytes, truth_digest: str) -> bool:
    """与 `_stratify_external_benchmark.matches_truth` **完全同口径**（直接复用）。

    关键：全串与「花括号内文」两种登记口径都试——不同题库的 flag_sha256
    有的登记 `ctf{...}` 全串，有的只登记 `{...}` 内文。
    复用实现而非重写，避免两工具判定漂移。
    """
    truth = str(truth_digest or "").strip().lower()
    if not truth:
        return False
    if hashlib.sha256(candidate).hexdigest().lower() == truth:
        return True
    m = re.search(rb"\{(.+?)\}", candidate, re.DOTALL)
    return bool(m) and hashlib.sha256(m.group(1)).hexdigest().lower() == truth


def load_questions(roots):
    """收集 (json_path, question_dict)。支持 dict-of-questions 与单题 dict。"""
    out = []
    for root in roots:
        for p in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
            if os.sep + "results" + os.sep in p or os.sep + "heldout" in p:
                continue  # 跳过跑批结果副本，避免重复计数
            try:
                d = json.load(open(p, encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(d, dict):
                continue
            if "flag_sha256" in d or "attachments" in d or "description" in d:
                out.append((p, d))
    return out


def resolve(att_path, att_root):
    """把题面里的附件路径解析成实际文件（兼容 data/ 前缀与裸文件名）。"""
    att_path = str(att_path).replace("\\", "/")
    cands = [os.path.join(att_root, att_path)]
    cands.append(os.path.join(att_root, "ctf_agent", att_path))
    base = os.path.basename(att_path)
    for c in cands:
        if os.path.isfile(c):
            return c
    hits = glob.glob(os.path.join(att_root, "**", base), recursive=True)
    return hits[0] if hits else None


def audit(qs, att_root):
    rows = []
    for jpath, q in qs:
        truth = str(q.get("flag_sha256") or "").lower().strip()
        atts = list(q.get("attachments") or [])
        if not atts:
            continue
        if not (len(truth) == 64 and all(c in "0123456789abcdef" for c in truth)):
            continue  # 无有效 flag_sha256，无法比对
        match = False
        cand_total = 0
        cand_sample = b""
        scanned = 0
        for a in atts:
            fp = resolve(a, att_root)
            if not fp or not os.path.isfile(fp):
                continue
            try:
                raw = open(fp, "rb").read()
            except OSError:
                continue
            scanned += 1
            cands = _candidates(raw)
            if len(raw) <= MAX_SMALL:
                cands += [raw.strip()] + [ln.strip() for ln in raw.splitlines()]
            for c in cands:
                if not c:
                    continue
                cand_total += 1
                if not cand_sample:
                    cand_sample = c[:80]
                if matches_truth(c, truth):
                    match = True
        if scanned == 0:
            continue
        level = "A_MATCH" if match else ("B_MISMATCH" if cand_total else "C_NO_CAND")
        rows.append({
            "json": jpath,
            "id": q.get("id") or q.get("title") or os.path.basename(jpath),
            "level": level,
            "cands": cand_total,
            "sample": cand_sample.decode("utf-8", "replace")[:60],
        })
    return rows


def main():
    att_root = sys.argv[1] if len(sys.argv) > 1 else "."
    roots = [os.path.join(att_root, "ctf_agent", "data")]
    qs = load_questions(roots)
    rows = audit(qs, att_root)
    cnt = Counter(r["level"] for r in rows)
    print("=== 题面 flag_sha256 一致性审计 ===")
    print("扫描题目录JSON: %d" % len(qs))
    print(json.dumps(dict(cnt), ensure_ascii=False, indent=1))
    print()
    for lv in ("B_MISMATCH", "A_MATCH"):
        sel = [r for r in rows if r["level"] == lv]
        if not sel:
            continue
        print("---- %s (%d) ----" % (lv, len(sel)))
        for r in sel:
            print("  [%s] cands=%d %s" % (r["level"], r["cands"], r["id"][:50]))
            if lv == "B_MISMATCH":
                print("        sample=%r" % r["sample"])
                print("        json=%s" % r["json"])
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
