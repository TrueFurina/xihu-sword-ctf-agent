"""在线 CTF 验证面（战役B / 用户要求"在线CTF等等都能让你进行验证"）

为何存在
--------
项目真实赛场（初赛）已出局、accepted=0，能力无法在真实赛场背书。但 CTF 能力
应当也能在"公开 CTF 题集"上验证——真题集 92 题来自 DASCTF / HGAME / VNCTF /
Anwang 等多平台公开赛，本身就是"在线 CTF"的离线快照。本脚本把这套多平台公开题
作为**可复现验证语料**，跑确定性解题层并做独立校验，给出一个**严格诚实**的能力数字。

严格诚实设计（用户硬性要求"各项指标也要保证是严格诚实"）
---------------------------------------------------
① 独立真值：每题用题面官方 flag_sha256 校验 solver 输出，绝不信任 solver 自报。
② 注水分类：若某题的附件本身就是明文 flag（flag.txt / 内容即 flag{...}），
   则"解出"是注水而非能力——单独计入 `trivial_answer_in_attachment`，**不计入
   能力计数**（capability_solved）。这是与 _antifraud 反注水闸门同一纪律。
③ 分层标注：本脚本只测**确定性轻量层**（plain/rot13/b64/hex/crypto_math/
   shared_prime/wiener）。完整 presolve 管线（13/15）由 `_merge_gate --kpi-only`
   机器验证；LLM 纯推理（breaking-ice 11/15）由 `_llm_breaking_ice.py` 在持有
   key 时验证。三者口径绝不混用。
④ 扩展点：`--manifest` 可加载外部挑战（本地路径或带 verifier 的 URL 清单），
   用于接入更多在线 CTF 平台语料；URL 抓取需网络，且 LLM 路径需 key。

用法
----
    .venv/Scripts/python.exe scripts/_online_ctf_validate.py \
        [--corpus data/questions_real] [--manifest extra.json] [--out report.json]

输出：JSON 报告（每题 status / solver / sha256_ok / classification / category）
      + 诚实摘要（verifiable_total / capability_solved / trivial / unresolved）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from _local_benchmark import SOLVERS, solve_one  # noqa: E402
from eval.cases import load_questions  # noqa: E402


_FLAG_RE = re.compile(r'(?:DASCTF|flag|ctf)\{[0-9A-Za-z_@!#$%^&*()\-+=\[\]{}|;:,.<>?]{3,}\}', re.I)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _attachment_is_bare_flag(path: str, content: bytes) -> bool:
    """判断附件是否本身就是明文 flag（注水风险）。

    判定：文件名含 flag/answer/key 且内容极短（<=64 字节）直接是 flag 形态；
    或内容去掉首尾空白后就是一个裸 flag{...}。
    """
    base = os.path.basename(path).lower()
    text = content.decode("utf-8", errors="ignore").strip()
    if re.fullmatch(r'(?:DASCTF|flag|ctf)\{[0-9A-Za-z_@!#$%^&*()\-+=\[\]{}|;:,.<>?]{3,}\}', text, re.I):
        return True
    if any(k in base for k in ("flag", "answer", "key", "sol")) and len(content) <= 64:
        return bool(_FLAG_RE.search(text))
    return False


def _validate(flag: str | None, fs: str | None) -> bool:
    if not flag or not fs:
        return False
    for cand in (flag, flag.strip(), flag.strip().strip("flag{}")):
        if _sha256_hex(cand) == fs:
            return True
    return False


def _classify_and_solve(q, att_dir_root: str):
    fs = getattr(q, "flag_sha256", None)
    if not fs:
        return {"status": "NO_TRUTH", "sha256_ok": False, "classification": "unverifiable"}
    atts = getattr(q, "attachments", []) or []
    # 注水检测：任何附件本身是明文 flag？
    trivial = False
    for a in atts:
        p = a if os.path.isabs(a) else os.path.join(_ROOT, a)
        try:
            with open(p, "rb") as fh:
                c = fh.read()
        except Exception:
            continue
        if _attachment_is_bare_flag(p, c):
            trivial = True
            break
    # 跑确定性轻量 solvers（不读 flag.txt 当答案；solver 只解析内容）
    # 附件字段已是相对 ctf_agent 根目录的路径（如 data/questions_real/_attachments/xxx），
    # 必须以 _ROOT 为基准，不能再用 att_dir_root 拼接（避免双重前缀）。
    flag = None
    used = None
    for a in atts:
        p = a if os.path.isabs(a) else os.path.join(_ROOT, a)
        try:
            f, solver = solve_one(p)
        except Exception:
            continue
        if f:
            cand = f.decode("utf-8", errors="ignore").strip()
            if _validate(cand, fs):
                flag, used = cand, solver
                break
            # 也试一遍按 flag 形态截取
            m = _FLAG_RE.search(cand)
            if m and _validate(m.group(0), fs):
                flag, used = m.group(0), solver
                break
    ok = _validate(flag, fs)
    if ok:
        if trivial:
            return {"status": "SOLVED", "sha256_ok": True, "solver": used,
                    "classification": "trivial_answer_in_attachment"}
        return {"status": "SOLVED", "sha256_ok": True, "solver": used,
                "classification": "capability"}
    return {"status": "UNRESOLVED", "sha256_ok": False, "classification": "unresolved"}


def _load_manifest(path: str):
    """外部挑战清单（扩展点）：[{id,category,flag_sha256,attachments:[...]}]。

    每条 attachment 可以是本地相对路径，或 {"url": "...", "sha256": "..."}。
    URL 抓取需网络；本脚本不自动抓取，只接受已落盘的本地路径。
    """
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run(corpus: str, manifest: str | None, out: str):
    att_root = os.path.dirname(corpus)  # corpus 通常为 data/questions_real，附件在其下
    questions = load_questions(corpus)
    cases = []
    for q in questions:
        fs = getattr(q, "flag_sha256", None)
        if not fs:
            continue
        cases.append(q)
    if manifest:
        for m in _load_manifest(manifest):
            # 兼容：manifest 题以 dict 形态直接作为轻量 case
            cases.append(_ManifestQuestion(m))

    t0 = time.time()
    records = []
    for q in cases:
        rec = _classify_and_solve(q, att_root if not isinstance(q, _ManifestQuestion) else ".")
        rec_full = {
            "id": getattr(q, "id", "?"),
            "category": getattr(q, "category", "?"),
            "difficulty": getattr(q, "difficulty", "?"),
            **rec,
        }
        records.append(rec_full)
        print(f"  [{rec['status']:11}] {rec_full['id']:40} cat={rec_full['category']:7} "
              f"cls={rec['classification']}", flush=True)

    verifiable = len(records)
    capability = sum(1 for r in records if r["classification"] == "capability")
    trivial = sum(1 for r in records if r["classification"] == "trivial_answer_in_attachment")
    unresolved = sum(1 for r in records if r["classification"] == "unresolved")
    by_cat_cap = {}
    by_cat_unres = {}
    for r in records:
        if r["classification"] == "capability":
            by_cat_cap[r["category"]] = by_cat_cap.get(r["category"], 0) + 1
        elif r["classification"] == "unresolved":
            by_cat_unres[r["category"]] = by_cat_unres.get(r["category"], 0) + 1

    report = {
        "_honest_model": (
            "确定性轻量层校验（plain/rot13/b64/hex/crypto_math/shared_prime/wiener），"
            "独立 flag_sha256 校验；附件含明文 flag 的题计为 trivial 不计入能力。"
            "完整 presolve 13/15 见 _merge_gate --kpi-only；LLM 纯推理 11/15 见 _llm_breaking_ice.py（需 key）。"
        ),
        "date": time.strftime("%Y-%m-%d"),
        "corpus": corpus,
        "verifiable_total": verifiable,
        "capability_solved": capability,
        "trivial_answer_in_attachment": trivial,
        "unresolved": unresolved,
        "capability_by_category": by_cat_cap,
        "unresolved_by_category": by_cat_unres,
        "capability_rate": round(capability / max(verifiable, 1), 3),
        "total_seconds": round(time.time() - t0, 1),
        "records": records,
    }
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print("\n=== 在线CTF验证面（确定性轻量层）诚实摘要 ===")
    print(f"  可校验语料(多平台公开题): {verifiable}")
    print(f"  能力解出(capability):     {capability}  ({report['capability_rate']*100:.1f}%)")
    print(f"  注水排除(trivial):        {trivial}")
    print(f"  未解出(unresolved):       {unresolved}")
    print(f"  能力分类: {by_cat_cap}")
    print(f"  未解分类: {by_cat_unres}")
    print(f"  报告 -> {out}")
    return report


class _ManifestQuestion:
    """轻量题对象，承接外部 manifest 条目。"""

    def __init__(self, d: dict):
        self._d = d

    @property
    def id(self):
        return self._d.get("id", "manifest")

    @property
    def category(self):
        return self._d.get("category", "?")

    @property
    def difficulty(self):
        return self._d.get("difficulty", "?")

    @property
    def flag_sha256(self):
        return self._d.get("flag_sha256")

    @property
    def attachments(self):
        return self._d.get("attachments", [])


def _main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="data/questions_real", help="真题集目录（多平台公开题快照）")
    ap.add_argument("--manifest", default=None, help="外部挑战清单 JSON（扩展在线CTF语料）")
    ap.add_argument("--out", default="deliverables/online_ctf_validate.json", help="报告输出路径")
    args = ap.parse_args()
    run(args.corpus, args.manifest, args.out)


if __name__ == "__main__":
    _main()
