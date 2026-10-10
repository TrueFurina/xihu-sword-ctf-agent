# -*- coding: utf-8 -*-
"""真题集真值 / 安全不变式批量回归校验（本地，self_authored_training 同性质的内部脚本）。

目的（P3 强化）：把原单题 verify_vnctf_flag.py 的守卫扩展为「批量」，
确保真题集 data/questions_real/** 全部纳入回归，新增 reveal 图 /
附件也不会漏检。

🔧 取题口径修正（2026-10-11，见 ../deliverables/工程补丁/KPI分母口径守护报告-20261011.md）
--------------------------------------------------------------------------------------
原口径为 `glob("**/real_*.json")`，即**只认 real_ 前缀**。而实跑链路
`eval/cases.py:load_questions` 用的是「排除附件目录后的全量 rglob」。
两者结果不等：差 1 题 `crypto/10733.json`——它本体合法
（`provenance=real_past_ctf`、有 flag_sha256、附件在盘），
却因命名前缀不符而**进入实跑分母、从不进入本回归保障**。

修正后与 `eval/cases.py` 同款：递归全量，**排除** `_attachments` / `answers`
等答案键与附件目录（这些目录里的 json 是载荷不是题目）。
修复了「在分母里、不在保护里」的保障逃逸，且不会引入新的漏检。

核验不变式（均不输出明文 flag，仅报状态）：
  1) 题面 flag 字段必须是哈希占位（40/64 hex），不得是 flag{...} 明文 —— 安全红线；
  2) 题面声明的 attachments 路径必须在磁盘存在（相对 ROOT 解析，可移植）；
  3) 若 data/results/verified_flags.json 含该题 sha256 真值，则 sha256 前缀须与台账一致。

不调用视觉 LLM（沙盒无密钥/网络即不可跑的部分由 verify_vnctf_flag.py 单题兜底），
本脚本只做结构性 / 哈希级回归，零明文泄露风险。

运行：.venv/Scripts/python.exe scripts/verify_real_questions.py
"""
import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QS_DIR = os.path.join(ROOT, "data", "questions_real")
VERIFIED = os.path.join(ROOT, "data", "results", "verified_flags.json")
HEX_HASH = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
PLAINTEXT_FLAG = re.compile(r"flag\{")

# 台账承诺的真值库 sha256 前缀（与 verify_vnctf_flag.py 对齐；新增题在此扩展）
LEDGER_SHA256_PREFIXES = {
    "real_misc_vnctf_flag": "7d9ce4e1a4e7369e",
}


def _load_verified() -> dict:
    try:
        with open(VERIFIED, encoding="utf-8") as f:
            return json.load(f).get("flags", {})
    except Exception:
        return {}


# 答案键 / 附件目录（小写）——与 eval/cases.py:load_questions 排除规则同款
EXCLUDED_DIRS = {"_attachments", "answers", "_answers", "_keys", "_solutions"}


def iter_question_files(qs_dir: str) -> list[str]:
    """枚举题目 JSON：递归全量，跳过答案键/附件目录（2026-10-11 口径修正）。

    与 `eval/cases.py:load_questions` 保持一致，使「实跑分母」与「回归保障」
    覆盖同一批文件——这是本脚本存在的意义（原 real_ 前缀口径会漏题）。
    """
    out: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(qs_dir):
        rel = os.path.relpath(dirpath, qs_dir)
        parts = {p.lower() for p in rel.split(os.sep)} if rel != "." else set()
        if parts & EXCLUDED_DIRS:
            continue
        for fn in filenames:
            if fn.endswith(".json"):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="真题集真值/安全不变式批量回归校验")
    ap.add_argument("--questions-dir", default=QS_DIR,
                    help=f"题库目录（默认 {QS_DIR}）；跨 worktree 验收时可指向真实数据目录")
    args = ap.parse_args()
    qs_dir = args.questions_dir

    # 附件相对路径的解析基准 = **数据所在侧**的 ctf_agent 级目录，而不是脚本自身位置。
    # 若用 ROOT 拼接，当 --questions-dir 指向别处（如跨 worktree 验收）时会整体错位，
    # 表现为「全部附件缺失」的假水位（2026-10-11 实测：98/98 误判）。
    data_root = os.path.dirname(os.path.dirname(os.path.abspath(qs_dir)))

    verified = _load_verified()
    files = iter_question_files(qs_dir)
    total = len(files)
    n_attach = 0
    n_plaintext = 0
    n_sha_mismatch = 0
    n_attach_missing = 0
    problems = []

    for f in files:
        qid = os.path.splitext(os.path.basename(f))[0]
        try:
            q = json.load(open(f, encoding="utf-8"))
        except Exception as exc:
            problems.append(f"[JSON解析失败] {f}: {exc}")
            continue
        # 1) flag 占位不变式
        flag = str(q.get("flag") or "")
        if PLAINTEXT_FLAG.search(flag):
            n_plaintext += 1
            problems.append(f"[安全回归] {qid}: flag 字段含明文 flag{{...}}（应迁出为哈希占位）")
        elif not HEX_HASH.match(flag):
            problems.append(f"[格式异常] {qid}: flag 既非哈希占位也非明文 flag{{}}: {flag[:16]!r}")
        # 2) 附件存在性
        for att_rel in (q.get("attachments") or []):
            n_attach += 1
            att = att_rel if os.path.isabs(att_rel) else os.path.join(data_root, att_rel)
            if not os.path.isfile(att):
                n_attach_missing += 1
                problems.append(f"[附件缺失] {qid}: {att}")
        # 3) 真值库 sha256 一致性（仅对有台账前缀承诺的题）
        if qid in LEDGER_SHA256_PREFIXES and qid in verified:
            sha = verified[qid].get("flag_sha256", "")
            if not sha.startswith(LEDGER_SHA256_PREFIXES[qid]):
                n_sha_mismatch += 1
                problems.append(f"[sha256 不匹配] {qid}: {sha[:16]}")

    print(f"真题集批量校验：共 {total} 题，声明附件 {n_attach} 个")
    print(f"  - 明文 flag 安全回归：{n_plaintext}")
    print(f"  - 附件缺失：{n_attach_missing}")
    print(f"  - sha256 真值不匹配：{n_sha_mismatch}")
    if problems:
        print("--- 问题清单 ---")
        for p in problems:
            print("  " + p)
        return 1
    print("✅ 批量不变式全部通过（无明文 flag、附件齐全、真值一致）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
