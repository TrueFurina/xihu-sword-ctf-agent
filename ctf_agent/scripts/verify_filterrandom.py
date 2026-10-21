# -*- coding: utf-8 -*-
"""real_crypto_filterrandom（西湖论剑 2021 · 噪声混合双 LFSR 初始状态恢复）— 可复现核验脚本。

2026-10-22 修复（接管 T2 阶段A 合入阻塞）：本題此前在合并闸门 REGRESSION_CHECKS 中
被误分类为「presolve 确定性管线可解」，指向 `scripts/_regress_one.py real_crypto_filterrandom`。
但 presolve 用的是通用 *工具* 管线（FileAnalysis/CryptoAuto/Python 适配器等），
**不会路由到** `skills/lfsr_filter_recover.py` 这个 *skill*，故长期 `REGRESS_FAIL 提取=None`。

本題的真实求解器是 skill `lfsr_filter_recover`（`run()` 入口），其 `_extract_masks_and_out`
从附件 FilterRandom.py 的 `'''` 数据块解析 mask1/mask2/2048 位混合输出，再用
`solve_lfsr_filter()` 恢复 init1/init2 → `DASCTF{init1-init2}`。本脚本直接调用该 skill，
并对题面 `flag_sha256` 做严格 sha256 比对（外部真值闭环，诚信红线：明文 flag 不打印不入库）。

与 `verify_specialcurve2.py` 同款定位：需要专属攻击链的題用专属 verify 脚本，
而非 `_regress_one.py`（presolve）。

运行：.venv/Scripts/python.exe scripts/verify_filterrandom.py
输出：REGRESS_PASS / REGRESS_FAIL；明文 flag 不回显（诚信红线）。
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

QUESTION = os.path.join(
    ROOT, "data", "questions_real", "crypto", "real_crypto_filterrandom.json")


def main() -> int:
    with open(QUESTION, encoding="utf-8") as f:
        q = json.load(f)
    qid = q.get("id", "real_crypto_filterrandom")
    stored_sha = (q.get("flag_sha256") or "").strip().lower()
    assert len(stored_sha) == 64 and all(
        c in "0123456789abcdef" for c in stored_sha), "题面缺合法 flag_sha256"

    attachments = q.get("attachments") or []
    if not attachments:
        print(f"[0] {qid}: 题面无附件，无法解析 mask/out")
        print("REGRESS_FAIL")
        return 1
    att = attachments[0]
    att_path = att if os.path.isabs(att) else os.path.join(ROOT, att)
    if not os.path.isfile(att_path):
        print(f"[0] {qid}: 附件缺失 {att_path}（非代码回归，载荷丢失）")
        print("REGRESS_FAIL")
        return 1
    print(f"[0] {qid}: 附件在盘 {os.path.basename(att_path)}，调用 lfsr_filter_recover skill")

    # 调用专属 skill（与题面真值闭环的唯一正确求解器）
    from skills.lfsr_filter_recover import run as solve  # noqa: E402
    res = solve({"path": att_path})
    if not res.get("ok"):
        print(f"[1] skill 未解出: {res.get('error', '未知')}")
        print("REGRESS_FAIL")
        return 1
    flag = res.get("flag") or ""
    got = hashlib.sha256(flag.encode("utf-8")).hexdigest()
    if got == stored_sha:
        print(f"[1] 解出 flag（明文不打印）sha256={got[:16]}… 与题面官方真值一致")
        print("REGRESS_PASS")
        return 0
    print(f"[1] sha256 不匹配: 解出 {got[:16]}… vs 官方 {stored_sha[:16]}…")
    print("REGRESS_FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
