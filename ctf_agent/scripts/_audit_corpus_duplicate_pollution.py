# -*- coding: utf-8 -*-
"""审计题库副本污染：同 id 在多个数据集里质量不齐的情况。

起因（2026-10-07）：能力兑现审计按 id 去重时，选中了 data/questions 里的
real_crypto_ezrsa 副本——其 attachments 指向**已失效的绝对路径**
（E:/Program/Cybersecurity/比赛真题/...，全部 exists=0），导致同一道题在
另一种去重顺序下"解不出"，制造了**能力未兑现的假象**。

这直接影响 KPI 可信度：任何按 id 聚合的评测，若选中坏副本，
算出的解题率会系统性偏低，且与"抄袭/伪造分数"反向但同样是假水位。

本脚本只做静态清点（不开 solver、不花 token）。
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.cases import load_questions  # noqa: E402

DATASETS = ("data/questions", "data/questions_real",
            "data/questions_external")


def att_stats(q):
    atts = getattr(q, "attachments", None) or []
    if isinstance(atts, str):
        atts = [atts]
    if not atts:
        return 0, 0
    ok = sum(1 for a in atts if os.path.isfile(str(a)))
    return len(atts), ok


def main():
    by_id = defaultdict(list)
    total_loaded = 0
    for d in DATASETS:
        try:
            qs = load_questions(d)
        except Exception as e:  # noqa: BLE001
            print("[skip] %s: %s" % (d, e))
            continue
        for q in qs or []:
            total_loaded += 1
            k = getattr(q, "id", None) or getattr(q, "title", None)
            n, ok = att_stats(q)
            has_truth = bool(getattr(q, "flag_sha256", None))
            by_id[k].append((d, n, ok, has_truth))

    print("加载条目总数: %d，去重 id 数: %d" % (total_loaded, len(by_id)))

    dup_all = {k: v for k, v in by_id.items() if len(v) > 1}
    print("跨数据集重复 id 数: %d" % len(dup_all))

    # 质量不齐 = 同一 id 的不同副本，附件可用数不同
    uneven = {}
    for k, v in dup_all.items():
        quals = sorted({(n, ok) for _d, n, ok, _t in v})
        if len(quals) > 1:
            uneven[k] = v
    print("其中**附件可用性不齐**的 id 数: %d" % len(uneven))

    # 完全失效副本（有 attachments 但一个都不存在）
    dead = []
    for k, v in by_id.items():
        for d, n, ok, _t in v:
            if n > 0 and ok == 0:
                dead.append((k, d, n))
    print("\n附件**全失效**的副本数: %d" % len(dead))
    for k, d, n in dead[:12]:
        print("  %-38s %-24s n_atts=%d" % (k, d, n))
    if len(dead) > 12:
        print("  ... 其余 %d 条" % (len(dead) - 12))

    # 无真值（无 flag_sha256）的题：评分时无法校验
    no_truth = [k for k, v in by_id.items()
                if not any(t for _d, _n, _o, t in v)]
    print("\n无任何副本登记 flag_sha256 的 id 数: %d（评分不可校验）"
          % len(no_truth))

    # 无附件
    no_att = [k for k, v in by_id.items()
              if all(n == 0 for _d, n, _o, _t in v)]
    print("全副本均无附件的 id 数: %d" % len(no_att))

    print("\n" + "=" * 72)
    print("影响要点")
    print("  · 按 id 聚合时若采用『先到先得』，会选中 data/questions 里的")
    print("    失效绝对路径副本 → 该题附件为空 → 任何依赖附件的评测恒 0 分。")
    print("  · 建议：**去重时按附件可用数择优**（scripts/_audit_autocallable_coverage.py")
    print("    的 load_all() 已按此修正）；评测/benchmark 脚本应同步采用同一策略。")


if __name__ == "__main__":
    main()
