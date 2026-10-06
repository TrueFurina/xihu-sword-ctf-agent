# -*- coding: utf-8 -*-
"""审计题库副本污染：同 id 在多个数据集里质量不齐的情况。

起因（2026-10-07）：能力兑现审计按 id 去重时，选中了 data/questions 里的
real_crypto_ezrsa 副本——其 attachments 指向**已失效的绝对路径**
（E:/Program/Cybersecurity/比赛真题/...，全部 exists=0），导致同一道题在
另一种去重顺序下"解不出"，制造了**能力未兑现的假象**。

这直接影响 KPI 可信度：任何按 id 聚合的评测，若选中坏副本，
算出的解题率会系统性偏低，且与"抄袭/伪造分数"反向但同样是假水位。

本脚本只做静态清点（不开 solver、不花 token）。

⚠️ 2026-10-07 修订：**判定全部改走 eval/corpus.py 共享层**。
此前本脚本用 `bool(q.flag_sha256)` 单独实现真值判定，**漏了明文 flag 字段**，
因而误报「48 题无真值、评分不可校验」——实际绝大多数题用 flag 明文存真值，
真正无真值的只有极少数。共享层的 has_truth() 同时认 sha256 与 flag 明文。
教训：可测性判定必须单一真相源，重复实现必然漂移。
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.corpus import (  # noqa: E402
    DEFAULT_ROOTS, attachment_health, corpus_report, has_input, has_truth,
    load_corpus,
)


def main():
    # ── 副本层面清点（dedup=False 保留每一个副本）──────────────────
    copies = load_corpus(dedup=False)
    by_id = defaultdict(list)
    for e in copies:
        k = getattr(e.question, "id", None) or getattr(e.question, "title", None)
        by_id[k].append(e)

    print("加载副本总数: %d，去重 id 数: %d" % (len(copies), len(by_id)))

    dup_all = {k: v for k, v in by_id.items() if len(v) > 1}
    print("跨数据集重复 id 数: %d" % len(dup_all))

    uneven = {k: v for k, v in dup_all.items()
              if len({e.health.existing for e in v}) > 1}
    print("其中**附件可用性不齐**的 id 数: %d" % len(uneven))
    for k, v in sorted(uneven.items())[:8]:
        desc = ", ".join("%s(%d/%d)" % (os.path.basename(e.source.rstrip("/\\")),
                                        e.health.existing, e.health.declared)
                         for e in v)
        print("    %-34s %s" % (k, desc))

    dead = [e for e in copies
            if e.health.declared > 0 and e.health.existing == 0]
    print("\n附件**全失效**的副本数: %d" % len(dead))
    for e in dead[:12]:
        print("  %-38s %-24s n_atts=%d" % (
            getattr(e.question, "id", ""), e.source, e.health.declared))
    if len(dead) > 12:
        print("  ... 其余 %d 条" % (len(dead) - 12))

    # ── 去重后的可测性分层（这才是 KPI 分母口径）─────────────────
    entries = load_corpus()
    rep = corpus_report(entries)
    print("\n" + "=" * 72)
    print("去重后可测性分层（KPI 分母口径）")
    print("  总共 unique 题数      : %d" % rep["total"])
    print("  可计入分母(有输入+真值): %d" % rep["measurable"])
    print("  input-less(附件全失效) : %d  ← 必须剔除，属数据缺失非能力缺失"
          % rep["no_input"])
    print("  无真值(解出也无法校验) : %d" % rep["no_truth"])
    print("  real_past_ctf         : %d 题，其中可计分母 %d" % (
        rep["real_past_ctf_total"], rep["real_past_ctf_measurable"]))

    # ── 择优正确性验证 ──────────────────────────────────────────
    best = defaultdict(int)
    for e in copies:
        best[getattr(e.question, "id", "")] = max(
            best[getattr(e.question, "id", "")], e.health.existing)
    viol = [(getattr(e.question, "id", ""), e.source, e.health.existing,
             best[getattr(e.question, "id", "")])
            for e in entries
            if e.health.existing < best[getattr(e.question, "id", "")]]
    print("\n择优失败（选中了存在更优副本的坏副本）: %d 题" % len(viol))
    for v in viol[:5]:
        print("    %s %s (%d < %d)" % v)

    print("\n" + "=" * 72)
    print("影响要点")
    print("  · 按 id 聚合时若采用『先到先得』，会选中 data/questions 里的")
    print("    失效绝对路径副本 → 该题附件为空 → 任何依赖附件的评测恒 0 分。")
    print("  · 判定口径统一在 eval/corpus.py：load_corpus() 按附件可用数择优去重，")
    print("    has_input()/has_truth()/measurable() 判定单题可测性。")
    print("  · 评测/benchmark 脚本应改用 load_corpus()，勿各自实现去重。")


if __name__ == "__main__":
    main()
