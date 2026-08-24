# -*- coding: utf-8 -*-
"""报告诚实性测试（2026-08-20 锐评 P0-1/P0-4 整改）。

验证：
1. 无真实交互记录（total=0）时不写"与网络流量/平台日志吻合"虚假声明
2. 有真实记录时才写"吻合"声明
3. 0 记录时标注"空跑/演练占位——非真实解题数据"
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from report.generator import generate_report


def test_empty_report_no_false_claim():
    """0 条记录的报告不得宣称"与网络流量吻合"。"""
    md = generate_report(poller_records=[], solve_logs={})
    # 禁止出现无条件吻合声明
    assert "与网络流量/平台日志吻合）" not in md, "0 题报告不应写'与网络流量吻合'"
    assert "与网络流量吻合）" not in md, "0 题报告不应写'与网络流量吻合'"
    # 必须标注为空跑/演练
    assert ("空跑" in md) or ("演练" in md) or ("未产生" in md), (
        "0 题报告应标注空跑/演练/未产生"
    )
    # 第四节标题也不应无条件写"与网络流量吻合"
    assert "平台交互记录（与网络流量吻合）" not in md
    print("✓ test_empty_report_no_false_claim")


def test_nonempty_report_has_honest_claim():
    """有真实记录时可写吻合声明（且数字正确）。"""
    recs = [
        {"challenge_id": "c1", "title": "t", "category": "web",
         "flag": "flag{x}", "accepted": True, "duration_s": 10.0},
    ]
    md = generate_report(poller_records=recs, solve_logs={})
    assert "与网络流量" in md or "平台日志吻合" in md or "真实交互记录" in md
    assert "| 题目总数 | 1 |" in md
    assert "| 解出题数 | 1 |" in md
    print("✓ test_nonempty_report_has_honest_claim")


def test_compliance_clause_conditional():
    """合规声明第 5 条须带"仅当存在真实交互记录时"限定。"""
    md_empty = generate_report(poller_records=[], solve_logs={})
    md_full = generate_report(
        poller_records=[{"challenge_id": "c1", "flag": "flag{x}",
                         "accepted": True, "duration_s": 1.0}],
        solve_logs={},
    )
    # 第 5 条限定语必须在两份报告里都出现（条件化声明）
    assert "仅当存在真实交互记录时" in md_empty or "非真实解题数据" in md_empty
    # 有数据时第5条也应带限定（不撤销）
    assert "仅当存在真实交互记录时" in md_full
    print("✓ test_compliance_clause_conditional")


def test_no_false_waterlevel_in_active_docs():
    """活跃项目文档不得含假水位/自嗨表述（防"离线复盘冒充战报"的元层面自循环）。

    复用 scripts/_honesty_scan.py 作为单一事实源（短语 + 正则），pre-commit 门禁
    与测试共享同一套规则，避免两处维护 drift。正则版比裸短语更精准：能覆盖
    任意「解出数 N→M」递增、且不误伤「真实解出题验证」这类方法论表述。
    """
    import sys as _sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _sys.path.insert(0, os.path.join(root, "scripts"))
    import _honesty_scan  # noqa: E402
    files = _honesty_scan.active_doc_files(root)
    hits = _honesty_scan.scan_files(files)
    assert not hits, (
        "活跃文档检出假水位/自嗨表述（应归档或中性化）: %r" % hits
    )
    print("✓ test_no_false_waterlevel_in_active_docs")
    print("✓ test_no_false_waterlevel_in_active_docs")


if __name__ == "__main__":
    test_empty_report_no_false_claim()
    test_nonempty_report_has_honest_claim()
    test_compliance_clause_conditional()
    test_no_false_waterlevel_in_active_docs()
    print("=== report 诚实性测试全部通过 ===")
