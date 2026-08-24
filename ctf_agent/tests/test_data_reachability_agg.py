# -*- coding: utf-8 -*-
"""数据可达率聚合工具测试（2026-08-21 产品官建议联动）。

锁定 scripts/agg_data_reachability.py 的解析契约——"[数据可达]" 日志行格式
一旦漂移，本测试立即报红，保护决赛答辩"数据可达率"硬证据的统计口径。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import agg_data_reachability as agg  # noqa: E402


def test_parse_line_full():
    r = agg.parse_line("[数据可达] 10793 desc=320字 att=True endpoints=2 has_instance=True")
    assert r["id"] == "10793"
    assert r["desc"] == 320
    assert r["att"] is True
    assert r["endpoints"] == 2
    assert r["has_instance"] is True
    assert r["fully_reachable"] is True


def test_parse_line_no_data_unreachable():
    r = agg.parse_line("[数据可达] 9999 desc=0字 att=False endpoints=0 has_instance=False")
    assert r["fully_reachable"] is False


def test_parse_line_desc_only_unreachable():
    """题面有但无抓手（无附件/无靶机）→ 不算完全可达。"""
    r = agg.parse_line("[数据可达] c desc=50字 att=False endpoints=0 has_instance=False")
    assert r["fully_reachable"] is False


def test_parse_line_nonmatching_returns_none():
    assert agg.parse_line("INFO ctfplatform.poller: 轮询：无新题") is None
    assert agg.parse_line("") is None


def test_aggregate_rate():
    lines = [
        "[数据可达] a desc=100字 att=True endpoints=1 has_instance=False",
        "[数据可达] b desc=0字 att=False endpoints=0 has_instance=False",
        "[数据可达] c desc=50字 att=False endpoints=0 has_instance=False",
    ]
    out = agg.aggregate(lines)
    assert out["total"] == 3
    assert out["desc_ok"] == 2
    assert out["att_ok"] == 1
    assert out["endpoints_ok"] == 1
    assert out["fully"] == 1          # 仅 a 完全可达
    assert out["fully_rate"] == round(1 / 3, 3)


def test_aggregate_empty():
    out = agg.aggregate(["no match here", ""])
    assert out["total"] == 0
    assert out["fully_rate"] == 0.0


def test_format_report_contains_rate():
    lines = [
        "[数据可达] a desc=100字 att=True endpoints=1 has_instance=False",
        "[数据可达] b desc=0字 att=False endpoints=0 has_instance=False",
    ]
    text = agg.format_report(agg.aggregate(lines))
    assert "数据可达率" in text
    assert "1 (50.0%)" in text  # 2 题中 1 题完全可达
    assert "b" in text           # 未完全可达样例列出
