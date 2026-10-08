"""归因指纹守卫回归测试（雷 0 / 10-06 假归因事故护栏）。

锁死四条不变式：
1. 亚 5s 解出 + 无 token 计费 + LLM 归因 → 必报可疑（雷 0 指纹）；
2. 真实 LLM 形态（时长 ≥ 阈值且 token 计费）→ 干净；
3. 未解出条目永不判疑（0/N 结论天然安全）；
4. 归因字段优先级：条目级 solved_by/method > 报告级 mode。

fixture 全部合成，无真实 flag。
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys

import pytest

_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "_attribution_fingerprint.py",
)
_spec = importlib.util.spec_from_file_location("_attribution_fingerprint", _SCRIPT)
fp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fp)


def _item(qid: str, solved: bool, dur=None, tokens=None, by=None):
    it = {"id": qid, "solved": solved}
    if dur is not None:
        it["duration_ms"] = dur
    if tokens is not None:
        it["tokens"] = tokens
    if by is not None:
        it["solved_by"] = by
    return it


def test_presolve_fingerprint_flagged():
    """雷 0 指纹：11ms 解出 + tokens=0 + main_agent_llm → 必报可疑。

    fixture 对齐真实事故（09-29 报告有 token 字段但计费为 0）。
    """
    report = {
        "mode": "real_main_agent",
        "results": [_item("synth_q1", True, dur=11, tokens=0, by="main_agent_llm")],
    }
    suspects = fp.audit_report(report)
    assert len(suspects) == 1
    assert suspects[0]["id"] == "synth_q1"
    assert "5000" in suspects[0]["reason"]
    assert "token" in suspects[0]["reason"]


def test_real_llm_shape_clean():
    """真实 LLM 形态：25s 解出 + token 计费 → 干净。"""
    report = {
        "mode": "real_main_agent",
        "results": [_item("synth_q2", True, dur=25000, tokens=1200, by="main_agent_llm")],
    }
    assert fp.audit_report(report) == []


def test_unsolved_never_suspect():
    """0/N 结论天然安全：未解出条目永不判疑。"""
    report = {
        "mode": "real_main_agent",
        "results": [_item("synth_q3", False, dur=10, by="main_agent_llm")],
    }
    assert fp.audit_report(report) == []


def test_attribution_priority_item_over_mode():
    """归因优先级：条目级 presolve 覆盖报告级 llm mode → 不判疑。"""
    report = {
        "mode": "real_main_agent",
        "results": [_item("synth_q4", True, dur=50, by="presolve")],
    }
    assert fp.audit_report(report) == []


def test_mode_fallback_when_no_item_field():
    """无条目级字段时回退报告级 mode：llm mode 下快解仍判疑。"""
    report = {"mode": "main_agent_llm", "results": [{"id": "q5", "solved": True, "duration_ms": 800}]}
    suspects = fp.audit_report(report)
    assert len(suspects) == 1 and suspects[0]["id"] == "q5"


def test_missing_duration_is_suspect():
    """无解出时长证据本身即可疑。"""
    report = {
        "mode": "real_main_agent",
        "results": [{"id": "q6", "solved": True, "by": "main_agent_llm", "tokens": 100}],
    }
    assert len(fp.audit_report(report)) == 1


def test_threshold_boundary():
    """阈值边界：4999ms 可疑，5000ms 且有 token 则干净。"""
    report = {
        "mode": "real_main_agent",
        "results": [
            _item("q_low", True, dur=4999, tokens=1, by="main_agent_llm"),
            _item("q_high", True, dur=5000, tokens=1, by="main_agent_llm"),
        ],
    }
    ids = [s["id"] for s in fp.audit_report(report)]
    assert ids == ["q_low"]


def test_legacy_schema_no_token_field_not_token_flagged():
    """旧 schema（全报告无任何 token 字段，09-19 格式）：仅凭「无 token」不得判疑。

    2026-10-08 全库扫史修正：heldout_rerun20260919_selftruth_full 里 31s 解出
    曾被误标——旧格式根本不记 token，31s 是合理 LLM 时长。
    """
    report = {
        "mode": "real_main_agent",
        "results": [_item("q_slow_legacy", True, dur=31271, by="main_agent_llm")],
    }
    assert fp.audit_report(report) == []


def test_legacy_schema_short_duration_still_flagged():
    """旧 schema 下时长判据不受影响：亚 5s 仍必报，且理由不含 token 判据。"""
    report = {
        "mode": "real_main_agent",
        "results": [_item("q_fast_legacy", True, dur=2309, by="main_agent_llm")],
    }
    suspects = fp.audit_report(report)
    assert [s["id"] for s in suspects] == ["q_fast_legacy"]
    assert "token" not in suspects[0]["reason"]
    assert "5000" in suspects[0]["reason"]


def test_mixed_schema_token_reason_applies():
    """混合 schema：任一条目带 token 字段，则无 token 的其他条目仍按该判据。"""
    report = {
        "mode": "real_main_agent",
        "results": [
            _item("q_with_tok", True, dur=30000, tokens=100, by="main_agent_llm"),
            _item("q_no_tok", True, dur=30000, by="main_agent_llm"),
        ],
    }
    suspects = fp.audit_report(report)
    assert [s["id"] for s in suspects] == ["q_no_tok"]


def test_cli_exit_codes(tmp_path):
    """CLI：污染报告 exit 1（fail-closed）、干净报告 exit 0、坏文件 exit 2。"""
    bad = tmp_path / "contaminated.json"
    bad.write_text(
        json.dumps(
            {
                "mode": "real_main_agent",
                "results": [_item("synth_x", True, dur=12, by="main_agent_llm")],
            }
        ),
        encoding="utf-8",
    )
    good = tmp_path / "clean.json"
    good.write_text(
        json.dumps(
            {
                "mode": "real_main_agent",
                "results": [_item("synth_y", True, dur=30000, tokens=999, by="main_agent_llm")],
            }
        ),
        encoding="utf-8",
    )
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r1 = subprocess.run([sys.executable, _SCRIPT, str(bad)], capture_output=True, text=True, env=env)
    assert r1.returncode == 1
    r2 = subprocess.run([sys.executable, _SCRIPT, str(good)], capture_output=True, text=True, env=env)
    assert r2.returncode == 0
    r3 = subprocess.run([sys.executable, _SCRIPT, str(broken)], capture_output=True, text=True, env=env)
    assert r3.returncode == 2
