# -*- coding: utf-8 -*-
"""收尾脚本（scripts/_closeout.py）单测（G3）。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _closeout  # noqa: E402


def test_check_inflight_parses_porcelain(monkeypatch):
    """解析 git status --porcelain -z 的 M/D/?? 状态（NUL 分隔）。"""
    monkeypatch.setattr(
        _closeout, "_git_status_porcelain",
        lambda: " M core/main_agent.py\0 D scripts/old.py\0?? scripts/_fix_x.py\0")
    inflight = _closeout.check_inflight()
    paths = {p for _, p in inflight}
    assert "core/main_agent.py" in paths
    assert "scripts/old.py" in paths
    assert "scripts/_fix_x.py" in paths
    assert len(inflight) == 3


def test_check_inflight_empty_clean(monkeypatch):
    monkeypatch.setattr(_closeout, "_git_status_porcelain", lambda: "")
    assert _closeout.check_inflight() == []


def test_scan_junk_finds_temp_files(tmp_path, monkeypatch):
    monkeypatch.setattr(_closeout, "ROOT", str(tmp_path))
    (tmp_path / "_probe_size.py").write_text("x")
    (tmp_path / "_try_sizes2.py").write_text("x")
    (tmp_path / "_png33_1000x1000.bin").write_bytes(b"\x00")
    (tmp_path / "real_code.py").write_text("x")
    junk = _closeout.scan_junk()
    assert "_probe_size.py" in junk
    assert "_try_sizes2.py" in junk
    assert "_png33_1000x1000.bin" in junk
    assert "real_code.py" not in junk
