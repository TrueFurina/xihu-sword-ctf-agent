# -*- coding: utf-8 -*-
"""机器事实采集器（scripts/_facts.py）单测。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _facts  # noqa: E402


def test_has_detects_needle(tmp_path):
    """_has：文件存在且含 needle 才 True。"""
    f = tmp_path / "x.py"
    f.write_text("def scopes_conflict(): pass", encoding="utf-8")
    assert _facts._has(str(f), "def scopes_conflict") is True
    assert _facts._has(str(f), "def nonexistent") is False
    assert _facts._has(str(tmp_path / "absent.py"), "x") is False


def test_render_md_contains_facts():
    """render_md 把采集的事实写进表格。"""
    facts = {
        "lease_mode": "multi", "g1_landed": True, "g2_landed": True,
        "g3_landed": True, "g4_landed": True, "honesty_gate": True,
        "doc_consistency": True, "git_bind": True, "task_board": True,
        "reviewer_gate": True, "head": "abc1234",
    }
    md = _facts.render_md(facts)
    assert "multi（目录级多写者）" in md
    assert "abc1234" in md
    assert "已落地" in md
    # 单一事实源声明必须在
    assert "单一事实源" in md


# ── 状态快照（--snapshot）──


def test_effective_provider_env_priority(monkeypatch):
    """provider 有效值：环境变量优先于 config 默认。"""
    monkeypatch.setenv("CTF_AGENT_LLM_PROVIDER", "deepseek")
    assert _facts._effective_provider() == "env=deepseek"


def test_effective_provider_config_default(monkeypatch):
    """无环境变量时回退 config.py 默认（baidu 千帆）。"""
    monkeypatch.delenv("CTF_AGENT_LLM_PROVIDER", raising=False)
    val = _facts._effective_provider()
    assert val.startswith("config默认=")
    assert val != "unknown"


def test_render_snapshot_all_sections(monkeypatch):
    """快照输出含全部关键段（provider/HEAD/工作树/租约/机器校验）。"""
    monkeypatch.setattr(_facts, "_effective_provider", lambda: "env=baidu")
    monkeypatch.setattr(_facts, "_git_worktree_summary", lambda: "clean")
    monkeypatch.setattr(_facts, "_lease_snapshot", lambda: "gu[data/results]@2026-08-23 10:00")
    monkeypatch.setattr(_facts, "_run_check", lambda s, a: "OK")
    snapshot = _facts.render_snapshot()
    assert "env=baidu" in snapshot
    assert "工作树" in snapshot and "clean" in snapshot
    assert "租约" in snapshot and "gu[data/results]" in snapshot
    assert "机器校验" in snapshot
    # 快照必须有"勿用记忆替代"的定位声明
    assert "勿用记忆替代" in snapshot


def test_lease_snapshot_float_last_active(tmp_path, monkeypatch):
    """租约 last_active 兼容 float 时间戳（实测发现并行会话写入 float）。"""
    import json
    import time

    coor = tmp_path / "coordination.json"
    coor.write_text(json.dumps({
        "version": 1,
        "leases": {"x": {"scope": ["a/**"], "last_active": time.time() - 60,
                         "last_commit": time.time(), "ttl_min": 5,
                         "key_id": "ab", "lease_version": 0}},
    }), encoding="utf-8")

    monkeypatch.setattr(_facts, "_lease_snapshot", lambda: "（单测：不读真实文件）")
    # 直接验证 float 不会被 .replace() 打爆——用真实 _lease.is_stale 逻辑模拟
    import _lease  # noqa: PLC0415
    doc = _lease.load(str(coor))
    lease = doc["leases"]["x"]
    assert _lease.is_stale(lease) is False  # 1 分钟前活跃，未过期
