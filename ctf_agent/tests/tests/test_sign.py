# -*- coding: utf-8 -*-
"""会话唯一 ID 登记（scripts/_sign.py）单测（G2）。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _sign  # noqa: E402


def _mk(tmp_path, name="co.json"):
    return str(tmp_path / name)


def test_init_generates_unique_ids(tmp_path):
    """同名会话两次 init 得到不同 sid（堵撞名）。"""
    coor = _mk(tmp_path)
    sid1 = _sign.init_session("gu", coor_path=coor)
    sid2 = _sign.init_session("gu", coor_path=coor)
    assert sid1 != sid2
    assert sid1.startswith("gu-") and sid2.startswith("gu-")
    assert len(sid1) == len("gu-") + 8  # 8 位 hex


def test_init_registers_identity(tmp_path):
    coor = _mk(tmp_path)
    sid = _sign.init_session("gu", coor_path=coor)
    assert _sign.is_registered(sid, coor_path=coor)
    assert not _sign.is_registered("gu-deadbeef", coor_path=coor)


def test_resolve_from_env(tmp_path, monkeypatch):
    coor = _mk(tmp_path)
    _sign.init_session("gu", coor_path=coor)
    monkeypatch.setenv("CT_AGENT_SESSION", "explicit-session")
    assert _sign.resolve_session(coor_path=coor) == "explicit-session"


def test_resolve_single_identity(tmp_path, monkeypatch):
    """无环境变量时，resolve 回退到 identity 表（隔离 CT_AGENT_SESSION，防 pre-commit 环境污染）。"""
    monkeypatch.delenv("CT_AGENT_SESSION", raising=False)
    coor = _mk(tmp_path)
    sid = _sign.init_session("gu", coor_path=coor)
    assert _sign.resolve_session(coor_path=coor) == sid


def test_resolve_empty_no_identity(tmp_path, monkeypatch):
    """无登记且无环境变量 → 空。"""
    monkeypatch.delenv("CT_AGENT_SESSION", raising=False)
    coor = _mk(tmp_path, "absent.json")
    assert _sign.resolve_session(coor_path=coor) == ""


def test_bind_author_sets_git_config(tmp_path, monkeypatch):
    """bind 把 session 写入 git config user.name / user.email（堵 P1-7）。"""
    coor = _mk(tmp_path)
    sid = _sign.init_session("gu", coor_path=coor)
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return object()  # bind_author 不访问返回值属性

    monkeypatch.setattr(_sign.subprocess, "run", fake_run)
    assert _sign.bind_author(sid, coor_path=coor) is True
    configs = [a for a in calls if len(a) >= 3 and a[:2] == ["git", "config"]]
    assert ["git", "config", "user.name", sid] in configs
    assert ["git", "config", "user.email", f"{sid}@local"] in configs


def test_author_matches(monkeypatch):
    """author == session 判定（pre-commit ④ 校验的核心逻辑）。"""
    monkeypatch.setattr(_sign, "current_git_author", lambda: "gu-abc12345")
    assert _sign.author_matches("gu-abc12345") is True
    assert _sign.author_matches("gu-other") is False


def test_bind_author_empty_sid(tmp_path):
    """空 session 不 bind。"""
    assert _sign.bind_author("", coor_path=_mk(tmp_path)) is False
