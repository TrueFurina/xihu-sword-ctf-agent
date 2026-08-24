# -*- coding: utf-8 -*-
"""Reviewer 验收门禁（scripts/_reviewer_gate.py）单测（T-10）。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _reviewer_gate as rg  # noqa: E402


def test_out_of_scope_files():
    """纯函数：越界文件判定。"""
    scope = ["agents/**", "skills/**"]
    files = ["agents/crypto.py", "skills/rsa.py", "core/main_agent.py", "README.md"]
    bad = rg.out_of_scope_files(files, scope)
    assert bad == ["core/main_agent.py", "README.md"]


def test_all_in_scope():
    scope = ["scripts/**", "tests/**"]
    files = ["scripts/_lease.py", "tests/test_lease.py"]
    assert rg.out_of_scope_files(files, scope) == []


def test_scope_prefix_match():
    """scope 裸目录名前缀匹配（path_in_scope 复用 _lease 语义）。"""
    scope = ["scripts"]
    assert rg.out_of_scope_files(["scripts/_x.py", "scripts/sub/y.py"], scope) == []
    assert rg.out_of_scope_files(["core/z.py"], scope) == ["core/z.py"]


def test_empty_scope_rejects_all():
    """空 scope 时所有文件都越界（fail-closed）。"""
    assert rg.out_of_scope_files(["a.py"], []) == ["a.py"]
