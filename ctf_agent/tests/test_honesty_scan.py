# -*- coding: utf-8 -*-
"""诚实口径扫描器（scripts/_honesty_scan.py）单测。

覆盖四个核心行为：裸词命中、引号引用豁免（使用-提及区分）、
方法论表述不误伤、正则命中（解出数递增 / +N 真实解出 / 真实解出…flag）。
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _honesty_scan as hs  # noqa: E402


def test_plain_phrase_hits():
    """裸短语命中（真的使用假水位）。"""
    hits = hs.scan_text("本轮解出数提升，冲第一", "x.md")
    phrases = [h.split(": ")[-1] for h in hits]
    assert any("解出数提升" in p for p in phrases)
    assert any("冲第一" in p for p in phrases)


def test_quoted_phrase_exempt():
    """引号包裹的「提及」不命中（治理记录引用违规词说明已去掉）。"""
    assert hs.scan_text("含「将功补过」子串彻底去掉", "x.md") == []
    assert hs.scan_text("原词「解出数提升」已改述", "x.md") == []


def test_methodology_not_hit():
    """方法论表述不误伤（"真实解出题验证"不是假水位战报）。"""
    assert hs.scan_text("先真实解出题验证，再声称有效", "x.md") == []
    assert hs.scan_text("可靠清单：真实解出过 vs 写过", "x.md") == []


def test_regex_hits():
    """正则命中：解出数递增 / +N 真实解出 / 真实解出…flag。"""
    assert hs.scan_text("解出数 15→16 实证", "x.md") != []
    assert hs.scan_text("16/60（+1 真实解出）", "x.md") != []
    assert hs.scan_text("真实解出——flag 拿到！", "x.md") != []


def test_archive_prefix_skipped(tmp_path):
    """_archive 前缀文件不参与扫描（离线复盘豁免）。"""
    arch = tmp_path / "_archive_离线刷题复盘.md"
    arch.write_text("将功补过，解出数 5→13", encoding="utf-8")
    assert hs.scan_files([str(arch)]) == []


# ── commit message 扫描（堵 99fb169：message 写"真实解出 flag"）──


def test_scan_commit_message_hits(tmp_path, monkeypatch):
    """commit message 含假水位 → 命中。"""
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("解出数 16→26 实证：真实解出 flag DASCTF{abc}\n", encoding="utf-8")
    monkeypatch.setattr(hs, "commit_message_path", lambda: str(msg))
    hits = hs.scan_commit_message()
    assert hits, "commit message 假水位必须命中"


def test_scan_commit_message_clean(tmp_path, monkeypatch):
    """commit message 干净（诚实表述）→ 不命中。"""
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("fix(解题): 模板扩展——离线推导命中 1 题（非平台 accepted，accepted=0）\n", encoding="utf-8")
    monkeypatch.setattr(hs, "commit_message_path", lambda: str(msg))
    assert hs.scan_commit_message() == []


def test_scan_commit_message_quoted_exempt(tmp_path, monkeypatch):
    """commit message 里用引号引用违规词说明（治理记录）→ 豁免。"""
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("docs(治理): 修复『真实解出 flag』残留表述\n", encoding="utf-8")
    monkeypatch.setattr(hs, "commit_message_path", lambda: str(msg))
    assert hs.scan_commit_message() == []


def test_commit_message_path_git(tmp_path):
    """git rev-parse --git-path 能定位 COMMIT_EDITMSG（在 git 仓库内）。"""
    import subprocess
    out = subprocess.run(["git", "rev-parse", "--git-path", "COMMIT_EDITMSG"],
                         cwd=tmp_path, capture_output=True, text=True)
    # tmp_path 不在 git 仓库内时 git 报错；这里只验证"返回字符串或空，不抛异常"
    assert out.returncode in (0, 128)


# ── --commit-msg-file（commit-msg 钩子传 $1，机制上可靠）──


def test_scan_commit_message_file_hits(tmp_path):
    """commit-msg 钩子路径：假水位 message 文件 → 命中。"""
    msg = tmp_path / "msg"
    msg.write_text("feat: 解出数 15→16 实证——真实解出 flag DASCTF{test}\n", encoding="utf-8")
    assert hs.scan_commit_message_file(str(msg)) != []


def test_scan_commit_message_file_clean(tmp_path):
    """干净 message → 不命中。"""
    msg = tmp_path / "msg"
    msg.write_text("fix(解题): 离线推导命中 1 题（非平台 accepted，accepted=0）\n", encoding="utf-8")
    assert hs.scan_commit_message_file(str(msg)) == []
