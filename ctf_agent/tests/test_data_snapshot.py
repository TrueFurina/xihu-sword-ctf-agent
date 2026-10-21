# -*- coding: utf-8 -*-
"""`scripts/_snapshot_data.py` 的回归锁（2026-10-21）。

背景：data/ 两次丢失（10-12、10-20）都靠运气恢复，10-20 那次永久丢了
10725 附件。本文件锁住快照脚本的四条硬口径：
  ① 只追加（目标已存在即拒，不覆盖/不删）；
  ② 清单是唯一真值（路径/字节数/sha256）；
  ③ 写完必须自校验，篡改/缺失/多余文件都要报出来；
  ④ 不碰快照根下的其他目录（别人的备份不许被牵连）。
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import _snapshot_data as S  # noqa: E402


def _mk_tree(root):
    (root / "a").mkdir(parents=True)
    (root / "a" / "one.bin").write_bytes(b"AAA")
    (root / "b").mkdir()
    (root / "b" / "two.txt").write_text("hello", encoding="utf-8")
    (root / "empty").mkdir()


def test_snapshot_copies_everything_and_manifest_is_truth(tmp_path):
    src = tmp_path / "data"
    src.mkdir()
    _mk_tree(src)
    out = tmp_path / "backups"

    dst = S.snapshot(str(src), str(out), "snap1")

    assert os.path.isfile(os.path.join(dst, "a", "one.bin"))
    assert os.path.isfile(os.path.join(dst, "b", "two.txt"))
    assert os.path.isdir(os.path.join(dst, "empty"))

    with open(os.path.join(dst, S.MANIFEST_NAME), encoding="utf-8") as f:
        m = json.load(f)
    assert m["schema"] == "data_snapshot/v1"
    assert m["file_count"] == 2
    assert m["total_bytes"] == 3 + 5
    paths = sorted(i["path"] for i in m["files"])
    assert paths == ["a/one.bin", "b/two.txt"]
    # 清单里必须有可核对的 sha256 与 mtime，不能只有路径
    for item in m["files"]:
        assert len(item["sha256"]) == 64
        assert isinstance(item["mtime"], int)
    # 刚写完的快照必须自校验通过
    assert S.verify(dst) == []


def test_snapshot_refuses_to_overwrite(tmp_path):
    """只追加口径：同名目标已存在必须拒绝，且原快照内容不被改动。"""
    src = tmp_path / "data"
    src.mkdir()
    _mk_tree(src)
    out = tmp_path / "backups"

    dst = S.snapshot(str(src), str(out), "snap1")
    before = (open(os.path.join(dst, "b", "two.txt"), "rb").read())

    # 源变了，再打同名快照：必须拒，不能悄悄覆盖成新内容
    (src / "b" / "two.txt").write_text("CHANGED", encoding="utf-8")
    with pytest.raises(FileExistsError):
        S.snapshot(str(src), str(out), "snap1")

    after = (open(os.path.join(dst, "b", "two.txt"), "rb").read())
    assert after == before == b"hello"


def test_verify_detects_tamper_missing_and_extra(tmp_path):
    src = tmp_path / "data"
    src.mkdir()
    _mk_tree(src)
    out = tmp_path / "backups"
    dst = S.snapshot(str(src), str(out), "snap1")

    # ① 篡改：同字节数不同内容（只比 size 的校验会漏）
    p = os.path.join(dst, "a", "one.bin")
    with open(p, "wb") as f:
        f.write(b"BBB")
    assert any("哈希不符" in x for x in S.verify(dst)), S.verify(dst)

    # ② 丢文件
    os.remove(os.path.join(dst, "b", "two.txt"))
    assert any("缺文件" in x for x in S.verify(dst))

    # ③ 多余文件（源目录在复制期间变动 → 这份快照不能当基线）
    with open(os.path.join(dst, "extra.bin"), "wb") as f:
        f.write(b"x")
    assert any("清单外多余文件" in x for x in S.verify(dst))


def test_snapshot_does_not_touch_sibling_backups(tmp_path):
    """快照根下别人的目录必须原样保留（脚本只写自己的目标目录）。"""
    src = tmp_path / "data"
    src.mkdir()
    _mk_tree(src)
    out = tmp_path / "backups"
    (out / "someone_else").mkdir(parents=True)
    (out / "someone_else" / "keep.txt").write_text("keep", encoding="utf-8")

    S.snapshot(str(src), str(out), "snap1")

    assert (out / "someone_else" / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert sorted(p.name for p in out.iterdir()) == ["snap1", "someone_else"]


def test_verify_reports_missing_manifest(tmp_path):
    d = tmp_path / "no_manifest"
    d.mkdir()
    assert S.verify(str(d)) == [f"缺清单：{os.path.join(str(d), S.MANIFEST_NAME)}"]


def test_verify_detects_missing_empty_dir(tmp_path):
    """空目录是语义的一部分（data/questions_external 空目录曾连带 24 条失败）。

    清单必须记 dirs；快照里空目录被删掉时要报「缺目录」，不能因为
    「没有文件少了」就判绿。
    """
    src = tmp_path / "data"
    src.mkdir()
    _mk_tree(src)
    out = tmp_path / "backups"
    dst = S.snapshot(str(src), str(out), "snap1")

    with open(os.path.join(dst, S.MANIFEST_NAME), encoding="utf-8") as f:
        m = json.load(f)
    assert "empty" in m["dirs"]

    os.rmdir(os.path.join(dst, "empty"))
    assert any("缺目录" in x for x in S.verify(dst)), S.verify(dst)
