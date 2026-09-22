#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P0-① 外部 CTF 平台题源离线脚手架测试（2026-09-22）。

守的是「扩池不破坏诚实口径」：
  - ingest_external_ctf 三条红线（只存 sha256 / 不收 writeup 重建 / 拒明文 flag 附件）
  - benchmark_heldout.select_candidates 合并外部题源时**复用既有排除链**，零新诚实逻辑
  - 外部题源豁免 _is_writeup_reconstructed 的宽松关键词误剔（description 含 writeup 不算排除）
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import benchmark_heldout as bh  # noqa: E402
from scripts import ingest_external_ctf as ingest  # noqa: E402


# --------------------------------------------------------------------------
# ingest_external_ctf：三条红线
# --------------------------------------------------------------------------
def test_ingest_hashes_plaintext_flag_and_strips_it():
    """红线①：给明文 flag → 现场算 sha256 后丢弃明文，明文永不落盘。"""
    plain = "flag{plaintext_must_not_persist}"
    sha = hashlib.sha256(plain.strip().encode()).hexdigest()
    q = {"id": "ext_a", "title": "t", "category": "misc",
         "description": "brief", "flag": plain, "external_source": "lab"}
    errs = ingest.validate(q)
    assert errs == [], f"valid question wrongly rejected: {errs}"
    assert q.get("flag_sha256") == sha, "flag_sha256 未就地补全"
    assert "flag" not in q, "明文 flag 未剥离（红线①失守）"
    print("✓ test_ingest_hashes_plaintext_flag_and_strips_it")


def test_ingest_refuses_writeup_reconstructed():
    """红线②：显式 source_reconstructed_from_writeup=true 必须拒收。"""
    q = {"id": "ext_b", "title": "t", "category": "web",
         "description": "reconstructed from official writeup",
         "flag_sha256": hashlib.sha256(b"flag{x}").hexdigest(),
         "external_source": "lab", "source_reconstructed_from_writeup": True}
    errs = ingest.validate(q)
    assert any("source_reconstructed_from_writeup" in e for e in errs), \
        "writeup 重建题未被拒收（红线②失守）"
    print("✓ test_ingest_refuses_writeup_reconstructed")


def test_ingest_requires_external_source_and_valid_category():
    """红线②/字段校验：缺 external_source 或非法类别必须报错。"""
    q_no_src = {"id": "ext_c", "title": "t", "category": "misc",
                "description": "brief",
                "flag_sha256": hashlib.sha256(b"flag{x}").hexdigest()}
    assert ingest.validate(q_no_src), "缺 external_source 却通过"
    q_bad_cat = {"id": "ext_d", "title": "t", "category": "forensics",
                 "description": "brief", "external_source": "lab",
                 "flag_sha256": hashlib.sha256(b"flag{x}").hexdigest()}
    assert ingest.validate(q_bad_cat), "非法类别却通过"
    print("✓ test_ingest_requires_external_source_and_valid_category")


def test_ingest_end_to_end_writes_hashed(tmp_path):
    """ingest_one 实际写盘：明文 flag 题哈希落盘、明文不落盘；writeup 题拒绝不写。"""
    plain = "flag{end_to_end_will_be_hashed}"
    sha = hashlib.sha256(plain.encode()).hexdigest()
    out = tmp_path / "ext_out"
    ok, msg = ingest.ingest_one(
        {"id": "ext_e", "title": "t", "category": "misc", "description": "brief",
         "flag": plain, "external_source": "lab"}, out, dry_run=False)
    assert ok and "wrote" in msg
    f = out / "misc" / "ext_e.json"
    assert f.exists(), "外部题未落盘"
    written = json.loads(f.read_text(encoding="utf-8"))
    assert written.get("flag_sha256") == sha and "flag" not in written

    bad, _ = ingest.ingest_one(
        {"id": "ext_f", "title": "t", "category": "web", "description": "d",
         "flag_sha256": hashlib.sha256(b"flag{y}").hexdigest(),
         "external_source": "lab", "source_reconstructed_from_writeup": True},
        out, dry_run=False)
    assert not bad, "writeup 重建题不应被写入"
    assert not (out / "web" / "ext_f.json").exists()
    print("✓ test_ingest_end_to_end_writes_hashed")


# --------------------------------------------------------------------------
# _is_writeup_reconstructed：外部题源豁免宽松关键词
# --------------------------------------------------------------------------
def test_external_writeup_keyword_not_excluded():
    """外部题 description 含 'writeup' 字样（如'多见 writeup'）不应被误剔。"""
    q = {"id": "ext_g", "provenance": "real_past_ctf", "external_source": "picoctf",
         "category": "misc", "attachments": [],
         "description": "this challenge has many writeups online; brief-written"}
    assert bh._is_writeup_reconstructed(q) is False, \
        "外部题 description 含 writeup 被误剔（豁免失效）"
    print("✓ test_external_writeup_keyword_not_excluded")


def test_non_external_writeup_reconstructed_still_excluded():
    """非外部题（无 provenance/external_source）description 含 reconstruct 仍排除。"""
    q = {"id": "wp_h", "category": "misc", "attachments": [],
         "description": "reconstructed from official writeup"}
    assert bh._is_writeup_reconstructed(q) is True
    print("✓ test_non_external_writeup_reconstructed_still_excluded")


# --------------------------------------------------------------------------
# select_candidates：合并外部题源 + 复用排除链
# --------------------------------------------------------------------------
def test_select_merges_external_and_tags_source(tmp_path, monkeypatch):
    """外部题源并入候选池，rec.source='external'，且复用既有 sha256 排除链。"""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    ext_dir = tmp_path / "ext"
    # 1 个合法外部题（有 sha256、标注来源）
    (ext_dir / "misc").mkdir(parents=True)
    (ext_dir / "misc" / "ext_ok.json").write_text(json.dumps(
        {"id": "ext_ok", "category": "misc", "description": "brief",
         "flag_sha256": hashlib.sha256(b"flag{ok}").hexdigest(),
         "provenance": "real_past_ctf", "external_source": "picoctf",
         "attachments": []}, ensure_ascii=False), encoding="utf-8")
    # 1 个外部题缺 sha256 → 应被 require_sha256 排除
    (ext_dir / "web").mkdir(parents=True)
    (ext_dir / "web" / "ext_no_sha.json").write_text(json.dumps(
        {"id": "ext_no_sha", "category": "web", "description": "brief",
         "provenance": "real_past_ctf", "external_source": "ringzer0",
         "attachments": []}, ensure_ascii=False), encoding="utf-8")

    monkeypatch.setattr(bh, "QUESTIONS_REAL", real_dir)  # 隔离真实 92 题集
    cands, all_recs = bh.select_candidates(require_sha256=True, external_dir=ext_dir)

    ext_cands = [r for r in cands if r.get("source") == "external"]
    assert len(ext_cands) == 1 and ext_cands[0]["id"] == "ext_ok", \
        f"合法外部题未并入：{[r['id'] for r in cands]}"
    no_sha = [r for r in all_recs if r["id"] == "ext_no_sha"][0]
    assert no_sha["excluded"] == "no-flag_sha256(unvalidatable)", \
        "缺 sha256 外部题未被既有排除链拦下（排除链未复用）"
    print("✓ test_select_merges_external_and_tags_source")


def test_select_external_absent_is_noop(tmp_path, monkeypatch):
    """external_dir 不存在时，select_candidates 行为与旧版一致（向后兼容）。"""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    monkeypatch.setattr(bh, "QUESTIONS_REAL", real_dir)
    cands, _ = bh.select_candidates(require_sha256=True, external_dir=real_dir / "nope")
    assert cands == [], "空 real 目录 + 不存在 external 应得空池"
    print("✓ test_select_external_absent_is_noop")
