# -*- coding: utf-8 -*-
"""对象库兜底快照（git bundle）测试 —— 节流"时间 OR 落后 N 提交"（2026-09-19 防复发）。

背景（team-lead 发现的缺口）：bundle 原为纯时间节流（24h），实测落后 4 个提交——
对象库真丢时，唯一救生艇 bundle 会恢复到一个**不含防复发修复本身**的旧状态。
修正：`should_bundle` = 时间到 OR 落后 ≥ commit_lag 提交即补落。

全部在 tmp_path 里跑；不触碰真 logs/git_bundles。
"""
import os
import subprocess
import sys

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS)

import _git_snapshot as snap  # noqa: E402


# ── 1. 纯函数：节流判定 ───────────────────────────────────────────────────
def test_should_bundle_no_bundle_always():
    do, _ = snap.should_bundle(None, None, 24.0, 1)
    assert do is True


def test_should_bundle_time_reached():
    do, reason = snap.should_bundle(25.0, 0, 24.0, 1)
    assert do is True and "时间到" in reason


def test_should_bundle_recent_and_not_behind_skips():
    # 唯一可跳过情形：时间未到 且 落后 < commit_lag
    do, reason = snap.should_bundle(0.1, 0, 24.0, 1)
    assert do is False and "跳过" in reason


def test_should_bundle_recent_but_behind_forced():
    # 关键：时间未到，但落后 ≥1 → 仍补落（防"bundle 落后于修复提交"）
    do, reason = snap.should_bundle(0.1, 1, 24.0, 1)
    assert do is True and "补落" in reason


def test_should_bundle_recent_unknown_lag_conservative():
    # 无法确认覆盖 HEAD → 保守补落
    do, reason = snap.should_bundle(0.1, None, 24.0, 1)
    assert do is True and "无法确认" in reason


def test_should_bundle_commit_lag_two():
    assert snap.should_bundle(0.1, 1, 24.0, 2)[0] is False   # 落后 1 < 2 → 跳过
    assert snap.should_bundle(0.1, 2, 24.0, 2)[0] is True    # 落后 2 ≥ 2 → 补落


# ── 2. 边车（.head）与滚动清理 ────────────────────────────────────────────
def test_sidecar_tip_and_prune_removes_sidecar(tmp_path):
    b = tmp_path / "repo-20260101T000000Z.bundle"
    b.write_bytes(b"dummy")
    (tmp_path / "repo-20260101T000000Z.bundle.head").write_text("deadbeef\n", encoding="utf-8")
    assert snap.bundle_tip(str(b)) == "deadbeef"
    # 保留 0 份 → 该 bundle 与其边车都被清掉
    removed = snap.prune_bundles(str(tmp_path), keep=0)
    assert len(removed) == 1
    assert not b.exists()
    assert not (tmp_path / "repo-20260101T000000Z.bundle.head").exists()


# ── 3. 端到端：真实 git bundle + verify + "落后即补" ─────────────────────
def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True,
                          text=True, check=True)


def _init_repo(tmp):
    _git(tmp, "init", "-q")
    _git(tmp, "config", "user.email", "d@d")
    _git(tmp, "config", "user.name", "d")
    with open(os.path.join(tmp, "f.txt"), "w") as fh:
        fh.write("1")
    _git(tmp, "add", "f.txt")
    _git(tmp, "commit", "-q", "-m", "c1")
    return os.path.join(tmp, ".git")


def test_make_bundle_and_verify(tmp_path):
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    gitdir = _init_repo(repo)
    outdir = str(tmp_path / "bundles")

    status, path = snap.make_bundle(out_dir=outdir, keep=10, daily=False, git_dir=gitdir)
    assert status == "ok" and path and os.path.isfile(path)
    # 边车记录 HEAD
    assert os.path.isfile(path + snap.HEAD_SIDECAR_SUFFIX)
    # git bundle verify 必须通过
    v = subprocess.run(["git", "bundle", "verify", path], cwd=repo,
                       capture_output=True, text=True)
    assert v.returncode == 0, v.stderr


def test_daily_throttle_bundles_when_behind_then_skips(tmp_path):
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    gitdir = _init_repo(repo)
    outdir = str(tmp_path / "bundles")

    # 第 1 次：无 bundle → 落
    s1, p1 = snap.make_bundle(out_dir=outdir, daily=True, commit_lag=1, git_dir=gitdir)
    assert s1 == "ok" and p1

    # 立刻再跑：时间未到且落后 0 → 跳过（唯一可跳过情形）
    s_skip, p_skip = snap.make_bundle(out_dir=outdir, daily=True, commit_lag=1,
                                      min_interval_hours=24.0, git_dir=gitdir)
    assert s_skip == "skip" and p_skip is None

    # 新提交 → 落后 1 → 即便时间未到也补落（核心要求）
    with open(os.path.join(repo, "f.txt"), "w") as fh:
        fh.write("2")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "c2")
    s2, p2 = snap.make_bundle(out_dir=outdir, daily=True, commit_lag=1,
                              min_interval_hours=24.0, git_dir=gitdir)
    assert s2 == "ok" and p2 and p2 != p1, "第二次提交后必须出现新 bundle"
    assert len(snap.list_bundles(outdir)) == 2
    v = subprocess.run(["git", "bundle", "verify", p2], cwd=repo,
                       capture_output=True, text=True)
    assert v.returncode == 0, v.stderr
    # p2 的边车应记录最新 HEAD
    tip = snap.bundle_tip(p2, gitdir)
    head = subprocess.run(["git", "--git-dir", gitdir, "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    assert tip == head
