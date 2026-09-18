# -*- coding: utf-8 -*-
"""git 健康门禁与快照兜底的单元测试（2026-09-19 防复发）。

锁定 2026-09-19 事故的直接判据：`.git/refs/` **目录**缺失 → 判损坏（即便有
`packed-refs`）——因为 git 的 is_git_directory() 要求 refs/ 必须是目录。
全部在 tmp_path 里构造假 `.git`，**绝不触碰真仓库的 .git**。
"""
import json
import os
import shutil
import subprocess
import sys

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS)

import _git_guard  # noqa: E402
import _git_snapshot  # noqa: E402

GUARD = os.path.join(SCRIPTS, "_git_guard.py")
SNAP = os.path.join(SCRIPTS, "_git_snapshot.py")
PY = sys.executable

MASTER = "5c984f6516c8c30f2cfa02462e8d435d6d26902f"
ORIGIN_MAIN = "4eb6d5e9f56323057351e1888d81bd3e7f90c61a"


# ── 假 .git 构造 ──────────────────────────────────────────────────────────
def _mk_fake_git(root, refs=True, packed=False, head="ref: refs/heads/master\n",
                 master=True):
    gd = os.path.join(root, ".git")
    os.makedirs(os.path.join(gd, "objects"), exist_ok=True)
    if refs:
        os.makedirs(os.path.join(gd, "refs", "heads"), exist_ok=True)
        if master:
            with open(os.path.join(gd, "refs", "heads", "master"), "w") as f:
                f.write(MASTER + "\n")
    if packed:
        with open(os.path.join(gd, "packed-refs"), "w") as f:
            f.write(f"{ORIGIN_MAIN} refs/remotes/origin/main\n")
    if head is not None:
        with open(os.path.join(gd, "HEAD"), "w") as f:
            f.write(head)
    return gd


def _run(script, args, **kw):
    return subprocess.run([PY, script, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=120, **kw)


# ── L0 判定（直接调用）────────────────────────────────────────────────────
def test_l0_healthy_all_pass(tmp_path):
    gd = _mk_fake_git(str(tmp_path))
    results = _git_guard.check_l0(gd)
    assert _git_guard.all_ok(results)
    by_id = {r["id"]: r["ok"] for r in results}
    assert by_id == {"HEAD": True, "objects": True, "refs": True, "refs-populated": True}


def test_l0_refs_dir_missing_is_fatal_even_with_packed(tmp_path):
    """2026-09-19 事故判据：refs/ 目录缺失即便 packed-refs 在，也必须判损坏。"""
    gd = _mk_fake_git(str(tmp_path), refs=False, packed=True)
    results = _git_guard.check_l0(gd)
    assert not _git_guard.all_ok(results)
    refs_item = next(r for r in results if r["id"] == "refs")
    assert refs_item["ok"] is False
    # refs-populated 因 packed-refs 存在而为 True——但整体仍因 refs 目录缺失而损坏
    assert next(r for r in results if r["id"] == "refs-populated")["ok"] is True


def test_l0_refs_empty_and_no_packed_fails_populated(tmp_path):
    gd = _mk_fake_git(str(tmp_path), refs=True, packed=False, master=False)
    results = _git_guard.check_l0(gd)
    assert next(r for r in results if r["id"] == "refs")["ok"] is True
    assert next(r for r in results if r["id"] == "refs-populated")["ok"] is False
    assert not _git_guard.all_ok(results)


def test_l0_missing_head_fails(tmp_path):
    gd = _mk_fake_git(str(tmp_path), head=None)
    results = _git_guard.check_l0(gd)
    assert next(r for r in results if r["id"] == "HEAD")["ok"] is False
    assert not _git_guard.all_ok(results)


def test_l0_missing_objects_fails(tmp_path):
    gd = _mk_fake_git(str(tmp_path))
    shutil.rmtree(os.path.join(gd, "objects"))
    results = _git_guard.check_l0(gd)
    assert next(r for r in results if r["id"] == "objects")["ok"] is False


# ── L0 退出码（CLI 集成，权威判据）────────────────────────────────────────
def test_cli_healthy_exit0(tmp_path):
    gd = _mk_fake_git(str(tmp_path))
    r = _run(GUARD, ["--git-dir", gd])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "✅" in r.stdout


def test_cli_refs_missing_exit1(tmp_path):
    gd = _mk_fake_git(str(tmp_path), refs=False, packed=True)
    r = _run(GUARD, ["--git-dir", gd])
    assert r.returncode == 1
    assert "refs/" in r.stdout
    assert "not a git repository" in r.stdout  # 诊断含关键机制说明


def test_cli_quiet_no_output_when_healthy(tmp_path):
    gd = _mk_fake_git(str(tmp_path))
    r = _run(GUARD, ["--git-dir", gd, "--quiet"])
    assert r.returncode == 0
    assert r.stdout.strip() == ""


def test_cli_quiet_still_reports_when_broken(tmp_path):
    gd = _mk_fake_git(str(tmp_path), refs=False, packed=True)
    r = _run(GUARD, ["--git-dir", gd, "--quiet"])
    assert r.returncode == 1
    assert "L0[refs]" in r.stdout


def test_cli_json_output(tmp_path):
    gd = _mk_fake_git(str(tmp_path), refs=False, packed=True)
    r = _run(GUARD, ["--git-dir", gd, "--json"])
    assert r.returncode == 1
    data = json.loads(r.stdout)
    assert data["ok"] is False
    assert any(item["id"] == "refs" and item["ok"] is False for item in data["l0"])


# ── 快照 + 重建 ───────────────────────────────────────────────────────────
def test_snapshot_writes_manifest(tmp_path):
    gd = _mk_fake_git(str(tmp_path), packed=True)
    out = os.path.join(str(tmp_path), "snap")
    path, latest, man = _git_guard.write_snapshot(gd, out_dir=out, explicit=True)
    assert os.path.isfile(path)
    assert os.path.isfile(latest)
    assert man["refs_files"].get("refs/heads/master", "").startswith(MASTER[:8])
    assert man["head"] == "ref: refs/heads/master"


def test_rebuild_restores_refs_and_keeps_remotes_packed(tmp_path):
    gd = _mk_fake_git(str(tmp_path), packed=True)
    out = os.path.join(str(tmp_path), "snap")
    _path, latest, _man = _git_guard.write_snapshot(gd, out_dir=out, explicit=True)

    # 破坏：删掉整个 refs/ 目录（复现 2026-09-19 事故）
    shutil.rmtree(os.path.join(gd, "refs"))
    assert not _git_guard.all_ok(_git_guard.check_l0(gd))

    with open(latest, encoding="utf-8") as f:
        man = json.load(f)
    _git_guard.rebuild(gd, man, apply=True)

    # 健康恢复
    assert _git_guard.all_ok(_git_guard.check_l0(gd))
    # master 恢复为 loose
    assert os.path.isfile(os.path.join(gd, "refs", "heads", "master"))
    # 远程引用只在 packed-refs，绝不写 loose refs/remotes（沙箱硬约束）
    assert not os.path.exists(os.path.join(gd, "refs", "remotes", "origin", "main"))
    with open(os.path.join(gd, "packed-refs"), encoding="utf-8") as f:
        packed = f.read()
    assert "refs/remotes/origin/main" in packed
    assert not packed.lstrip().startswith("#")  # 无 `# pack-refs with:` 头


def test_rebuild_dry_run_does_not_touch_disk(tmp_path):
    gd = _mk_fake_git(str(tmp_path), packed=True)
    out = os.path.join(str(tmp_path), "snap")
    _path, latest, _man = _git_guard.write_snapshot(gd, out_dir=out, explicit=True)
    shutil.rmtree(os.path.join(gd, "refs"))
    with open(latest, encoding="utf-8") as f:
        man = json.load(f)
    _git_guard.rebuild(gd, man, apply=False)
    # dry-run 不落盘：refs/ 仍不存在
    assert not os.path.isdir(os.path.join(gd, "refs"))


def test_rebuild_missing_snapshot_cli_exit1(tmp_path):
    gd = _mk_fake_git(str(tmp_path))
    r = _run(GUARD, ["--git-dir", gd, "--rebuild", "--from",
                     os.path.join(str(tmp_path), "nope.json")])
    assert r.returncode == 1
    assert "找不到快照" in r.stdout


# ── _git_snapshot 滚动保留（纯函数）──────────────────────────────────────
def test_prune_bundles_keeps_newest(tmp_path):
    d = os.path.join(str(tmp_path), "bundles")
    os.makedirs(d)
    for i in range(15):
        p = os.path.join(d, f"repo-x{i:02d}.bundle")
        with open(p, "w") as f:
            f.write("x")
        os.utime(p, (1000 + i, 1000 + i))  # 递增 mtime，x14 最新
    removed = _git_snapshot.prune_bundles(d, keep=10)
    assert len(removed) == 5
    remaining = _git_snapshot.list_bundles(d)
    assert len(remaining) == 10
    assert remaining[-1].endswith("repo-x14.bundle")
    assert all(not p.endswith("repo-x00.bundle") for p in remaining)


def test_list_bundles_ignores_non_bundle(tmp_path):
    d = os.path.join(str(tmp_path), "bundles")
    os.makedirs(d)
    for name in ("repo-a.bundle", "note.txt", "other.bundle", "repo-b.bundle.bak"):
        with open(os.path.join(d, name), "w") as f:
            f.write("x")
    listed = _git_snapshot.list_bundles(d)
    assert len(listed) == 1
    assert listed[0].endswith("repo-a.bundle")


def test_newest_age_hours_none_when_empty(tmp_path):
    d = os.path.join(str(tmp_path), "empty")
    os.makedirs(d)
    assert _git_snapshot.newest_age_hours(d) is None


def test_snapshot_daily_skips_when_fresh(tmp_path):
    """--daily（2026-09-19 新语义）：已有**覆盖当前 HEAD**的新 bundle → skip 且不新建。

    旧语义是"纯时间跳过"；新语义要求"时间未到 AND 已确认覆盖 HEAD"才跳过
    （防"bundle 落后于防复发修复提交"）。故此处用真实 repo + `.head` 边车构造"已覆盖"。
    """
    repo = os.path.join(str(tmp_path), "repo")
    os.makedirs(repo)
    for a in (["init", "-q"], ["config", "user.email", "d@d"], ["config", "user.name", "d"]):
        subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)
    with open(os.path.join(repo, "f.txt"), "w") as f:
        f.write("x")
    subprocess.run(["git", "add", "f.txt"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=repo, check=True, capture_output=True)
    gitdir = os.path.join(repo, ".git")

    d = os.path.join(str(tmp_path), "bundles")
    s0, p0 = _git_snapshot.make_bundle(d, keep=10, daily=False, git_dir=gitdir)
    assert s0 == "ok" and p0  # 先落一份真实 bundle（含 .head 边车）

    status, path = _git_snapshot.make_bundle(d, keep=10, daily=True,
                                             min_interval_hours=24.0, commit_lag=1,
                                             git_dir=gitdir)
    assert status == "skip"          # 时间未到 且 落后 0 → 唯一可跳过情形
    assert path is None
    assert len(_git_snapshot.list_bundles(d)) == 1  # 未新建


def test_snapshot_list_cli_empty(tmp_path):
    r = _run(SNAP, ["--list", "--dir", os.path.join(str(tmp_path), "none")])
    assert r.returncode == 0
    assert "无 bundle" in r.stdout
