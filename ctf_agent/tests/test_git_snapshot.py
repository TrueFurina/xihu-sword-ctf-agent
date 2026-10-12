# -*- coding: utf-8 -*-
"""对象库兜底快照（git bundle）测试 —— 节流"时间 OR 落后 N 提交"（2026-09-19 防复发）
+ 增量制/共享目录/链式保留（2026-10-12；磁盘实证：全量 bundle 单份 ≈2.8G，
"每次提交一份全量"在密集提交轮次下 1 小时即 19G，且 worktree 与主仓各打各的 = 27G 纯重复）。

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

from conftest import clean_git_env  # noqa: E402  （2026-10-11：隔离 git 本地环境变量）


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
    # env=clean_git_env()：必须显式隔离。真实 `git commit` 时钩子会导出 GIT_DIR /
    # GIT_INDEX_FILE，继承下去会让本函数操作**主仓**而非 tmp 仓库（2026-10-11 实锤）。
    return subprocess.run(["git", *args], cwd=repo, env=clean_git_env(),
                          capture_output=True, text=True, check=True)


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
                       env=clean_git_env(), capture_output=True, text=True)
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
                       env=clean_git_env(), capture_output=True, text=True)
    assert v.returncode == 0, v.stderr
    # p2 的边车应记录最新 HEAD
    tip = snap.bundle_tip(p2, gitdir)
    head = subprocess.run(["git", "--git-dir", gitdir, "rev-parse", "HEAD"],
                          env=clean_git_env(), capture_output=True,
                          text=True).stdout.strip()
    assert tip == head


# ── 4. 增量制 + 共享目录 + 链式保留（2026-10-12）──────────────────────────
def _init_repo_big(tmp_path, name="repo", blob_bytes=200_000):
    """仓库：c1 含大 blob（随机字节 ≈ 不可压缩），使全量 bundle 远大于增量。"""
    repo = os.path.join(str(tmp_path), name)
    os.makedirs(repo)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "d@d")
    _git(repo, "config", "user.name", "d")
    with open(os.path.join(repo, "big.bin"), "wb") as fh:
        fh.write(os.urandom(blob_bytes))
    _git(repo, "add", "big.bin")
    _git(repo, "commit", "-q", "-m", "c1")
    return repo


def _commit(repo, content, msg):
    with open(os.path.join(repo, "f.txt"), "w") as fh:
        fh.write(content)
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", msg)


def test_incremental_bundle_small_and_prerequisite_gated(tmp_path):
    """增量 bundle：只含新对象（远小于全量），且 prerequisite 缺失时 verify 必失败。"""
    repo = _init_repo_big(tmp_path)
    gd = os.path.join(repo, ".git")
    outdir = str(tmp_path / "bundles")

    s1, p1 = snap.make_bundle(out_dir=outdir, keep=10, daily=False, git_dir=gd)
    assert s1 == "ok" and os.path.basename(p1).startswith(snap.FULL_PREFIX)

    _commit(repo, "2", "c2")
    s2, p2 = snap.make_bundle(out_dir=outdir, keep=10, daily=False, git_dir=gd)
    assert s2 == "ok" and os.path.basename(p2).startswith(snap.INC_PREFIX)
    # 只含新对象 → 远小于全量（全量 ≈200KB 随机 blob，增量 ≈KB 级）
    assert os.path.getsize(p2) < os.path.getsize(p1) // 5
    # 全量在空仓库可 verify；增量在空仓库必须失败（缺 prerequisite）→ 证明确是增量制
    empty = str(tmp_path / "empty")
    os.makedirs(empty)
    _git(empty, "init", "-q")
    v_full = subprocess.run(["git", "bundle", "verify", p1], cwd=empty,
                            env=clean_git_env(), capture_output=True, text=True)
    assert v_full.returncode == 0, v_full.stderr
    v_inc = subprocess.run(["git", "bundle", "verify", p2], cwd=empty,
                           env=clean_git_env(), capture_output=True, text=True)
    assert v_inc.returncode != 0, "增量 bundle 在空仓库应因缺 prerequisite 验不过"
    # 本仓库内 verify 通过（prerequisite 满足）
    v_ok = subprocess.run(["git", "bundle", "verify", p2], cwd=repo,
                          env=clean_git_env(), capture_output=True, text=True)
    assert v_ok.returncode == 0, v_ok.stderr
    # 边车记录最新 HEAD
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    assert snap.bundle_tip(p2, gd) == head


def test_no_new_commits_skips_incremental(tmp_path):
    """无新提交 → 增量也无对象可打 → skip（不产空 bundle）。"""
    repo = _init_repo_big(tmp_path)
    gd = os.path.join(repo, ".git")
    outdir = str(tmp_path / "bundles")
    s1, _ = snap.make_bundle(out_dir=outdir, keep=10, daily=False, git_dir=gd)
    assert s1 == "ok"
    s2, p2 = snap.make_bundle(out_dir=outdir, keep=10, daily=False, git_dir=gd)
    assert s2 == "skip" and p2 is None
    assert len(snap.list_bundles(outdir)) == 1


def test_auto_mode_resets_to_full_every_n(tmp_path):
    """auto 模式：每累计 full_every 份增量 → 重打全量重置恢复链。"""
    repo = _init_repo_big(tmp_path)
    gd = os.path.join(repo, ".git")
    outdir = str(tmp_path / "bundles")
    s, p0 = snap.make_bundle(out_dir=outdir, keep=10, daily=False, git_dir=gd)
    assert s == "ok" and os.path.basename(p0).startswith(snap.FULL_PREFIX)
    kinds = [os.path.basename(p0)]
    for i in range(2, 5):  # c2/c3/c4
        _commit(repo, str(i), f"c{i}")
        s, p = snap.make_bundle(out_dir=outdir, keep=10, daily=False,
                                git_dir=gd, full_every=2)
        assert s == "ok"
        kinds.append(os.path.basename(p))
    # 序列 = full, inc, inc, full（c4 时增量累计 2 ≥ full_every → 转全量）
    assert [k.startswith(snap.FULL_PREFIX) for k in kinds] == [True, False, False, True]
    # 转全量后，被新全量覆盖的旧增量由保留策略自动清理（内容已含于新全量）
    names = [os.path.basename(p) for p in snap.list_bundles(outdir)]
    assert names[-1].startswith(snap.FULL_PREFIX)
    assert not any(n.startswith(snap.INC_PREFIX) for n in names)


def test_chain_recovery_full_plus_incrementals(tmp_path):
    """端到端灾难恢复：全量 clone + 按序 fetch 增量 → 完整还原 HEAD 与内容。"""
    repo = _init_repo_big(tmp_path)
    gd = os.path.join(repo, ".git")
    outdir = str(tmp_path / "bundles")
    snap.make_bundle(out_dir=outdir, keep=10, daily=False, git_dir=gd)   # full @c1
    _commit(repo, "2", "c2")
    snap.make_bundle(out_dir=outdir, keep=10, daily=False, git_dir=gd)   # inc @c2
    _commit(repo, "3", "c3")
    snap.make_bundle(out_dir=outdir, keep=10, daily=False, git_dir=gd)   # inc @c3
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()

    bundles = snap.list_bundles(outdir)
    fulls = [b for b in bundles if not snap._is_incremental(b)]
    incs = [b for b in bundles if snap._is_incremental(b)]
    assert len(fulls) == 1 and len(incs) == 2

    rec = os.path.join(str(tmp_path), "recover")
    os.makedirs(rec)
    # 占位初始分支（避开与 bundle 内 refs/heads/<default> 相撞的"已检出分支拒绝 fetch"）
    _git(rec, "init", "-q", "-b", "__recover__")
    # 空仓库 init + fetch（HEAD 尚未诞生 → 无"已检出分支"拒绝问题）
    r = subprocess.run(["git", "-C", rec, "fetch", "-q", fulls[0], "+refs/*:refs/*"],
                       env=clean_git_env(), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    for inc in incs:  # prerequisite 链 → 必须按 mtime 顺序
        r = subprocess.run(["git", "-C", rec, "fetch", "-q", inc, "+refs/*:refs/*"],
                           env=clean_git_env(), capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
    r = subprocess.run(["git", "-C", rec, "checkout", "-q", "--detach", head],
                       env=clean_git_env(), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert _git(rec, "rev-parse", "HEAD").stdout.strip() == head
    with open(os.path.join(rec, "f.txt")) as fh:
        assert fh.read() == "3"
    with open(os.path.join(rec, "big.bin"), "rb") as fh:
        assert len(fh.read()) == 200_000


def test_prune_keeps_live_chain_drops_superseded(tmp_path):
    """保留策略：最新 keep 份全量 + 最新全量之后的全部增量（活链）；
    被新全量覆盖的旧增量可删；keep=0 全清（兼容旧语义）。"""
    d = str(tmp_path / "bundles")
    os.makedirs(d)

    def mk(name, mtime):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write("x")
        os.utime(p, (mtime, mtime))

    mk("repo-full-t1.bundle", 1000)
    mk("repo-inc-t2.bundle", 1001)
    mk("repo-inc-t3.bundle", 1002)
    mk("repo-full-t4.bundle", 1003)
    mk("repo-inc-t5.bundle", 1004)

    removed = snap.prune_bundles(d, keep=2)
    assert sorted(os.path.basename(p) for p in removed) == \
        ["repo-inc-t2.bundle", "repo-inc-t3.bundle"]
    assert sorted(os.path.basename(p) for p in snap.list_bundles(d)) == \
        ["repo-full-t1.bundle", "repo-full-t4.bundle", "repo-inc-t5.bundle"]

    removed = snap.prune_bundles(d, keep=1)
    assert sorted(os.path.basename(p) for p in removed) == ["repo-full-t1.bundle"]
    assert sorted(os.path.basename(p) for p in snap.list_bundles(d)) == \
        ["repo-full-t4.bundle", "repo-inc-t5.bundle"]

    snap.prune_bundles(d, keep=0)
    assert snap.list_bundles(d) == []


def test_resolve_shared_bundle_dir_main_and_worktree(tmp_path):
    """目录唯一化：主工作树与车道 worktree 都解析到**主工作树**的 bundle 目录
    （共享对象库 → bundle 内容逐字相同，各写各的 = 纯重复占盘）。"""
    repo = os.path.join(str(tmp_path), "main")
    os.makedirs(repo)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "d@d")
    _git(repo, "config", "user.name", "d")
    _commit(repo, "1", "c1")
    os.makedirs(os.path.join(repo, "ctf_agent"))  # 主工作树布局
    want = os.path.join(repo, "ctf_agent", "logs", "git_bundles")

    # 主工作树：--git-common-dir 返回相对路径（如 .git）→ 按 cwd 拼接
    assert snap.resolve_shared_bundle_dir(cwd=repo) == want

    # 车道 worktree：必须回到主工作树，而不是车道自己的目录
    lane = os.path.join(str(tmp_path), "wt-x")
    _git(repo, "worktree", "add", lane, "-b", "w/x")
    os.makedirs(os.path.join(lane, "ctf_agent"))
    assert snap.resolve_shared_bundle_dir(cwd=os.path.join(lane, "ctf_agent")) == want

    # 非本布局（无 ctf_agent 子目录）→ 回退 DEFAULT_DIR（fail-safe，不造新目录）
    bare = os.path.join(str(tmp_path), "bare")
    os.makedirs(bare)
    _git(bare, "init", "-q")
    assert snap.resolve_shared_bundle_dir(cwd=bare) == snap.DEFAULT_DIR


def test_make_bundle_default_dir_is_shared_main_tree(tmp_path):
    """out_dir=None → 落进主工作树共享目录（车道内调用也如此）。"""
    repo = _init_repo_big(tmp_path)
    gd = os.path.join(repo, ".git")
    os.makedirs(os.path.join(repo, "ctf_agent"))
    lane = os.path.join(str(tmp_path), "wt-y")
    _git(repo, "worktree", "add", lane, "-b", "w/y")
    os.makedirs(os.path.join(lane, "ctf_agent"))

    s, p = snap.make_bundle(out_dir=None, keep=10, daily=False, git_dir=gd)
    assert s == "ok" and p
    # git_dir 指向主仓 → 解析落点应是主仓 ctf_agent/logs/git_bundles
    assert os.path.dirname(p) == os.path.join(repo, "ctf_agent", "logs", "git_bundles")
