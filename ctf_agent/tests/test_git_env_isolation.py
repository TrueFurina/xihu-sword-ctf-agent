# -*- coding: utf-8 -*-
"""临时仓库的环境隔离护栏（2026-10-11 实锤缺陷的防复发）。

背景（受损证据见 conftest.clean_git_env 的说明，此处不复述）：真实 `git commit`
拉起 pre-commit 钩子时，git 向钩子导出 GIT_DIR / GIT_INDEX_FILE 等本地环境变量。
任何"在 tmp_path 里 `git init` 构造临时仓库"的用例一旦继承这些变量，就不再操作
临时仓库，而是把对象写进**主仓**——既让用例假红（⑥ 门禁拦死每次真实提交），
又往主仓落垃圾提交（实测多出 `x`、`c1` 两个提交）。

本文件把这条约束钉成三条可跑的判据：
  1. clean_git_env() 必须剔净 git 自报的全部本地环境变量；
  2. 在"被污染的父亲进程环境"下建临时仓库，绝不能碰到宿主仓库；
  3. 端到端：把被污染的环境真的传给 pytest 子进程，目标用例仍绿（保姆式回归，
     防止后人新写的临时仓库用例忘了传 env=）。
"""
import os
import subprocess
import sys

import pytest

from conftest import clean_git_env, _LOCAL_ENV_VARS

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_AGENT = os.path.dirname(_TESTS_DIR)


def _git(repo, *args, env=None):
    return subprocess.run(["git", *args], cwd=str(repo), env=env,
                          capture_output=True, text=True, check=True)


def _init_victim(path, env=None):
    """造一个"宿主仓库"（模拟真实提交时 GIT_DIR 指向的主仓）。"""
    _git(path, "init", "-q", env=env)
    _git(path, "config", "user.email", "v@v", env=env)
    _git(path, "config", "user.name", "v", env=env)
    with open(os.path.join(str(path), "keep.txt"), "w") as fh:
        fh.write("victim\n")
    _git(path, "add", "keep.txt", env=env)
    _git(path, "commit", "-q", "-m", "victim-init", env=env)


# ── 1. 变量清单必须剔净 ──────────────────────────────────────────────────
def test_clean_git_env_strips_every_local_var():
    poisoned = dict(os.environ)
    for k in _LOCAL_ENV_VARS:
        poisoned[k] = "/some/injected/path"
    poisoned["UNRELATED_KEEP_ME"] = "keep"

    cleaned = clean_git_env(poisoned)

    leaked = sorted(k for k in _LOCAL_ENV_VARS if k in cleaned)
    assert not leaked, f"仍有仓库绑定变量泄漏到子进程环境：{leaked}"
    assert cleaned["UNRELATED_KEEP_ME"] == "keep", "误伤与本缺陷无关的环境变量"


# ── 2. 污染环境下建临时仓库，不得碰到宿主仓库 ────────────────────────────
@pytest.mark.skipif(subprocess.run(["git", "--version"], capture_output=True).returncode != 0,
                    reason="需要 git")
def test_temp_repo_write_does_not_touch_host_repo(tmp_path, monkeypatch):
    """把 GIT_DIR/GIT_INDEX_FILE/GIT_WORK_TREE 指向"宿主仓库"，临时仓库仍写自己。"""
    victim = tmp_path / "victim"
    victim.mkdir()
    _init_victim(victim)
    head_before = _git(victim, "rev-parse", "HEAD").stdout.strip()
    status_before = subprocess.run(["git", "status", "--porcelain"], cwd=str(victim),
                                   capture_output=True, text=True).stdout

    # 模拟真实提交上下文：父亲进程把宿主仓库的 gitdir/index 导进子进程
    monkeypatch.setenv("GIT_DIR", str(victim / ".git"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(victim / ".git" / "index"))
    monkeypatch.setenv("GIT_WORK_TREE", str(victim))

    # 临时仓库：用 clean env 建（= 修复后的 test_git_snapshot._init_repo 同款做法）
    tmp_repo = tmp_path / "tmp_repo"
    tmp_repo.mkdir()
    clean = clean_git_env()
    _git(tmp_repo, "init", "-q", env=clean)
    _git(tmp_repo, "config", "user.email", "d@d", env=clean)
    _git(tmp_repo, "config", "user.name", "d", env=clean)
    with open(os.path.join(str(tmp_repo), "f.txt"), "w") as fh:
        fh.write("1")
    _git(tmp_repo, "add", "f.txt", env=clean)
    _git(tmp_repo, "commit", "-q", "-m", "c1", env=clean)

    # 宿主仓库：HEAD 不动、工作区/索引不被写脏
    assert _git(victim, "rev-parse", "HEAD").stdout.strip() == head_before, \
        "临时仓库的提交落进了宿主仓库（git 本地环境变量泄漏）"
    status_after = subprocess.run(["git", "status", "--porcelain"], cwd=str(victim),
                                  capture_output=True, text=True).stdout
    assert status_before == status_after, \
        f"宿主仓库被写脏：\n{status_after}"
    # 临时仓库自己确实提交了（修复没有把用例改废）
    assert _git(tmp_repo, "rev-list", "--count", "HEAD", env=clean).stdout.strip() == "1"


# ── 3. 端到端：污染环境真的传给 pytest 子进程，目标用例仍绿 ──────────────
@pytest.mark.skipif(subprocess.run(["git", "--version"], capture_output=True).returncode != 0,
                    reason="需要 git")
def test_pytest_under_poisoned_env_stays_green(tmp_path):
    """复刻 ⑥ 门禁的真实处境：pytest 继承 GIT_DIR=主仓 → 相关用例不得假红。"""
    victim = tmp_path / "victim"
    victim.mkdir()
    _init_victim(victim)
    head_before = _git(victim, "rev-parse", "HEAD").stdout.strip()

    poisoned = dict(os.environ)
    poisoned["GIT_DIR"] = str(victim / ".git")
    poisoned["GIT_INDEX_FILE"] = str(victim / ".git" / "index")
    poisoned["GIT_WORK_TREE"] = str(victim)
    poisoned.pop("GIT_PREFIX", None)

    r = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_git_snapshot.py::test_make_bundle_and_verify",
         "tests/test_git_guard.py::test_snapshot_daily_skips_when_fresh",
         "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=_AGENT, env=poisoned, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=600)
    assert r.returncode == 0, (
        "真实提交上下文（GIT_DIR 被导出）下用例假红——某处又把主仓当成了临时仓库：\n"
        + (r.stdout or "")[-3000:] + (r.stderr or "")[-1500:])
    assert _git(victim, "rev-parse", "HEAD").stdout.strip() == head_before, \
        "pytest 子进程在宿主仓库里留下了提交（垃圾提交 x / c1 的复发）"
