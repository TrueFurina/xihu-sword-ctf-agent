# -*- coding: utf-8 -*-
"""core.bare 健康判据的单元测试（2026-10-12 防复发）。

锁定 2026-10-11 时间窗内复现两次的**语义损坏**事故：真实 commit 时 git 向钩子
导出 `GIT_DIR`，⑥ 中「在 tmp_path 构造临时仓库」的用例继承后把**主仓共享
`.git/config`** 改写成 `core.bare = true`（并附 `user.name = d`）。此后主工作树
被 git 判为 bare —— `git status` 报 `fatal: this operation must be run in a
work tree`，merge/status 全线失效。

既有 L0 四查全是「文件在不在」，refs/、HEAD、objects 一个没少，看不出这类语义
损坏，故单独立判据 `check_core_bare`。本文件锁定它的三层契约：

1. **事故特征必须被抓**：`bare = true` 及其 git 认可的全部真值变体
   （`yes` / `on` / `1`，大小写与首尾空白不敏感）。
2. **不许误伤**：没有 config 的假 `.git` 夹具（既有 `test_l0_*` 就是这种）、
   注释掉的 `bare`、其他 section 里的 `bare`、`[core]` 段内的其他键。
3. **必须能拦住开工**：CLI 退出码非 0 且给出处置命令；`--quiet` 下仍然报。

全部在 tmp_path 里构造假 `.git`，**绝不触碰真仓库的 .git**。
"""
import json
import os
import subprocess
import sys

import pytest

SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
)
sys.path.insert(0, SCRIPTS)

import _git_guard  # noqa: E402

from conftest import clean_git_env  # noqa: E402  （2026-10-11：隔离 git 本地环境变量）

GUARD = os.path.join(SCRIPTS, "_git_guard.py")
PY = sys.executable


# ── 假 .git 构造 ──────────────────────────────────────────────────────────
def _mk_git(root, config=None):
    """构造最小可用的假 .git。

    config 为 None 时**不写 config** —— 复现 `test_l0_*` 那批夹具的形态，
    用来锁「无 config 不误判」这条边界。
    """
    gd = os.path.join(root, ".git")
    os.makedirs(os.path.join(gd, "objects"), exist_ok=True)
    os.makedirs(os.path.join(gd, "refs", "heads"), exist_ok=True)
    with open(os.path.join(gd, "refs", "heads", "master"), "w", encoding="utf-8") as f:
        f.write("0" * 40 + "\n")
    with open(os.path.join(gd, "HEAD"), "w", encoding="utf-8") as f:
        f.write("ref: refs/heads/master\n")
    if config is not None:
        with open(os.path.join(gd, "config"), "w", encoding="utf-8") as f:
            f.write(config)
    return gd


def _run(args, **kw):
    # 子进程默认继承 clean env：被真实 commit 拉起时父进程带 GIT_DIR，
    # 透传下去会让 `_git_guard.py` 去体检**主仓**（2026-10-11 实锤）。
    kw.setdefault("env", clean_git_env())
    return subprocess.run(
        [PY, GUARD, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        **kw,
    )


HEALTHY_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[user]
\tname = d
\temail = d@example.com
"""


# ── 事故特征：必须抓到 ────────────────────────────────────────────────────
def test_bare_true_is_unhealthy(tmp_path):
    """2026-10-11 事故的原始形态：主仓 config 被写成 core.bare = true。"""
    gd = _mk_git(str(tmp_path), config="[core]\n\tbare = true\n")
    r = _git_guard.check_core_bare(gd)
    assert r["id"] == "core-bare"
    assert r["ok"] is False
    # 判据必须给出可执行的处置命令，否则值班的人只能干瞪眼
    assert "git config --local core.bare false" in r["detail"]


@pytest.mark.parametrize("value", ["true", "TRUE", "True", "yes", "YES", "on", "ON", "1"])
def test_bare_truthy_variants_are_unhealthy(tmp_path, value):
    """git 认可的布尔真值全都得抓，不能只认小写 true。"""
    gd = _mk_git(str(tmp_path), config=f"[core]\n\tbare = {value}\n")
    assert _git_guard.check_core_bare(gd)["ok"] is False


@pytest.mark.parametrize("value", ["false", "FALSE", "no", "off", "0"])
def test_bare_falsy_variants_are_healthy(tmp_path, value):
    gd = _mk_git(str(tmp_path), config=f"[core]\n\tbare = {value}\n")
    assert _git_guard.check_core_bare(gd)["ok"] is True


def test_bare_true_with_surrounding_whitespace(tmp_path):
    """真实 config 里 bare 常带缩进/行尾空白，strip 后仍要判出真值。"""
    gd = _mk_git(str(tmp_path), config="[core]\n   bare   =   true   \n")
    assert _git_guard.check_core_bare(gd)["ok"] is False


def test_bare_in_uppercase_section_is_detected(tmp_path):
    """section 名大小写不敏感（[CORE] 与 [core] 等价）。"""
    gd = _mk_git(str(tmp_path), config="[CORE]\n\tbare = true\n")
    assert _git_guard.check_core_bare(gd)["ok"] is False


def test_last_bare_assignment_wins(tmp_path):
    """重复 [core] 段时以最后一次赋值为准 —— 与 git config 的覆盖语义一致。"""
    gd = _mk_git(
        str(tmp_path),
        config="[core]\n\tbare = true\n[core]\n\tbare = false\n",
    )
    assert _git_guard.check_core_bare(gd)["ok"] is True


# ── 不许误伤 ──────────────────────────────────────────────────────────────
def test_no_config_is_healthy(tmp_path):
    """既有 test_l0_* 夹具没有 config，绝不能因此判红（否则一次改判据全仓爆红）。"""
    gd = _mk_git(str(tmp_path), config=None)
    r = _git_guard.check_core_bare(gd)
    assert r["ok"] is True
    assert "跳过" in r["detail"]


def test_unreadable_config_is_healthy(tmp_path):
    """config 是目录（不可读）时按「无法判定」放行，不误伤。"""
    gd = _mk_git(str(tmp_path), config=None)
    os.makedirs(os.path.join(gd, "config"))
    assert _git_guard.check_core_bare(gd)["ok"] is True


def test_commented_bare_is_ignored(tmp_path):
    gd = _mk_git(
        str(tmp_path),
        config="[core]\n\t# bare = true\n\t; bare = true\n\tbare = false\n",
    )
    assert _git_guard.check_core_bare(gd)["ok"] is True


def test_bare_in_other_section_is_ignored(tmp_path):
    """`[user] bare = true` 不是 core.bare，不许误判成事故。"""
    gd = _mk_git(str(tmp_path), config="[user]\n\tbare = true\n")
    assert _git_guard.check_core_bare(gd)["ok"] is True


def test_bare_before_any_section_is_ignored(tmp_path):
    """文件头没有 section 时出现的裸 key 不属于任何段，不应计入。"""
    gd = _mk_git(str(tmp_path), config="bare = true\n[core]\n\tbare = false\n")
    assert _git_guard.check_core_bare(gd)["ok"] is True


def test_healthy_config_is_healthy(tmp_path):
    gd = _mk_git(str(tmp_path), config=HEALTHY_CONFIG)
    r = _git_guard.check_core_bare(gd)
    assert r["ok"] is True
    assert "正常" in r["detail"]


def test_other_core_keys_do_not_trigger(tmp_path):
    """`[core]` 段内除 bare 之外的键（含名字里带 bare 的）不得触发。"""
    gd = _mk_git(
        str(tmp_path),
        config="[core]\n\trepositoryformatversion = 0\n\tbaremore = true\n",
    )
    assert _git_guard.check_core_bare(gd)["ok"] is True


# ── CLI 集成：必须能拦住开工 ──────────────────────────────────────────────
def test_cli_bare_true_exit1_and_actionable(tmp_path):
    gd = _mk_git(str(tmp_path), config="[core]\n\tbare = true\n")
    r = _run(["--git-dir", gd])
    assert r.returncode == 1, r.stdout + r.stderr
    assert "core.bare" in r.stdout
    assert "git config --local core.bare false" in r.stdout


def test_cli_bare_false_exit0(tmp_path):
    gd = _mk_git(str(tmp_path), config=HEALTHY_CONFIG)
    r = _run(["--git-dir", gd])
    assert r.returncode == 0, r.stdout + r.stderr


def test_cli_json_exposes_core_bare(tmp_path):
    """--json 必须带 core_bare 字段，便于脚本按机器可读口径判红。"""
    gd = _mk_git(str(tmp_path), config="[core]\n\tbare = true\n")
    r = _run(["--git-dir", gd, "--json"])
    assert r.returncode == 1
    data = json.loads(r.stdout)
    assert data["ok"] is False
    assert data["core_bare"]["id"] == "core-bare"
    assert data["core_bare"]["ok"] is False
    # L0 四查在这种损坏下依然全绿 —— 这正是要单独立判据的原因
    assert all(item["ok"] for item in data["l0"])


def test_cli_json_healthy_has_core_bare_ok(tmp_path):
    gd = _mk_git(str(tmp_path), config=HEALTHY_CONFIG)
    r = _run(["--git-dir", gd, "--json"])
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["core_bare"]["ok"] is True


def test_cli_quiet_still_reports_core_bare_when_broken(tmp_path):
    """--quiet 只在健康时静默；core.bare 坏了必须出声。"""
    gd = _mk_git(str(tmp_path), config="[core]\n\tbare = true\n")
    r = _run(["--git-dir", gd, "--quiet"])
    assert r.returncode == 1
    assert "core.bare" in r.stdout
