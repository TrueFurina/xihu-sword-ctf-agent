# -*- coding: utf-8 -*-
"""合并闸门 `--merge-context` 回归（2026-10-11 修 pre-merge-commit 时序误杀）。

缺陷（裁判会话实锤，含复现）：git 2.55.0 在 `pre-merge-commit` 钩子执行时尚未把
`.git/MERGE_HEAD` 落盘（临时仓库复现：钩子内 `ls .git/MERGE_HEAD` → No such file or
directory，GIT_DIR 未注入、`rev-parse --git-dir` 解析正常，唯一变量是时序）。
于是闸门 `dirty_check()` 的 MERGE_HEAD 检测恒为假 → 把"合并产生的 staged 改动"误判成
"已跟踪在飞改动" → 打印「❌ 收尾门禁：工作树有 N 处已跟踪在飞改动」→ exit 1 →
本宿主上任何 `git merge --no-ff` 都被误杀（KPI 双通道与全量 pytest 根本没机会跑）。

修法边界（本测试钉死）：新增的 `--merge-context` 只许让 `dirty_check` 跳过收尾门禁，
不得连带放松 KPI 双通道、泄露扫描、全量 pytest 中的任何一项。

三条判据：
  1. `--merge-context` 下，即使工作树有已跟踪文件的在飞改动，dirty_check 返回 True（跳过）；
  2. 不传该参数且无 MERGE_HEAD 时，同一棵脏工作树必须返回 False（防松弛：门禁整体不许放宽）；
  3. `--merge-context` 只影响 dirty_check —— kpi_check / full_tests / --kpi-only 语义不变。

环境隔离：临时仓库的 git 调用一律用剔除「仓库绑定」变量的 env（清单取自
`git rev-parse --local-env-vars`，与 conftest.clean_git_env() 同源）。真实 commit 时
git 会向钩子及其后代导出 GIT_DIR/GIT_INDEX_FILE，测试若继承会把对象写进主仓
（2026-10-11 事故：测试文件落进主仓索引形成垃圾提交）——此处 fail-closed 校验兜住。
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import scripts._merge_gate as mg


def _clean_git_env():
    """剔除 git 导出的「仓库绑定」变量（清单同源 conftest.clean_git_env）。"""
    r = subprocess.run(["git", "rev-parse", "--local-env-vars"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    names = set(r.stdout.split()) if r.returncode == 0 else set()
    names |= {"GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR"}  # 清单缺失时兜底
    return {k: v for k, v in os.environ.items() if k not in names}


@pytest.fixture
def dirty_tmp_repo(tmp_path):
    """临时 git 仓库：1 个已跟踪文件被改（在飞改动 M）+ 1 个未跟踪杂物，且无 MERGE_HEAD。

    同时 monkeypatch `mg.sh`，让闸门的 git 调用落在本临时仓库（而非主仓）里执行。
    """
    env = _clean_git_env()
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        r = subprocess.run(["git", *args], cwd=str(repo), env=env, capture_output=True,
                           text=True, encoding="utf-8", errors="replace")
        assert r.returncode == 0, f"git {' '.join(args)} 失败：{r.stderr}"
        return r

    git("init", "-q")
    # 隔离校验（fail-closed）：仓库必须真的建在 tmp 里，否则说明 env 泄漏回了主仓
    gd = git("rev-parse", "--absolute-git-dir").stdout.strip()
    assert os.path.abspath(gd).startswith(os.path.abspath(str(tmp_path))), (
        f"临时仓库未隔离（git-dir={gd}）——env 泄漏会把对象写进主仓")

    (repo / "tracked.txt").write_text("v1\n", encoding="utf-8")
    iden = ["-c", "user.name=t", "-c", "user.email=t@t"]
    git(*iden, "add", "tracked.txt")
    git(*iden, "commit", "-q", "-m", "c1")
    (repo / "tracked.txt").write_text("v2\n", encoding="utf-8")  # 已跟踪文件的在飞改动
    (repo / "junk.txt").write_text("x", encoding="utf-8")        # 未跟踪杂物（闸门本就忽略）

    status = git("status", "--porcelain").stdout
    assert "tracked.txt" in status, f"临时仓库未构造出脏工作树：{status!r}"
    assert not os.path.exists(os.path.join(gd, "MERGE_HEAD")), "临时仓库不得处于合并中"

    def fake_sh(cmd, cwd=None, timeout=600):
        r = subprocess.run(cmd, cwd=str(repo), env=env, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=60)
        out = r.stdout
        if "--git-dir" in cmd:  # 相对路径按临时仓库解析，避免误命中进程 cwd 下的 .git
            out = out.strip()
            if out and not os.path.isabs(out):
                out = str(repo / out)
        return subprocess.CompletedProcess(cmd, r.returncode, out, r.stderr)

    return repo, fake_sh


def test_merge_context_skips_closeout_gate(dirty_tmp_repo, monkeypatch, capsys):
    """判据1：--merge-context 下，脏工作树（已跟踪文件 M）也跳过收尾门禁。"""
    _, fake_sh = dirty_tmp_repo
    monkeypatch.setattr(mg, "sh", fake_sh)
    assert mg.dirty_check(merge_context=True) is True, "合并上下文必须跳过收尾门禁"
    assert "跳过收尾门禁" in capsys.readouterr().out


def test_without_merge_context_dirty_tree_still_blocked(dirty_tmp_repo, monkeypatch, capsys):
    """判据2（防松弛）：不传 --merge-context 且无 MERGE_HEAD → 同一棵脏树必须拦下。"""
    _, fake_sh = dirty_tmp_repo
    monkeypatch.setattr(mg, "sh", fake_sh)
    assert mg.dirty_check() is False, "非合并上下文不得放宽收尾门禁（脏树仍须拦）"
    assert "收尾门禁" in capsys.readouterr().out


def _run_main(monkeypatch, argv, calls):
    monkeypatch.setattr(mg, "dirty_check",
                        lambda merge_context=False: (calls["dirty"].append(merge_context), True)[1])
    monkeypatch.setattr(mg, "kpi_check", lambda: (calls.__setitem__("kpi", calls["kpi"] + 1), True)[1])
    monkeypatch.setattr(mg, "full_tests", lambda: (calls.__setitem__("full", calls["full"] + 1), True)[1])
    monkeypatch.setattr(mg, "_pre_merge_snapshot", lambda kpi_only=False: True)
    monkeypatch.setattr(sys, "argv", argv)
    return mg.main()


@pytest.mark.parametrize("argv,expect_full", [
    (["_merge_gate.py"], 1),
    (["_merge_gate.py", "--merge-context"], 1),
    (["_merge_gate.py", "--kpi-only"], 0),
    (["_merge_gate.py", "--kpi-only", "--merge-context"], 0),
])
def test_merge_context_does_not_relax_other_gates(monkeypatch, argv, expect_full):
    """判据3：--merge-context 只作用于 dirty_check；KPI 双通道 / 全量测试 / --kpi-only 语义不变。"""
    calls = {"dirty": [], "kpi": 0, "full": 0}
    assert _run_main(monkeypatch, argv, calls) == 0
    assert calls["dirty"] == [argv.count("--merge-context") == 1], (
        f"{argv}：dirty_check 收到的 merge_context 不符预期 → {calls['dirty']}")
    assert calls["kpi"] == 1, f"{argv}：KPI 双通道必须照跑（不因 --merge-context 放松）"
    assert calls["full"] == expect_full, (
        f"{argv}：全量测试调用次数不符（--kpi-only 语义不得被 --merge-context 改写）")
