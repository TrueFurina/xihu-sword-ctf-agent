"""DockerSession 的 fail-closed 护栏。

守的是什么（这是本测套存在的唯一理由）
──────────────────────────────────────
本机 Docker daemon 是**时好时坏**的：同一会话内先用还好用，过一阵再敲就变
`npipe ... dockerDesktopLinuxEngine: The system cannot find the file specified`
（2026-10-09 实测：下午还能 ps 出容器、inspect 有数据，到晚上直接报
`Docker Desktop is unable to start` / engine HTTP 503）。

于是最危险的失败形态**不是**「docker 起不来导致报错」，而是：

    「docker 起不来」→ 后端默默退回本机 Windows shell → 命令照跑、rc=0、
     输出照有 → 上层以为工具执行成了，其实是**在错误的机器上干的活**。

这类假绿比报错难查一个量级：ziphard 的 bkcrack 在 Windows 上根本编不出来，
一旦静默降级，日志看到的就是「bkcrack 执行失败」，然后一直重试到预算烧光。
本测套锁死「**任何** docker 侧失败都必须返回 UNAVAILABLE_RC 并带
[DOCKER_UNAVAILABLE] 标记，绝不 fallback」。

设计纪律（沿用 ㉚ / ㉗）
─────────────────────
- **不真发起 docker 调用**：`subprocess.run` 全程 stub（见 `_CapturingRun`）。
  否则守卫一旦失效，测试自身就成了真实请求发射道——最糟的失败形态。
- **断言打在生产的 `_exec` / `availability_reason` 上**，不在测试里复述判定式；
  源码级禁令（不许出现 `shell=True`、不许回调本地 `_exec`）用 AST 扫生产模块。
- 「当前为 0 命中」的护栏必须配合成自检，否则把规则删掉照样全绿
  （㉚ 的教训：模仿实现的自检不算守卫）。

变异验证见文件末尾。
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.docker_session import (  # noqa: E402
    UNAVAILABLE_RC,
    UNAVAILABLE_TAG,
    DockerSession,
)

_MODULE_PATH = Path(__file__).resolve().parent.parent / "core" / "docker_session.py"


# ── 测试替身 ────────────────────────────────────────────────────────────────
class _CapturingRun:
    """替身：记录所有 subprocess.run 调用并按要求返回假结果。

    不真跑 docker。`inspect_ok=False` 模拟容器没起；`raise_on_exec=True`
    模拟 daemon 在 exec 那一刻当场挂掉——这正是诱发「那就降级跑本地吧」
    这种冲动的两个场景。
    """

    def __init__(self, inspect_ok=True, exec_stdout=b"", exec_rc=0, raise_on_exec=False):
        self.calls = []          # [(argv, kwargs)]
        self.inspect_ok = inspect_ok
        self.exec_stdout = exec_stdout
        self.exec_rc = exec_rc
        self.raise_on_exec = raise_on_exec

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        is_probe = "inspect" in argv
        if is_probe:
            # 探针：这里有独立的成功/失败开关。**且 mend失败了必须给非 0 rc**——
            # 曾经这里写成「探针也返回 exec_rc(默认 0)」，结果探针失败被判成
            # 「容器在跑」，测试替身自己把护栏要走的那条路径给短路了。
            return subprocess.CompletedProcess(
                args=argv,
                returncode=0 if self.inspect_ok else 1,
                stdout=b"true\n" if self.inspect_ok else b"",
                stderr=b"" if self.inspect_ok else b"Error: No such object\n",
            )
        if self.raise_on_exec:
            raise FileNotFoundError("docker: no such file or directory")
        return subprocess.CompletedProcess(
            args=argv, returncode=self.exec_rc,
            stdout=self.exec_stdout, stderr=b"boom\n" if self.exec_rc else b"",
        )


@pytest.fixture
def sess(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    return DockerSession(cwd=str(work), image="ctf-tools:1",
                         container="unit-test-ctn", session_id="unit")


def _patch_subprocess(monkeypatch, run):
    monkeypatch.setattr("core.docker_session.subprocess.run", run)
    return run


class TestNoSilentFallback:
    """docker 不可用时，必须报错，**不得**退回本机 shell。"""

    def test_container_down_returns_unavailable(self, sess, monkeypatch):
        """容器不在跑 → UNAVAILABLE_RC + 标记，且**一次 exec 都不发**。"""
        sub = _patch_subprocess(monkeypatch, _CapturingRun(inspect_ok=False))
        rec = sess._exec("bkcrack --version", 60, "")
        assert rec.returncode == UNAVAILABLE_RC, rec.stderr
        assert UNAVAILABLE_TAG in rec.stderr
        # 只允许探测；任何 exec 调用都说明「探测失败后还想硬跑」
        assert [c for c in sub.calls if "exec" in c[0]] == []

    def test_exec_raises_returns_unavailable_not_local(self, sess, monkeypatch):
        """exec 阶段抛异常（daemon 当场挂掉）→ UNAVAILABLE_RC，
        且**绝不能**顺手在本地再跑一次同样的命令。"""
        sub = _patch_subprocess(monkeypatch,
                                _CapturingRun(inspect_ok=True, raise_on_exec=True))
        rec = sess._exec("some-linux-tool --flag", 60, "")
        assert rec.returncode == UNAVAILABLE_RC, rec.stderr
        assert UNAVAILABLE_TAG in rec.stderr
        execs = [c for c in sub.calls if "exec" in c[0]]
        assert len(execs) == 1, f"应当只尝试一次容器 exec，实测 {len(execs)} 次"
        # 降级的最典型形态：退化成裸命令字符串 + 把本职工作目录交给宿主机 subprocess
        for argv, kw in sub.calls:
            assert kw.get("shell") is not True, "后端不许用宿主机 shell"
            assert kw.get("cwd") is None, "不得把 cwd 塞给宿主机 subprocess"

    def test_timeout_returns_minus_one(self, sess, monkeypatch):
        """超时归 -1（与本地后端语义一致），不得混成 UNAVAILABLE。"""
        def boom(argv, **kw):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kw.get("timeout", 1))

        monkeypatch.setattr("core.docker_session.subprocess.run", boom)
        monkeypatch.setattr(sess, "_container_is_running", lambda: True)
        rec = sess._exec("sleep 100", 5, "")
        assert rec.returncode == -1
        assert "[TIMEOUT]" in rec.stderr


class TestHappyPath:
    """可用时确实把命令送进容器的 sh（不是本机 shell）。"""

    def test_exec_argv_shape(self, sess, monkeypatch):
        sub = _patch_subprocess(
            monkeypatch, _CapturingRun(inspect_ok=True, exec_stdout=b"bkcrack 1.6.1\n"))
        rec = sess._exec("bkcrack --version", 60, "")
        assert rec.returncode == 0
        assert "1.6.1" in rec.stdout
        argv, kw = sub.calls[-1]
        assert argv[0] == "docker" and argv[1] == "exec"
        assert argv[-3:] == ["sh", "-c", "bkcrack --version"]
        assert "-w" in argv and "/work" in argv
        assert kw.get("shell") is not True, "命令由容器内 sh 解析，宿主机 shell 不参与"


# ── 源码级禁令：两块不得出现的写法 ───────────────────────────────────────────
def _scan_shell_true(path: Path) -> list[int]:
    """返回 `shell=True` 出现的所有行号。**打的是真实 AST 解析。**

    自我要求：合成自检必须走这个函数本身（见下方 test），不能自己在用例里
    重写一遍解析器——重写副本的后果见 ㉚（删了规则还全绿）。
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.keyword) and n.arg == "shell"
        and isinstance(n.value, ast.Constant) and n.value.value is True
    ]


def _scan_super_exec(path: Path) -> list[int]:
    """返回调用 `_exec` 的位置（在后端模块里回调本地 _exec = 降级入口）。"""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "_exec"
    ]


class TestSourceLevelBan:
    """宿主机 shell 一旦介入，引号/管道会被 Windows cmd.exe 先吃一层。

    这条禁令比逐条行为断言更硬：它直接堵死「将来有人在某个 except 里
    补一句 subprocess.run(cmd, shell=True)」这条路。
    """

    def test_module_never_uses_host_shell(self):
        offenders = _scan_shell_true(_MODULE_PATH)
        assert offenders == [], f"docker_session 模块内禁止 shell=True，发现行号：{offenders}"

    def test_no_super_exec_fallback(self):
        offenders = _scan_super_exec(_MODULE_PATH)
        assert offenders == [], \
            f"不允许在后端里回调本地 _exec（静默降级的标准实现），发现行号：{offenders}"

    def test_ban_detector_has_teeth(self, tmp_path):
        """检测器自身的合成自检：喂给它带违规的样本，它必须报警。"""
        bad = tmp_path / "bad.py"
        bad.write_text(
            "import subprocess\n"
            "subprocess.run('x', shell=True)\n"
            "class A:\n    def f(self):\n        return super()._exec('y', 1, '')\n",
            encoding="utf-8")
        assert _scan_shell_true(bad), "shell=True 检测器对合成样本无反应——护栏是空壳"
        assert _scan_super_exec(bad), "super()._exec 检测器对合成样本无反应——护栏是空壳"

    def test_clean_sample_is_not_flagged(self, tmp_path):
        """反向自检：合规样本必须 0 命中，否则护栏会天天假红、最终被整段注释掉。"""
        good = tmp_path / "ok.py"
        good.write_text(
            "import subprocess\n"
            "subprocess.run(['docker', 'exec', 'x', 'sh', '-c', 'ls'], shell=False)\n",
            encoding="utf-8")
        assert _scan_shell_true(good) == []
        assert _scan_super_exec(good) == []


# ── 可用性原因串（给上层看的，必须认得出）──────────────────────────────────
class TestAvailabilityReason:
    def test_down_gives_actionable_reason(self, sess, monkeypatch):
        monkeypatch.setattr(sess, "_container_is_running", lambda: False)
        reason = sess.availability_reason()
        assert reason and UNAVAILABLE_TAG in reason
        assert "start()" in reason, "要告诉调用方怎么修，而不是只说「失败」"

    def test_up_returns_none(self, sess, monkeypatch):
        monkeypatch.setattr(sess, "_container_is_running", lambda: True)
        assert sess.availability_reason() is None

    def test_start_failure_is_reported_not_guessed(self, sess, monkeypatch):
        """docker run 失败要带回真实 rc/stderr，不许吞掉说「成功了」。"""
        monkeypatch.setattr(sess, "_container_is_running", lambda: False)
        _patch_subprocess(monkeypatch, _CapturingRun(inspect_ok=False, exec_rc=1))
        ok, why = sess.start()
        assert ok is False
        assert UNAVAILABLE_TAG in why and "rc=" in why


"""
变异验证（本次实记录）
────────────────────
绿灯基线：11 passed。依次注入以下飘移，确认测套报红：

  M1  except 分支首行插入 `return super()._exec(...)`
      （最典型的「那就降级跑本地吧」）      → 2 failed
      （test_no_super_exec_fallback + test_exec_raises_returns_unavailable_not_local）
  M2  availability_reason() 开头短路 `return None`
      （探测失效，直接去 exec）            → 2 failed
  M3  exec 异常的 except 里补一次
      `subprocess.run(cmd, shell=True, cwd=self.cwd)`（降级形态）
                                          → 2 failed
      （test_module_never_uses_host_shell + test_exec_raises_..._not_local）
  M4  _scan_shell_true 开头 `return []`     → 1 failed（由合成自检
      test_ban_detector_has_teeth 抓住；真实模块上该分支恒绿）

M4 尤其重要：源码级禁令在真实模块上恒为「0 命中」，不配合成样本它等于不存在。
"""
