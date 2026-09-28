"""G1 Session 抽象的单测（¥0、无 LLM、无网络）。

验证：命令捕获 / 历史累积 / 产物索引 / 跨步 transcript / 超时 / grep_output。
轨道 A 的可验证切片——证明"持久会话 + 跨步记忆"抽象在 Windows 上即可开发、可测。
"""

import os
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.session import CommandRecord, Session  # noqa: E402


def test_run_captures_stdout():
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        r = s.run("echo hello_world")
        assert r.returncode == 0
        assert "hello_world" in r.stdout
        assert r.ok()


def test_history_accumulates_across_steps():
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.run("echo step1")
        s.run("echo step2")
        assert s.step_count() == 2
        # 跨步：第二步能看到第一步的痕迹（transcript 合并）
        assert "step1" in s.transcript()
        assert "step2" in s.transcript()


def test_artifacts_indexed_on_write():
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        open(os.path.join(d, "out.txt"), "w").write("flag{abc}")
        s.run("echo done")  # 触发 _refresh_artifacts
        assert "out.txt" in s.artifacts
        assert os.path.isabs(s.artifacts["out.txt"])


def test_transcript_contains_steps_and_cwd():
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, session_id="t1")
        s.run("echo hi")
        t = s.transcript()
        assert "Session t1" in t
        assert "echo hi" in t
        assert d in t


def test_timeout_returns_negative_rc():
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        r = s.run(f'{sys.executable} -c "import time; time.sleep(5)"', timeout=1)
        assert r.returncode == -1
        assert "TIMEOUT" in r.stderr


def test_grep_output_finds_flag_in_history():
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.run("echo nothing_here")
        s.run("echo the_flag_is flag{FOUND123}")
        found = s.grep_output(r"flag\{[^}]+\}")
        assert found == "flag{FOUND123}"


def test_timeout_does_not_poison_next_command():
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.run(f'{sys.executable} -c "import time; time.sleep(5)"', timeout=1)
        r2 = s.run("echo recovered")
        assert r2.returncode == 0
        assert "recovered" in r2.stdout


def test_session_is_thread_safe():
    import threading

    with tempfile.TemporaryDirectory() as d:
        s = Session(d)

        def worker(i):
            s.run(f"echo w{i}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert s.step_count() == 8
