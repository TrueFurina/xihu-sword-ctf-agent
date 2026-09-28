"""占位符假阳性守卫测试（ReflectAgent / looks_like_placeholder）。

起因（2026-09-28 真机真题批次1 实锤）：LLM 执行 `echo "flag{...}"` 打印字面占位符，
旧逻辑"输出命中 flag 正则 = SUCCESS"把它判为真解出 → **伪造能力数字**。
本测试锁死该行为：占位符命中不得判定 SUCCESS；真实 flag 仍须正常判定。
"""
from __future__ import annotations

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from core.agent_loop import (  # noqa: E402
    AgentLoop, ExecutorAgent, Plan, ReflectAgent, Subtask, SubtaskKind,
    Verdict, looks_like_placeholder,
)
from core.session import Session  # noqa: E402


# ── looks_like_placeholder 纯函数 ──────────────────────────
@pytest.mark.parametrize("s", [
    "flag{...}", "flag{}", "flag{ }", "flag{xxx}", "flag{XXX}",
    "flag{???}", "flag{***}", "flag{flag}", "flag{your_flag}",
    "flag{placeholder}", "flag{redacted}", "flag{todo}", "flag{-}",
])
def test_placeholder_detected(s):
    assert looks_like_placeholder(s), s


@pytest.mark.parametrize("s", [
    "flag{REAL_LINUX_GCC_2026_SMOKE}", "flag{TRACKB_INTERACTIVE_OK}",
    "flag{s0me_r3al_flag}", "flag{CTF_test_1234}",
])
def test_real_flag_not_placeholder(s):
    assert not looks_like_placeholder(s), s


def test_empty_is_placeholder():
    assert looks_like_placeholder("")
    assert looks_like_placeholder(None)  # type: ignore[arg-type]


# ── ReflectAgent：占位符不得判 SUCCESS ────────────────────
class _FakeSession:
    """最小会话替身：仅提供 history（避免依赖真实执行）。"""

    def __init__(self, outs):
        from core.session import CommandRecord
        self.history = [
            CommandRecord(cmd="echo", cwd=".", stdout=o, stderr="", returncode=0,
                          ts="2026-09-28 00:00:00")
            for o in outs
        ]


def test_reflect_rejects_placeholder_hit():
    refl = ReflectAgent(flag_pattern=r"flag\{.*?\}")
    sess = _FakeSession(["no flag here", "flag{...}"])  # 只有占位符
    r = refl.reflect(Plan(), sess, [], round_no=1, max_rounds=3)
    assert r.verdict != Verdict.SUCCESS
    assert refl.flag_hit(sess) is None


def test_reflect_accepts_real_flag():
    refl = ReflectAgent(flag_pattern=r"flag\{.*?\}")
    sess = _FakeSession(["flag{REAL_ONE}"])
    r = refl.reflect(Plan(), sess, [], round_no=1, max_rounds=3)
    assert r.verdict == Verdict.SUCCESS
    assert refl.flag_hit(sess) == "flag{REAL_ONE}"


def test_reflect_skips_placeholder_and_takes_later_real_flag():
    refl = ReflectAgent(flag_pattern=r"flag\{.*?\}")
    sess = _FakeSession(["flag{...}", "flag{REAL_LATER}"])
    assert refl.flag_hit(sess) == "flag{REAL_LATER}"
    assert refl.reflect(Plan(), sess, [], 1, 3).verdict == Verdict.SUCCESS


# ── 端到端：真实 subprocess 复现 echo 占位符场景 ────────────
def test_echo_placeholder_no_longer_reports_success(tmp_path):
    """回归锁定：真实 shell 里 echo 占位符，loop 不得报 SUCCESS。"""
    d = tmp_path
    sess = Session(str(d))

    class Planner:
        def __init__(self):
            self.call_count = 0

        def plan(self, challenge, session, replan_hint=""):
            self.call_count += 1
            # 复现实测中 LLM 的行为：打印字面占位符
            return Plan(subtasks=[Subtask(SubtaskKind.COMMAND, "echo 'flag{...}'")],
                        raw="")

    loop = AgentLoop(Planner(), ExecutorAgent(), ReflectAgent(flag_pattern=r"flag\{.*?\}"),
                     sess, challenge="x", flag_pattern=r"flag\{.*?\}")
    out = loop.run(max_rounds=3)
    assert out.verdict != Verdict.SUCCESS, "占位符 echo 不得判为解出"
    # 旧行为（命中即 success）确实会误判，守卫必须拦住
    assert looks_like_placeholder(sess.grep_output(r"flag\{.*?\}") or "")
