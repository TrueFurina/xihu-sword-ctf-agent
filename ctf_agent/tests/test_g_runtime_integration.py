"""G1/G5 接入主链路运行时测试（2026-09-29）。

覆盖：
- MainAgent 构造：g_session 开关默认 ON、env 可关、显式参数优先
- solve() 建会话：context 挂上 Session/SessionMemory（g_session=True）
- act_step command 动作：真实执行、输出带回、记忆入账、rc 标注
- extract_flag 全链路护栏对 command 结果生效：
  * echo 硬编码假 flag + sha256 不符 → 拒绝（sha256 仲裁）
  * 命令输出真实 flag + sha256 匹配 → 采信
- build_plan_prompt：有会话历史时注入会话记录；无会话时不注入
- observe_step：command 结果打 command 标
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from core.main_agent import AgentContext, MainAgent  # noqa: E402
from core import phases  # noqa: E402
from core.prompts import build_plan_prompt  # noqa: E402
from core.session import Session  # noqa: E402
from core.memory import SessionMemory  # noqa: E402


def _q(flag_sha256=None):
    return SimpleNamespace(id="g1test", title="t", category="misc",
                           description="d", attachments=[],
                           flag_pattern=r"flag\{[^}]+\}",
                           flag_sha256=flag_sha256, difficulty="EASY",
                           extra={})


def _agent(**kw):
    kw.setdefault("llm_client", None)
    return MainAgent(registry=None, sandbox=None, **kw)


def _ctx_with_session(q=None):
    import tempfile
    q = q or _q()
    ctx = AgentContext(question=q)
    ctx.g_session = Session(tempfile.mkdtemp(prefix="g1test_ws_"), session_id="g1test")
    ctx.g_memory = SessionMemory("g1test")
    return ctx


# ── 开关语义 ────────────────────────────────────────────────
def test_g_session_default_on():
    assert _agent().g_session is True


def test_g_session_env_off(monkeypatch):
    monkeypatch.setenv("CTF_AGENT_G_SESSION", "0")
    assert _agent().g_session is False


def test_g_session_explicit_overrides_env(monkeypatch):
    monkeypatch.setenv("CTF_AGENT_G_SESSION", "1")
    assert _agent(g_session=False).g_session is False


def test_agentcontext_defaults_none():
    ctx = AgentContext(question=_q())
    assert ctx.g_session is None and ctx.g_memory is None


# ── act_step command 真实执行 ──────────────────────────────
def test_command_action_runs_and_records():
    ctx = _ctx_with_session()
    agent = _agent()
    plan = {"action": "command", "command": "echo hello_g1",
            "detail": "smoke", "stage": "recon"}
    act = asyncio.run(phases.act_step(agent, ctx, plan, 0))
    assert act["kind"] == "script"
    assert "hello_g1" in act["output"]
    assert act["command"] == "echo hello_g1"
    assert act["source"] == "echo hello_g1"  # 供 print-leak 闸检查
    assert len(ctx.g_session.history) == 1
    assert ctx.g_memory.step_count() == 1    # G5 记忆入账
    assert "[rc=0]" in act["output"]


def test_command_rc_nonzero_not_tool_failure():
    """rc>0（grep 无匹配等）是正常信号，不得标 error（否则误触死循环计数）。"""
    ctx = _ctx_with_session()
    agent = _agent()
    plan = {"action": "command", "command": "echo nothing | grep definitely_missing_xyz"}
    act = asyncio.run(phases.act_step(agent, ctx, plan, 0))
    assert act["error"] == ""


def test_command_placeholder_echo_sha256_rejected():
    """echo 硬编码假 flag + 题面 sha256 不符 → extract_flag 拒绝（闸门在运行时生效）。"""
    real = "flag{g1_real_answer}"
    ctx = _ctx_with_session(_q(flag_sha256=hashlib.sha256(real.encode()).hexdigest()))
    agent = _agent()
    plan = {"action": "command", "command": 'echo "flag{placeholder_fake}"'}
    act = asyncio.run(phases.act_step(agent, ctx, plan, 0))
    got = phases.extract_flag(agent, ctx, act)
    assert got is None, "sha256 不符的硬编码 flag 必须被拒绝"
    assert getattr(ctx, "_extract_failed", False) is True


def test_command_real_flag_sha256_accepted():
    """命令真实产出的 flag 与题面 sha256 匹配 → 采信（确定性早接受）。"""
    real = "flag{g1_real_answer}"
    ctx = _ctx_with_session(_q(flag_sha256=hashlib.sha256(real.encode()).hexdigest()))
    agent = _agent()
    plan = {"action": "command",
            "command": f"echo {real}"}
    act = asyncio.run(phases.act_step(agent, ctx, plan, 0))
    got = phases.extract_flag(agent, ctx, act)
    assert got == real


def test_command_echo_placeholder_guarded_by_print_leak_when_no_sha256():
    """无 sha256 时：echo 硬编码 flag 命中 print-leak（命令即 source）→ 拒绝。"""
    ctx = _ctx_with_session(_q(flag_sha256=None))
    agent = _agent()
    plan = {"action": "command", "command": 'echo "flag{hardcoded_guess}"'}
    act = asyncio.run(phases.act_step(agent, ctx, plan, 0))
    got = phases.extract_flag(agent, ctx, act)
    assert got is None, "echo 硬编码 flag 在无 sha256 时也应被 print-leak 闸拒绝"


# ── observe_step 打标 ──────────────────────────────────────
def test_observe_labels_command():
    agent = _agent()
    ctx = AgentContext(question=_q())
    rec = phases.observe_step(agent, ctx, {"action": "command", "stage": "recon"},
                              {"kind": "script", "output": "[rc=0]\nok",
                               "command": "echo ok"})
    assert rec.action == "command"


# ── plan prompt 注入 ───────────────────────────────────────
def test_plan_prompt_injects_session_record():
    ctx = _ctx_with_session()
    ctx.g_session.run("echo session_marker_12345")
    ctx.g_memory.add(ctx.g_session.history[-1])
    text = build_plan_prompt(ctx, 0)
    assert "持久工作区会话记录" in text
    assert "session_marker_12345" in text


def test_plan_prompt_no_injection_without_session():
    ctx = AgentContext(question=_q())
    text = build_plan_prompt(ctx, 0)
    assert "持久工作区会话记录" not in text


def test_plan_prompt_g5_compact_keeps_key_facts():
    ctx = _ctx_with_session()
    ctx.g_session.run("echo flag{keyfact_marker}")
    ctx.g_memory.add(ctx.g_session.history[-1])
    text = build_plan_prompt(ctx, 0)
    assert "KEY_FACT" in text or "flag{keyfact_marker}" in text


# ── solve() 建会话（集成冒烟，mock LLM 恒空 plan → 快速收口）────
async def _null_llm(system, user, attempt):
    return "{}"


def test_solve_creates_session_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_AGENT_STEP_TIMEOUT_S", "5")
    monkeypatch.setenv("CTF_AGENT_LLM_CALL_BUDGET", "2")
    agent = _agent(llm_client=_null_llm)
    q = _q()
    out = asyncio.run(agent.solve(q))
    assert out["task_id"] == "g1test"
    # 会话已建立（或创建失败时退化——两种都不崩）；这里 mock LLM 恒空，
    # 主循环按空 plan 走 reason 空转收敛，session 建立即可断言
    # （若 self.g_session=True 且创建成功，最后一次 solve 内 ctx 已释放，
    #  故直接检查 g_sessions 目录有无新子目录）
    base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "results", "g_sessions")
    assert os.path.isdir(base)
    assert any(d.startswith("g1test_") for d in os.listdir(base))


def test_solve_no_session_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_AGENT_STEP_TIMEOUT_S", "5")
    monkeypatch.setenv("CTF_AGENT_LLM_CALL_BUDGET", "2")
    agent = _agent(llm_client=_null_llm, g_session=False)
    out = asyncio.run(agent.solve(_q()))
    assert out["task_id"] == "g1test"
