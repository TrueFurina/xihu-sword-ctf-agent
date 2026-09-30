# -*- coding: utf-8 -*-
"""G1+G2 离线集成验证 · ¥0 / 零 token / 真实 subprocess（Windows cmd.exe 可用）。

对应 `2027-prep/差异分析-SOTA对比-20260928.md` 与 `下一步规划-v2` 轨道 A 第 4 步
「离线验证」。

**要证明的事（09-27 实测根因）**：
旧架构在 presolve miss 后，LLM 看不到"自己刚跑了什么"（没有持久会话 + 跨步记忆），
只能凭题面静态猜 → 外部 5 题 0/5、能力 2/2 中 LLM 贡献 0。本测试用真实 subprocess
跑一个静态挑战，证明：

  - **有 G1 持久会话（跨步 transcript 喂给 planner）**：planner 在第 2 轮能看到第 1 轮
    的输出，从而把"探查 → 读取 flag"串成两步，最终 SUCCESS。这正是把 LLM 从 0/14
    推向"有贡献"的核心杠杆。
  - **对照（planner 无视跨步记忆，模拟旧架构的"盲猜"）**：同一道可解题、同样的命令可用，
    却永远停在 `dir` 上、读不到 flag → STUCK。证明缺口确实是"跨步记忆"，不是"题太难"。

全程零网络、零 token：LLM 以**确定性脚本函数**注入（读 prompt 里的 transcript 字符串
做分支），Session.run 用真实本地 subprocess 执行 `dir`/`type`（cmd.exe 内建）。
"""

from __future__ import annotations

import os
import pathlib

from core.agent_loop import (
    AgentLoop, ExecutorAgent, PlannerAgent, ReflectAgent, Verdict,
)
from core.memory import SessionMemory
from core.model_registry import ModelMeta, ModelRegistry
from core.session import Session


# ── 挑战脚手架（真实静态题，可离线解）──────────────────────
FLAG = "flag{STATIC_DEMO_OK}"

# ── 平台感知的等价命令 ──────────────────────────────────────
# 同一套"探查 → 读取"两步语义，在两个平台上都是**真实 subprocess**：
#   Windows: cmd.exe 内建 type/dir（原实现）
#   POSIX  : /bin/sh 的 cat/ls（CI 跑 ubuntu-latest，cmd 内建不存在）
# 保留真实命令而非 mock，是为了仍然验证"跨步记忆把两步串起来"这件事本身。
_IS_WINDOWS = os.name == "nt"
CMD_READ_HINT = "type README.txt" if _IS_WINDOWS else "cat README.txt"
CMD_LIST_ALL = "dir /s /b" if _IS_WINDOWS else "ls -R"
CMD_READ_FLAG = ("type hidden\\answer.flag" if _IS_WINDOWS
                 else "cat hidden/answer.flag")


def _build_challenge(root: pathlib.Path) -> pathlib.Path:
    """在 root 下造一个可解的静态挑战。

    challenge/
      README.txt            # 提示：flag 在 hidden/ 下、文件名以 .flag 结尾
      hidden/
        answer.flag         # 内容即 FLAG
    """
    cwd = root / "challenge"
    hidden = cwd / "hidden"
    hidden.mkdir(parents=True, exist_ok=True)
    # ASCII-only：避免 Windows cmd.exe 输出 GBK 与 subprocess 文本解码冲突
    (cwd / "README.txt").write_text(
        "HINT: the flag is under the 'hidden' subdir, filename ends with .flag.\n"
        "Read it with the 'type' command to get the flag.\n",
        encoding="utf-8",
    )
    (hidden / "answer.flag").write_text(FLAG + "\n", encoding="utf-8")
    return cwd


# ── 注入的"LLM"：确定性脚本，但**真实读取 transcript**做分支 ──
def _make_memory_llm():
    """planner 拿到 prompt（内含 session.transcript）后据此决策。

    第 1 轮 transcript 为空 → 探查（读 README + 列文件）。
    第 ≥2 轮 transcript 里已含 'answer.flag' 路径但尚未出现 flag → 读取它。
    """

    def llm(prompt: str) -> str:
        trans = ""
        if "# 已执行会话上下文:" in prompt:
            trans = prompt.split("# 已执行会话上下文:", 1)[1]
        if "flag{" in trans:
            return "reason: 已在先前步骤获得 flag"
        if "answer.flag" in trans:
            # 上一轮探查已暴露路径，本轮读取 flag 文件
            return f"command: {CMD_READ_FLAG}"
        # 第 1 轮：读提示 + 列出全部文件，找到 flag 文件位置
        return f"command: {CMD_READ_HINT}\ncommand: {CMD_LIST_ALL}"

    return llm


def _make_blind_llm():
    """对照：planner 完全无视 transcript（模拟旧架构"盲猜"）。

    永远只列目录，从不读 README、从不读 answer.flag → 不可能解出。
    """

    def llm(prompt: str) -> str:
        return f"command: {CMD_LIST_ALL}"

    return llm


def _run_loop(cwd: pathlib.Path, llm, max_rounds: int = 5) -> "object":
    session = Session(str(cwd))
    planner = PlannerAgent(llm=llm)
    executor = ExecutorAgent(llm=llm)
    reflect = ReflectAgent(flag_pattern=r"flag\{.*?\}")
    loop = AgentLoop(planner, executor, reflect, session,
                     challenge="read hidden/answer.flag to obtain the flag",
                     flag_pattern=r"flag\{.*?\}")
    return loop.run(max_rounds=max_rounds)


# ── 测试 1：有跨步记忆 → 两步解出 SUCCESS ──────────────────
def test_loop_solves_via_cross_step_memory(tmp_path):
    cwd = _build_challenge(tmp_path)
    out = _run_loop(cwd, _make_memory_llm(), max_rounds=5)

    assert out.verdict == Verdict.SUCCESS
    # 必须 ≥2 轮：证明"探查 → 读取"是跨步串联，而非一步碰巧命中
    assert out.rounds >= 2
    # 会话输出的确出现过 flag（确定性判定，非 LLM 自报）
    assert Session(str(cwd)).grep_output(r"flag\{.*?\}") is not None or \
        any("flag{" in (r.stdout or "") + (r.stderr or "")
            for r in out.session.history)


# ── 测试 2：无视跨步记忆（旧架构对照）→ 同样命令可用却 STUCK ──
def test_without_cross_step_memory_gets_stuck(tmp_path):
    cwd = _build_challenge(tmp_path)
    out = _run_loop(cwd, _make_blind_llm(), max_rounds=4)

    # 同样的题、同样的命令可用，但 blind planner 永远停在 dir 上
    assert out.verdict == Verdict.STUCK
    # 始终没读过 answer.flag → 会话里从没出现过 flag
    assert out.session.grep_output(r"flag\{.*?\}") is None
    # 轮次确实跑满（说明是"卡住"而非"提前成功"）
    assert out.rounds == 4


# ── 测试 3：G1+G2 与 G5(记忆压缩)+G6(模型注册表) 组合可用 ────
def test_full_stack_composes_g1_g2_g5_g6(tmp_path):
    cwd = _build_challenge(tmp_path)
    out = _run_loop(cwd, _make_memory_llm(), max_rounds=5)
    assert out.verdict == Verdict.SUCCESS

    # G5：从会话构建压缩记忆，并能被检索召回 flag 事实
    mem = SessionMemory(session_id="demo").from_session(out.session)
    assert mem.fact_count() > 0
    summary = mem.compact(keep_recent=5)
    assert "flag" in summary.lower()
    hits = mem.retrieve("flag", top_k=3)
    assert any(f.kind == "flag" for f in hits)

    # G6：模型注册表可扩展、可查询、白名单判定生效
    reg = ModelRegistry()
    reg.register("deepseek", "deepseek-chat",
                ModelMeta(name="deepseek-chat", provider="deepseek",
                          ctx=64000, free=False))
    meta = reg.lookup("deepseek-chat")
    assert meta is not None and meta.provider == "deepseek"
    # deepseek 在默认白名单内（防注入/防越权 provider 的治理同源）
    assert reg.is_whitelisted("deepseek") is True
    # 未知 provider 默认不在白名单
    assert reg.is_whitelisted("unknown-evil") is False
