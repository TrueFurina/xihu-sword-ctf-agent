# -*- coding: utf-8 -*-
"""presolve 并发嗅探阶段「全局墙钟」护栏回归（2026-10-13）。

背景（实证，非推测）：`core/presolve.py::presolve()` 用 `asyncio.as_completed`
并发启动约 30 路确定性嗅探，但**整个阶段没有任何全局截止**。各 handler 只自带
subprocess 级 timeout，而：
  ① 部分 handler（maze BFS / primes Coppersmith / mhk2）走**进程内** CPU 密集
     循环，不受 subprocess timeout 约束；
  ② `WALLCLOCK_ZIPHARD = 3600`（1h）**远超**单题墙钟 `per_question_wallclock
     = 300s` —— handler 预算 > 调用方预算，契约本身不自洽；
  ③ 单题墙钟是**步间协作式检查**（main_agent.py:1273-1281），卡在 presolve
     单步内部根本走不到下一次检查 ⇒ 挂起无法被任何现有机制止损。

后果：任一 handler 非终止 ⇒ `as_completed` 永不返回 ⇒ 单题卡死、并发池被拖死，
且 **合并闸门（`scripts/_regress_one.py` 无超时）会被永久阻塞**。

修复：给并发嗅探阶段加全局墙钟截止（`CTF_AGENT_PRESOLVE_WALLCLOCK`，默认派生自
config `per_question_wallclock`，禁写死数字）。到期即：**loud 告警 + 取消剩余 +
回退已有候选**（候选必经 sha256/pattern/answer 校验才入 `_fallback`），
**绝不静默冒充成功**，也**不把止损当成"能力失败"计入能力率**。

变异纪律（㉚）：本文件只 stub 掉各 `_try_*` handler 依赖，**判定落在生产入口
`P.presolve()` 上**，不在用例里重写被测逻辑 —— 模仿实现的自检不算守卫。
零真实 LLM 调用，零 token 成本。
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import presolve as P  # noqa: E402
from eval.cases import Question  # noqa: E402


def _try_names() -> list:
    """生产入口里所有并发嗅探 handler 名（自动枚举，新增 handler 自动纳入）。"""
    return sorted(n for n in dir(P) if n.startswith("_try_"))


def _make_question(tmp_path) -> Question:
    """合成一道题：有一个真实存在、但不含 flag 的附件 ⇒ 嗅探阶段必被启动。"""
    att = tmp_path / "note.txt"
    att.write_text("no flag here, just a plain fixture note.\n",
                   encoding="utf-8")
    return Question(
        id="test_presolve_wallclock_fixture",
        title="wallclock guard fixture",
        category="misc",
        description="fixture for presolve global wallclock guard",
        attachments=[str(att)],
    )


def test_try_names_not_empty():
    """元自检：若枚举不到 handler，则本文件其余用例全是空转 —— 先钉死这个前提。

    这一条是「防假绿」用���：handler 重命名/删除会让 stub 全部失效，
    若没有这一条，下面两个用例会变成"没测到任何东西却通过"。
    """
    names = _try_names()
    assert len(names) >= 10, (
        f"枚举到的嗅探 handler 过少（{len(names)}）：{names}。"
        "若 handler 已改名，本文件需同步更新")


def test_presolve_global_wallclock_cuts_hanging_sniffer(tmp_path, monkeypatch,
                                                        caplog):
    """核心回归：任一 handler 挂起 ⇒ presolve 仍必须在全局墙钟内返回。

    stub 策略：把**所有** `_try_*` 换成立刻返回 None 的空转（排除真实
    附件/网络/二进制依赖），再把其中一路换成永久挂起。挂在被测入口
    `P.presolve()` 上的判定：
      - 必须在 deadline + 充足余量内返回（不挂死）；
      - 必须留下 loud 告警（含未完成路数）—— 静默止损等同掩盖。
    """
    q = _make_question(tmp_path)
    names = _try_names()
    assert names, "前提失败：未枚举到任何 handler"

    async def _no_op(*_a, **_k):
        return None

    async def _hang(*_a, **_k):
        await asyncio.sleep(3600)  # 永不自然结束
        return "flag{should_never_reach}"

    for n in names:
        monkeypatch.setattr(P, n, _no_op, raising=False)
    victim = names[0]
    monkeypatch.setattr(P, victim, _hang, raising=False)

    monkeypatch.setenv("CTF_AGENT_PRESOLVE_WALLCLOCK", "2")
    with caplog.at_level("WARNING", logger="core.presolve"):
        t0 = asyncio.get_event_loop_policy().new_event_loop().time()
        out = asyncio.run(P.presolve(q, registry=None, force=True))
        elapsed = (asyncio.get_event_loop_policy().new_event_loop().time()
                   - t0)

    assert out is None, (
        f"挂起 handler 不应返回候选，实际={out!r}（若非 None 说明止损失效）")
    assert elapsed < 60, (
        f"presolve 未能在全局墙钟内返回：耗时 {elapsed:.1f}s "
        f"（deadline=2s，余量应远小于 60s）")

    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert "墙钟耗尽" in msgs, (
        "全局墙钟止损未留下 loud 告警 —— 静默止损会掩盖真实挂起，"
        f"实际捕获日志：{msgs[:300] or '(空)'}")


def test_presolve_healthy_path_emits_no_wallclock_warning(tmp_path,
                                                          monkeypatch,
                                                          caplog):
    """反向守卫：全部 handler 正常快速返回 ⇒ 不得误报墙钟耗尽。

    防「守卫本身制造假红/假噪音」——若健康路径也告警，告警就会被无视，
    这正是项目反复强调的『天天假红的护栏最终会被整段注释掉』。
    """
    q = _make_question(tmp_path)

    async def _no_op(*_a, **_k):
        return None

    for n in _try_names():
        monkeypatch.setattr(P, n, _no_op, raising=False)

    monkeypatch.setenv("CTF_AGENT_PRESOLVE_WALLCLOCK", "120")
    with caplog.at_level("WARNING", logger="core.presolve"):
        out = asyncio.run(P.presolve(q, registry=None, force=True))

    assert out is None
    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert "墙钟耗尽" not in msgs, (
        f"健康路径被误报为墙钟耗尽（假红）：{msgs[:300]}")
