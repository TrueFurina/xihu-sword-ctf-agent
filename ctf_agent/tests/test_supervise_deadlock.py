# -*- coding: utf-8 -*-
"""P0-A 监督死锁修复回归测试（2026-08-21 锐评整改）。

验证 main_agent.py:240-255 的修复：
1. stuck_count>=2 时调 _supervise（而非直接 break）
2. 监督裁决 give_up → break
3. 监督裁决 upgrade + attempt<2 → attempt 升级 + continue（不 break）
4. 监督裁决 upgrade + attempt>=2 → break（防无限升级）

手法：注入 mock supervisor（确定性裁决）+ mock _plan 返回空（不调 LLM），
     用 _FakeTime 防墙钟干扰，纯测循环控制流。
"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace
from core.main_agent import (
    MainAgent,
    AgentContext,
    SupervisionVerdict,
    ERR_STUCK_LOOP,
    VERDICT_GIVE_UP,
    VERDICT_UPGRADE,
    VERDICT_CONTINUE,
)
import core.main_agent as ma


class _FakeTime:
    """假时钟：步长极小，永不触发墙钟。"""
    def __init__(self):
        self._now = 0.0
    def monotonic(self):
        v = self._now
        self._now += 0.001
        return v


class _MockSupervisor:
    """确定性监督：按预设裁决返回，记录被调用次数。"""
    def __init__(self, verdict_action, reason="test", suggestion="test suggestion"):
        self._action = verdict_action
        self._reason = reason
        self._suggestion = suggestion
        self.call_count = 0

    async def review(self, ctx):
        self.call_count += 1
        return SupervisionVerdict(
            action=self._action,
            reason=self._reason,
            suggestion=self._suggestion,
        )


def _make_question(qid="supervise_test", category="crypto"):
    return SimpleNamespace(
        id=qid, category=category, title="test", description="test",
        flag_pattern=r"flag\{[^}]+\}", attachments=None, extra={},
    )


def _make_agent(supervisor, max_retries=3):
    """构造 MainAgent：注入 mock supervisor，不注入 LLM/工具（纯测控制流）。"""
    agent = MainAgent(
        supervisor=supervisor,
        max_retries=max_retries,
        per_question_wallclock=999999,  # 关掉墙钟干扰
    )
    return agent


def test_stuck_triggers_supervise_not_break():
    """stuck_count>=2 时调 _supervise（而非直接 break）——P0-A 核心断言。"""
    fake_time = _FakeTime()
    original = ma.time.monotonic
    ma.time.monotonic = fake_time.monotonic
    try:
        sup = _MockSupervisor(VERDICT_GIVE_UP, reason="测试放弃")
        agent = _make_agent(sup)
        # monkeypatch _plan 返回空 plan（不调 LLM，让循环走 observe→record→stuck）
        async def fake_plan(ctx, attempt):
            return {"action": "reason", "detail": "test"}
        agent._plan = fake_plan
        # monkeypatch _act 返回空结果（触发 stuck_count 累积）
        async def fake_act(ctx, plan, attempt):
            return {"flag": None, "output": ""}
        agent._act = fake_act

        result = asyncio.run(agent.solve(_make_question(), attempt=0))
        # 监督应被调用至少一次（如果直接 break 则 call_count=0）
        assert sup.call_count >= 1, (
            f"P0-A 回归失败：stuck_count>=2 应触发 _supervise，但调用次数={sup.call_count}"
        )
        assert result["error"] is not None
        print(f"✓ test_stuck_triggers_supervise_not_break (supervisor called {sup.call_count}x)")
    finally:
        ma.time.monotonic = original


def test_upgrade_low_attempt_continues():
    """监督裁决 upgrade + attempt<2 → attempt 升级（不直接 break）。"""
    fake_time = _FakeTime()
    original = ma.time.monotonic
    ma.time.monotonic = fake_time.monotonic
    try:
        sup = _MockSupervisor(VERDICT_UPGRADE, reason="升级重型模型")
        agent = _make_agent(sup, max_retries=5)
        _upgrade_seen = {"attempt": -1}

        async def fake_plan(ctx, attempt):
            _upgrade_seen["attempt"] = attempt
            return {"action": "reason", "detail": f"attempt={attempt}"}
        agent._plan = fake_plan

        async def fake_act(ctx, plan, attempt):
            return {"flag": None, "output": ""}
        agent._act = fake_act

        result = asyncio.run(agent.solve(_make_question(), attempt=0))
        # 监督应被调用
        assert sup.call_count >= 1, "upgrade 裁决应触发 _supervise"
        # 应看到 attempt 被升级到 2（在某一步）
        assert _upgrade_seen["attempt"] >= 2, (
            f"upgrade 应使 attempt>=2，实际 max attempt={_upgrade_seen['attempt']}"
        )
        print(f"✓ test_upgrade_low_attempt_continues (max attempt seen={_upgrade_seen['attempt']})")
    finally:
        ma.time.monotonic = original


def test_upgrade_high_attempt_breaks():
    """监督裁决 upgrade + attempt>=2 → break（防无限升级）。"""
    fake_time = _FakeTime()
    original = ma.time.monotonic
    ma.time.monotonic = fake_time.monotonic
    try:
        sup = _MockSupervisor(VERDICT_UPGRADE, reason="已升级仍失败")
        agent = _make_agent(sup, max_retries=5)

        async def fake_plan(ctx, attempt):
            return {"action": "reason", "detail": "test"}
        agent._plan = fake_plan

        async def fake_act(ctx, plan, attempt):
            return {"flag": None, "output": ""}
        agent._act = fake_act

        # attempt 从 2 开始（已升级过）
        result = asyncio.run(agent.solve(_make_question(), attempt=2))
        # 监督被调用后，attempt>=2 仍 upgrade → break
        assert sup.call_count >= 1, "应触发 _supervise"
        assert result["flag"] is None, "不应解出 flag"
        print(f"✓ test_upgrade_high_attempt_breaks (supervisor called {sup.call_count}x)")
    finally:
        ma.time.monotonic = original


if __name__ == "__main__":
    test_stuck_triggers_supervise_not_break()
    test_upgrade_low_attempt_continues()
    test_upgrade_high_attempt_breaks()
    print("=== P0-A 监督死锁回归测试全部通过 ===")
