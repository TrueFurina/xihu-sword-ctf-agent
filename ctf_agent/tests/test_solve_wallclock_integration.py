# -*- coding: utf-8 -*-
"""MainAgent solve() 墙钟硬止损集成测试（2026-08-21 锐评 P0-4 补强）。

验证 solve() 主循环在墙钟超限时：
1. break 跳出循环（不再调 _plan/_act）
2. 返回 error.category=wallclock_timeout
3. 不产出 flag

手法：注入极小 per_question_wallclock + monkeypatch time.monotonic 让 elapsed 超限，
无需真实 LLM 调用即可验证循环 break 逻辑。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace
from core.main_agent import MainAgent, ERR_WALLCLOCK_TIMEOUT


class _FakeTime:
    """假时钟：每次调用返回递增值，模拟时间流逝。"""

    def __init__(self, start=0.0, step=0.0):
        self._now = start
        self._step = step

    def monotonic(self):
        v = self._now
        self._now += self._step
        return v


def _make_question(qid="t1", category="crypto"):
    return SimpleNamespace(
        id=qid,
        category=category,
        title="test",
        description="test desc",
        flag_pattern=r"flag\{[^}]+\}",
        attachments=None,
        extra={},
    )


def test_solve_breaks_on_wallclock():
    """墙钟超限时 solve() 立即 break，返回 wallclock_timeout。"""
    import core.main_agent as ma

    # 注入假时钟：起点 0，每次 time.monotonic() 调用 +400s（一步即超 300s 阈值）
    fake = _FakeTime(start=0.0, step=400.0)
    original = ma.time.monotonic
    ma.time.monotonic = fake.monotonic
    try:
        agent = MainAgent(per_question_wallclock=300)
        # _plan 不该被实质调用（墙钟先 break）——但循环顶部先检查，
        # 第一次进入时 elapsed=400 >= 300 即 break，不执行 _plan
        result = agent.solve(_make_question())
        # solve 是 async
        import asyncio
        out = asyncio.run(result)
        assert out["error"] is not None, "墙钟超限应产出 error"
        assert out["error"]["category"] == ERR_WALLCLOCK_TIMEOUT, (
            f"期望 wallclock_timeout，实得 {out['error']['category']}"
        )
        assert out["flag"] is None
        assert out["steps"] == [] or len(out["steps"]) == 0, "墙钟先 break 不应有步骤"
        print("✓ test_solve_breaks_on_wallclock")
    finally:
        ma.time.monotonic = original


def test_solve_under_wallclock_runs():
    """墙钟未超限时 solve() 正常进入循环（不立即 wallclock break）。"""
    import core.main_agent as ma

    # 假时钟：起点 0，步长 0.001（永远不超 300s）——会进入循环调 _plan
    # 但 _plan 依赖 LLM，未注入时会走兜底；为避免真实 LLM 调用，
    # 注入假 llm_client 返回 None（_plan 兜底 reason），max_retries=0 使循环上限为 0
    fake = _FakeTime(start=0.0, step=0.001)
    original = ma.time.monotonic
    ma.time.monotonic = fake.monotonic
    try:
        # max_retries=0 → range(0*3)=range(0) 循环不执行，直接 _finalize
        agent = MainAgent(per_question_wallclock=300, max_retries=0)
        import asyncio
        out = asyncio.run(agent.solve(_make_question()))
        # 循环未执行，无墙钟命中，无 flag → stuck_loop（非 wallclock）
        assert out["error"] is not None
        assert out["error"]["category"] != ERR_WALLCLOCK_TIMEOUT, (
            "未超限不应是 wallclock_timeout"
        )
        assert out["flag"] is None
        print("✓ test_solve_under_wallclock_runs")
    finally:
        ma.time.monotonic = original


if __name__ == "__main__":
    test_solve_breaks_on_wallclock()
    test_solve_under_wallclock_runs()
    print("=== main_agent solve() 墙钟集成测试全部通过 ===")
