# -*- coding: utf-8 -*-
"""MainAgent 墙钟硬止损测试（2026-08-20 锐评 P0-2/P0-4 整改）。

验证：
1. 墙钟命中时 _finalize 输出 error.category=wallclock_timeout（区别于 stuck_loop）
2. 墙钟未命中且无 flag 时仍是 stuck_loop
3. per_question_wallclock 阈值可注入覆盖
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace
from core.main_agent import (
    MainAgent,
    AgentContext,
    ERR_WALLCLOCK_TIMEOUT,
    ERR_STUCK_LOOP,
    ERR_UNRESOLVED,
)


def _make_question(qid="t1", category="crypto"):
    return SimpleNamespace(
        id=qid,
        category=category,
        title="test",
        description="",
        flag_pattern=r"flag\{[^}]+\}",
        attachments=None,
    )


def _make_agent(wallclock=300):
    """构造一个不依赖 LLM/工具的 MainAgent（只测 _finalize 分类逻辑）。"""
    return MainAgent(per_question_wallclock=wallclock)


def test_wallclock_hit_classified():
    """墙钟命中 + 无 flag → error.category=wallclock_timeout。"""
    agent = _make_agent(wallclock=300)
    ctx = AgentContext(question=_make_question())
    ctx._start_monotonic = 0.0  # 假起点
    ctx._wallclock_hit = True
    # 无 candidate_flag
    result = agent._finalize(ctx, attempt=0)
    err = result.get("error")
    assert err is not None, "无 flag 应产出 error"
    assert err["category"] == ERR_WALLCLOCK_TIMEOUT, f"期望 wallclock_timeout，实得 {err['category']}"
    assert "墙钟" in err["detail"]
    assert result["flag"] is None
    print("✓ test_wallclock_hit_classified")


def test_wallclock_not_hit_returns_unresolved():
    """未命中墙钟 + 无 flag + 无异常 → unresolved（2026-08-28 新 taxonomy：

    非真死循环（stuck_count<3）的"未解出且无明确归因"归 unresolved，而非一律 stuck_loop。
    """
    agent = _make_agent(wallclock=300)
    ctx = AgentContext(question=_make_question())
    ctx._wallclock_hit = False
    result = agent._finalize(ctx, attempt=0)
    err = result["error"]
    assert err is not None
    assert err["category"] == ERR_UNRESOLVED, f"期望 unresolved，实得 {err['category']}"
    print("✓ test_wallclock_not_hit_returns_unresolved")


def test_wallclock_threshold_injectable():
    """阈值可通过构造参数注入（默认 300，可覆盖为 10）。"""
    a_default = _make_agent()
    assert a_default.per_question_wallclock == 300
    a_small = _make_agent(wallclock=10)
    assert a_small.per_question_wallclock == 10
    print("✓ test_wallclock_threshold_injectable")


def test_wallclock_hit_with_flag_no_error():
    """墙钟命中但已拿到 flag → 不产 error（flag 优先于墙钟）。"""
    agent = _make_agent(wallclock=300)
    ctx = AgentContext(question=_make_question())
    ctx._wallclock_hit = True
    ctx.candidate_flag = "flag{got_it_2026}"
    result = agent._finalize(ctx, attempt=0)
    assert result["flag"] == "flag{got_it_2026}"
    assert result["error"] is None
    print("✓ test_wallclock_hit_with_flag_no_error")


def test_wallclock_hard_uses_hard_threshold_in_detail():
    """HARD 题墙钟命中 → error detail 反映 hard_wallclock（非 per_question 300）。"""
    agent = MainAgent(per_question_wallclock=300, hard_wallclock=480)
    q = _make_question()
    q.difficulty = "HARD"
    ctx = AgentContext(question=q)
    ctx._wallclock_hit = True
    result = agent._finalize(ctx, attempt=0)
    err = result.get("error")
    assert err is not None
    assert err["category"] == ERR_WALLCLOCK_TIMEOUT
    assert "480" in err["detail"], f"期望 detail 含 480，实得 {err['detail']}"
    print("✓ test_wallclock_hard_uses_hard_threshold_in_detail")


if __name__ == "__main__":
    test_wallclock_hit_classified()
    test_wallclock_not_hit_returns_stuck_loop()
    test_wallclock_threshold_injectable()
    test_wallclock_hit_with_flag_no_error()
    print("=== main_agent 墙钟止损测试全部通过 ===")
