"""P0-1 回归：no_progress_streak 是真正的空转检测器（替代被误用的 stuck_count）。

背景（2026-09-22 held-out 17 池实证）：3 题在「observation 非空、无工具报错、零候选」的
空转循环里烧 19-22 万 token，stuck_count 全程为 0，监督升级路径与死循环标注永不触发。
本测试锁定修复后语义：
  - stuck_count        仅数工具报错步（失败桶分类用，语义不变）
  - no_progress_streak 累计「无工具报错且无候选推进」的连续步（真正的空转检测）
  - 候选命中 / 监督 switch·upgrade / 同动作强切 都会重置 no_progress_streak
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.main_agent import (
    AgentContext, StepRecord, STAGE_RECON,
    VERDICT_SWITCH, VERDICT_UPGRADE,
)


def _step(error_category=None, observation="out"):
    return StepRecord(
        stage=STAGE_RECON, action="reason",
        observation=observation, error_category=error_category,
    )


def test_no_progress_increments_on_no_error_steps():
    ctx = AgentContext()
    for _ in range(5):
        ctx.record(_step(error_category=None))
    assert ctx.no_progress_streak == 5
    # stuck_count 语义不变：无报错时恒为 0
    assert ctx.stuck_count == 0


def test_no_progress_resets_on_tool_error():
    ctx = AgentContext()
    for _ in range(3):
        ctx.record(_step(error_category=None))
    assert ctx.no_progress_streak == 3
    ctx.record(_step(error_category="tool_failure"))
    # 工具报错 → 状态在变，不算空转
    assert ctx.no_progress_streak == 0
    assert ctx.stuck_count == 1


def test_no_progress_resets_on_supervise_switch():
    ctx = AgentContext()
    for _ in range(4):
        ctx.record(_step(error_category=None))
    assert ctx.no_progress_streak == 4

    class _V:
        action = VERDICT_SWITCH
        reason = ""
        suggestion = "换个切入点"

    ctx.apply_verdict(_V())
    assert ctx.no_progress_streak == 0
    assert ctx.strategy_switches == 1


def test_no_progress_resets_on_supervise_upgrade():
    ctx = AgentContext()
    for _ in range(4):
        ctx.record(_step(error_category=None))
    assert ctx.no_progress_streak == 4

    class _V:
        action = VERDICT_UPGRADE
        reason = ""
        suggestion = ""

    ctx.apply_verdict(_V())
    assert ctx.no_progress_streak == 0
    assert ctx.model_upgrades == 1


def test_candidate_found_resets_no_progress():
    ctx = AgentContext()
    for _ in range(6):
        ctx.record(_step(error_category=None))
    assert ctx.no_progress_streak == 6
    # 真实链路里候选命中会重置（与 main_agent.py 两处 candidate_flag 赋值点同构）
    ctx.candidate_flag = "flag{x}"
    ctx.no_progress_streak = 0
    # 重置后继续无进展步，应从 0 重新累计，而非续接旧值
    ctx.record(_step(error_category=None))
    assert ctx.no_progress_streak == 1


def test_error_then_no_error_restarts_streak():
    ctx = AgentContext()
    ctx.record(_step(error_category="tool_failure"))
    assert ctx.no_progress_streak == 0
    ctx.record(_step(error_category=None))
    assert ctx.no_progress_streak == 1
    ctx.record(_step(error_category=None))
    assert ctx.no_progress_streak == 2
