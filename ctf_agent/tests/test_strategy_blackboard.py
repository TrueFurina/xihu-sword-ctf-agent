"""strategy_blackboard 单元测试（P2 记忆层——题内跨步「已试策略黑板」，纯规则、无 LLM）。

背景：P1 两轮 held-out 真跑（外部池 0/10）诊断出「plan prompt 只含近 3 步窗口，
更早试过的失败策略被挤出 → 规划器原样重复」。黑板把每步策略签名+结局结构化
沉淀并注入 plan prompt。A/B 安全契约：黑板未启用（None）时 prompt 与旧版逐字一致。
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.main_agent import AgentContext, StepRecord  # noqa: E402
from core.prompts import build_plan_prompt  # noqa: E402
from core.strategy_blackboard import StrategyBlackboard, StrategyEntry  # noqa: E402


class Q:
    """最小题目桩。"""
    id = "bb_test"
    title = "黑板测试题"
    category = "misc"
    description = "test"
    flag_pattern = r"flag\{[^}]+\}"
    difficulty = "MEDIUM"


def _step(stage="recon", action="recon:command", tool=None, obs="", err=None):
    return StepRecord(stage=stage, action=action, tool_used=tool,
                      observation=obs, error_category=err)


# ── 纯黑板行为 ──
def test_record_aggregates_failures_and_empties():
    bb = StrategyBlackboard()
    bb.record(_step(obs="some output"))           # 有进展
    bb.record(_step(err="tool_failure"))          # 失败
    bb.record(_step(err="tool_failure"))          # 再失败（同签名）
    bb.record(_step(obs=""))                      # 无产出
    e = bb._entries["recon|recon:command|-"]
    assert e.count == 4
    assert e.failures == 2
    assert e.empties == 1
    assert e.last_error == "tool_failure"


def test_signature_distinguishes_stage_action_tool():
    bb = StrategyBlackboard()
    bb.record(_step(stage="recon", action="a1", tool="t1"))
    bb.record(_step(stage="exploit", action="a1", tool="t1"))
    bb.record(_step(stage="recon", action="a2", tool="t1"))
    bb.record(_step(stage="recon", action="a1", tool="t2"))
    assert len(bb._entries) == 4


def test_repeat_ratio_and_window():
    bb = StrategyBlackboard(window=5)
    assert bb.repeat_ratio() is None  # 样本不足 → None
    # 窗口 [a,a,b,b,c]：a 第 2 次 + b 第 2 次 = 2 步重复 → 2/5=0.4
    bb.record(_step(action="a", obs="ok"))
    bb.record(_step(action="a", obs="ok"))
    bb.record(_step(action="b", obs="ok"))
    bb.record(_step(action="b", obs="ok"))
    bb.record(_step(action="c", obs="ok"))
    rr = bb.repeat_ratio()
    assert rr is not None and abs(rr - 0.4) < 1e-9


def test_is_repeat_failure():
    bb = StrategyBlackboard()
    bb.record(_step(err="tool_failure"))
    assert bb.is_repeat_failure(_step(err="tool_failure"))
    assert not bb.is_repeat_failure(_step(action="other"))


def test_summary_empty_blackboard_returns_empty_string():
    assert StrategyBlackboard().summary() == ""


def test_summary_lists_failures_and_warning():
    # 「失败×4」聚合：4 步同签名报错
    bb = StrategyBlackboard()
    for _ in range(4):
        bb.record(_step(err="tool_failure"))
    text = bb.summary()
    assert "已试策略黑板" in text
    assert "失败×4" in text
    # 换策略告警：窗口 [a,a,b,b,c] 重复率 40% ≥ 阈值 40%
    bb2 = StrategyBlackboard()
    bb2.record(_step(action="a", obs="x"))
    bb2.record(_step(action="a", obs="x"))
    bb2.record(_step(action="b", err="tool_failure"))
    bb2.record(_step(action="b", err="tool_failure"))
    bb2.record(_step(action="c", obs="x"))
    text2 = bb2.summary()
    assert "重复率 40%" in text2


def test_lru_eviction_respects_max_entries():
    bb = StrategyBlackboard(max_entries=3)
    for i in range(5):
        bb.record(_step(action=f"act{i}", obs="x"))
    assert len(bb._entries) == 3
    # 最旧的 act0/act1 被淘汰，act2/act3/act4 保留
    assert "recon|act0|-" not in bb._entries
    assert "recon|act4|-" in bb._entries


def test_record_never_raises_on_dirty_step():
    bb = StrategyBlackboard()
    dirty = object()  # 无任何预期属性
    bb.record(dirty)  # 不抛异常即通过
    assert isinstance(bb.metrics()["entries"], int)


# ── AgentContext 接线 ──
def test_agentcontext_record_feeds_blackboard_when_enabled():
    ctx = AgentContext(question=Q())
    bb = StrategyBlackboard()
    ctx.blackboard = bb
    ctx.record(_step(err="tool_failure", obs="boom"))
    assert "recon|recon:command|-" in bb._entries
    assert bb.metrics()["failures"] == 1


def test_agentcontext_record_noop_without_blackboard():
    ctx = AgentContext(question=Q())  # blackboard 默认 None（旧行为）
    ctx.record(_step(err="tool_failure"))
    assert ctx.blackboard is None  # 不报错、不创建


# ── prompt 注入 A/B 契约 ──
def _mk_ctx_with_steps(n, blackboard=None):
    ctx = AgentContext(question=Q())
    ctx.blackboard = blackboard
    for _ in range(n):
        ctx.record(_step(err="tool_failure", obs="boom"))
    return ctx


def test_prompt_injects_blackboard_block_when_enabled():
    bb = StrategyBlackboard()
    ctx = _mk_ctx_with_steps(3, blackboard=bb)
    prompt = build_plan_prompt(ctx, 0)
    assert "【已试策略黑板】" in prompt
    assert "失败×3" in prompt
    assert "请勿原样重复" in prompt


def test_prompt_unchanged_when_blackboard_none():
    ctx_no_bb = _mk_ctx_with_steps(3, blackboard=None)
    p1 = build_plan_prompt(ctx_no_bb, 0)
    # 无黑板基线：不含黑板块
    assert "【已试策略黑板】" not in p1


def test_prompt_unchanged_when_blackboard_empty():
    ctx_empty = _mk_ctx_with_steps(0, blackboard=StrategyBlackboard())
    assert "【已试策略黑板】" not in build_plan_prompt(ctx_empty, 0)
    # 等价性：空黑板 ctx 与 无黑板 ctx 的 prompt 逐字一致（A/B 安全）
    assert build_plan_prompt(ctx_empty, 0) == build_plan_prompt(
        _mk_ctx_with_steps(0, blackboard=None), 0
    )


def test_prompt_blackboard_survives_step_window_eviction():
    """核心价值用例：6 步同签名失败——近 3 步窗口只见最后 3 步，
    黑板必须完整保留「失败×6」的完整历史并注入 prompt。"""
    bb = StrategyBlackboard()
    ctx = _mk_ctx_with_steps(6, blackboard=bb)
    prompt = build_plan_prompt(ctx, 0)
    assert "失败×6" in prompt
    # 已执行步骤窗口仍只显示近 3 步（旧行为不变）
    assert prompt.count("recon | recon:command") == 3


def test_entry_dataclass_defaults():
    e = StrategyEntry(signature="s|a|t")
    assert e.count == 0 and e.failures == 0 and e.empties == 0
    assert e.last_error is None and e.last_observation == ""
