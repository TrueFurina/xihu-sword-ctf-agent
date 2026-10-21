# -*- coding: utf-8 -*-
"""浅层工具空转升级检测测试（2026-10-21 glm 真题实证补漏）。

背景：glm-4-flash 跑 cybench crushing 8 步 / flecks 9 步**全程只调 file_analyze**
（每次参数微调 → 观测输出不同 → E2 签名判重与同参数判重都不触发），直到预算
硬顶（81,794 ≥ 80,000）或空转止损。终止机制有效，但**恢复机制缺失**：reverse
题的专用深挖工具 rea_probe 从未被调用，也没有任何提示告诉模型该换工具。

本锁保证：
  1. 纯函数口径：连续 3 步同一浅层工具 + 本题型专用工具从未使用 → 具名提示
  2. 反向锁：已有候选 flag / 混用工具 / 重复的是专用工具 / 步数不足 / 无 registry → 不触发
  3. 去重：同一浅层工具同题只注入一次
  4. 集成锁：真实 solve 循环里 3 步 file_analyze 后 advisor_hint 必须带上升级提示
"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace
from unittest.mock import patch

from core.main_agent import (
    MainAgent,
    AgentContext,
    StepRecord,
    SupervisionVerdict,
    ERR_STUCK_LOOP,
    _shallow_tool_escalation,
    _apply_shallow_escalation,
    _force_deep_probe,
    _pick_probe_target,
    _SHALLOW_TOOLS,
    _SHALLOW_STREAK,
    _FORCED_STREAK,
)


class _FakeRegistry:
    """假注册表：inventory 直接返回预装备份清单（真实注册表已按题型过滤）。"""

    def __init__(self, inv):
        self._inv = inv

    def inventory(self, category=""):
        return list(self._inv)

    def get(self, name):
        return None


class _FakeRegistryWithRun(_FakeRegistry):
    """带异步 run 的假注册表（记录调用，返回预置探针产物）。"""

    def __init__(self, inv, run_result="decompiled-code", run_exc=None):
        super().__init__(inv)
        self._run_result = run_result
        self._run_exc = run_exc
        self.calls = []

    async def run(self, name, params):
        self.calls.append((name, params))
        if self._run_exc:
            raise self._run_exc
        return SimpleNamespace(text=self._run_result, ok=True)


def _inv_reverse():
    return [
        {"name": "file_analyze", "categories": ["misc", "web", "reverse", "crypto"],
         "desc": "通用文件分析（明文/元数据/内嵌文件头）", "params": {}},
        {"name": "rea_probe", "categories": ["reverse", "misc"],
         "desc": "ELF/PE 逆向探针（lane=auto 路由，decompile_batch 批量反编译）", "params": {}},
        {"name": "python", "categories": ["crypto", "misc", "web", "reverse", "pwn"],
         "desc": "沙盒 Python 执行", "params": {}},
    ]


def _ctx_with(steps, category="rev", candidate=None):
    """steps: list of (action, tool_used, observation)。"""
    q = SimpleNamespace(id="t-rev", category=category, difficulty="EASY",
                        description="ELF 逆向题面（模拟）", attachments=None,
                        flag_pattern=r"flag\{[^}]+\}")
    ctx = AgentContext(question=q)
    ctx.candidate_flag = candidate
    for action, tool, obs in steps:
        ctx.record(StepRecord(stage="recon", action=action,
                              observation=obs, tool_used=tool,
                              error_category=None, plan_fp="fp"))
    return ctx


def _fa(i):
    return (f"tool:file_analyze", "file_analyze", f"distinct-output-{i}")


# ── 1. 纯函数口径 ──────────────────────────────────────────────────────

def test_fires_on_repeated_shallow_tool():
    """连续 3 步 file_analyze + rea_probe/python 从未用 → 具名升级提示。"""
    ctx = _ctx_with([_fa(1), _fa(2), _fa(3)])
    got = _shallow_tool_escalation(SimpleNamespace(registry=_FakeRegistry(_inv_reverse())), ctx)
    assert got is not None, "连续 3 步浅层工具空转且专用工具未用，必须给升级提示"
    tool, hint = got
    assert tool == "file_analyze"
    assert "rea_probe" in hint, f"提示必须具名本题型专用工具：{hint}"
    assert "python" in hint
    assert "file_analyze" in hint, "提示要点名正在空转的浅层工具"
    assert "ELF/PE 逆向探针" in hint, "提示应带工具描述（来自 inventory desc）"


def test_no_fire_when_candidate_flag_exists():
    """已有候选 flag → 不触发（进展已有，不是空转）。"""
    ctx = _ctx_with([_fa(1), _fa(2), _fa(3)], candidate="flag{x}")
    assert _shallow_tool_escalation(
        SimpleNamespace(registry=_FakeRegistry(_inv_reverse())), ctx) is None


def test_no_fire_on_mixed_tools():
    """混用工具（fa/fa/rea_probe）→ 不是单一浅层工具空转。"""
    ctx = _ctx_with([_fa(1), _fa(2), ("tool:rea_probe", "rea_probe", "deep")])
    assert _shallow_tool_escalation(
        SimpleNamespace(registry=_FakeRegistry(_inv_reverse())), ctx) is None


def test_no_fire_when_dedicated_tool_repeated():
    """重复的是专用工具（rea_probe）→ 不是浅层空转（lane 升级由 rea_probe 内部提示管）。"""
    ctx = _ctx_with([("tool:rea_probe", "rea_probe", "d1"),
                     ("tool:rea_probe", "rea_probe", "d2"),
                     ("tool:rea_probe", "rea_probe", "d3")])
    assert _shallow_tool_escalation(
        SimpleNamespace(registry=_FakeRegistry(_inv_reverse())), ctx) is None


def test_no_fire_when_all_cat_tools_already_used():
    """本题型专用工具都已用过（前面步骤用过 rea_probe/python）→ 无可用升级目标。"""
    ctx = _ctx_with([("tool:rea_probe", "rea_probe", "d0"),
                     _fa(1), _fa(2), _fa(3)])
    ctx.record(StepRecord(stage="recon", action="tool:python",
                          observation="ran", tool_used="python",
                          error_category=None, plan_fp="fp"))
    assert _shallow_tool_escalation(
        SimpleNamespace(registry=_FakeRegistry(_inv_reverse())), ctx) is None


def test_no_fire_below_threshold():
    """不足 3 步 → 不触发（阈值与 E2/同参数判重对齐）。"""
    ctx = _ctx_with([_fa(1), _fa(2)])
    assert _shallow_tool_escalation(
        SimpleNamespace(registry=_FakeRegistry(_inv_reverse())), ctx) is None


def test_no_fire_without_registry():
    """无注册表 → 不触发（拿不到专用清单就不瞎指挥）。"""
    ctx = _ctx_with([_fa(1), _fa(2), _fa(3)])
    assert _shallow_tool_escalation(SimpleNamespace(registry=None), ctx) is None


def test_no_fire_when_inventory_explodes():
    """inventory 抛异常 → 不阻塞主循环，返回 None。"""

    class _Boom:
        def inventory(self, category=""):
            raise RuntimeError("boom")

    ctx = _ctx_with([_fa(1), _fa(2), _fa(3)])
    assert _shallow_tool_escalation(SimpleNamespace(registry=_Boom()), ctx) is None


def test_shallow_tool_set_is_explicit():
    """浅层工具集是显式白名单（file_analyze/flag_scan），不靠类别数猜。"""
    assert "file_analyze" in _SHALLOW_TOOLS
    assert "rea_probe" not in _SHALLOW_TOOLS
    assert _SHALLOW_STREAK == 3


# ── 2. 去重与注入 ──────────────────────────────────────────────────────

def test_apply_injects_once_per_tool():
    """同一浅层工具只注入一次；第二次调用返回 False 且不覆盖 advisor_hint。"""
    ctx = _ctx_with([_fa(1), _fa(2), _fa(3)])
    agent = SimpleNamespace(registry=_FakeRegistry(_inv_reverse()))
    assert _apply_shallow_escalation(agent, ctx) is True
    first = ctx.advisor_hint
    assert "rea_probe" in first
    assert ctx.escalated_tools == {"file_analyze"}
    # 再 record 两步同工具（仍满足触发条件）→ 去重生效
    ctx.record(StepRecord(stage="recon", action="tool:file_analyze",
                          observation="more", tool_used="file_analyze",
                          error_category=None, plan_fp="fp"))
    ctx.record(StepRecord(stage="recon", action="tool:file_analyze",
                          observation="more2", tool_used="file_analyze",
                          error_category=None, plan_fp="fp"))
    assert _apply_shallow_escalation(agent, ctx) is False
    assert ctx.advisor_hint == first, "去重后不得覆盖既有提示"


# ── 3. 集成锁：真实 solve 循环 ─────────────────────────────────────────

async def _fake_supervise(*a, **k):
    return SupervisionVerdict(action="continue")


def _run_loop(captured, budget=6):
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=budget)
    agent.registry = _FakeRegistry(_inv_reverse())
    q = SimpleNamespace(id="t-rev", category="reverse", difficulty="EASY",
                        description="ELF 逆向题面（模拟 crushing：观测微挑不死循环）",
                        attachments=None, flag_pattern=r"flag\{[^}]+\}")

    async def _plan(agent_, ctx, attempt):
        captured["ctx"] = ctx
        captured["plans"] = captured.get("plans", 0) + 1
        # 模拟 glm crushing：每步都调 file_analyze，参数微调 → 观测不同
        return {"action": "tool", "tool": "file_analyze",
                "hypothesis": "shallow_probe"}

    counter = {"i": 0}

    def _observe(agent_, ctx, plan, act):
        i = counter["i"]
        counter["i"] += 1
        return StepRecord(stage="recon", action="tool:file_analyze",
                          observation=f"distinct-output-{i}",
                          tool_used="file_analyze",
                          error_category=None, plan_fp=f"fp{i}")

    async def _act(*a, **k):
        return {"kind": "tool", "tool": "file_analyze", "output": "x"}

    async def _run():
        with patch("core.phases.plan_step", _plan), \
             patch("core.phases.act_step", _act), \
             patch("core.phases.supervise_step", _fake_supervise), \
             patch("core.phases.observe_step", _observe), \
             patch("core.presolve.presolve", _async_none):
            return await agent.solve(q)

    async def _async_none(*a, **k):
        return None

    return asyncio.run(_run())


def test_loop_injects_escalation_hint_after_3_shallow_steps():
    """集成锁（glm crushing 现场复刻）：3 步 file_analyze 后 advisor_hint 必须
    带上「换专用工具」升级提示——这是 crushing 8 步空烧 81,794 token 的修复点。"""
    captured = {}
    res = _run_loop(captured, budget=6)
    ctx = captured["ctx"]
    assert captured["plans"] >= 4, f"循环应至少跑 4 步以便观察第 3 步后的提示，实得 {captured['plans']}"
    hint = ctx.advisor_hint or ""
    assert "rea_probe" in hint, (
        f"3 步浅层工具空转后必须注入具名升级提示，实得 advisor_hint={hint!r}")
    assert "file_analyze" in hint
    assert ctx.escalated_tools == {"file_analyze"}, (
        f"去重集合应记录已提示工具，实得 {ctx.escalated_tools}")
    assert res.get("flag") in (None, ""), "本探针无 flag，不应误报解出"


# ── 4. 强制深挖（软提示被无视后机器自己动手）─────────────────────────

def _ctx_shallow_streak(n, category="reverse"):
    """n 步 file_analyze + 软提示已注入（escalated_tools 含 file_analyze）。"""
    steps = [(f"tool:file_analyze", "file_analyze", f"out-{i}") for i in range(n)]
    ctx = _ctx_with(steps, category=category)
    ctx.escalated_tools.add("file_analyze")
    return ctx


def _q_with_atts(atts):
    return SimpleNamespace(id="t-rev", category="reverse", difficulty="EASY",
                           description="ELF 逆向题面（模拟）", attachments=atts,
                           flag_pattern=r"flag\{[^}]+\}")


def test_pick_probe_target_prefers_magic_match(tmp_path):
    """魔数命中优先：ELF 二进制被选中，纯文本附件被跳过。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    txt = tmp_path / "message.txt.cz"
    txt.write_bytes(b"not-a-binary" * 40)   # 比 ELF 大也不能冒充
    got = _pick_probe_target("rea_probe", [str(txt), str(elf)])
    assert got == str(elf), f"应按魔数选 ELF，实得 {got}"


def test_pick_probe_target_falls_back_to_largest(tmp_path):
    """无魔数命中 → 取最大文件（二进制通常是最大的）。"""
    small = tmp_path / "a.bin"
    small.write_bytes(b"\x01\x02")
    big = tmp_path / "b.bin"
    big.write_bytes(b"\x03" * 500)
    got = _pick_probe_target("rea_probe", [str(small), str(big)])
    assert got == str(big)


def test_force_deep_probe_fires_when_soft_hint_ignored(tmp_path):
    """软提示注入后模型仍 5 步 file_analyze → 强制调用 rea_probe 并把产物写进历史。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_shallow_streak(_FORCED_STREAK)
    ctx.question = q
    reg = _FakeRegistryWithRun(_inv_reverse(), run_result="int main(){...serialize...}")
    got = asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx))
    assert got == "rea_probe", f"应强制调用 rea_probe，实得 {got}"
    assert reg.calls and reg.calls[0][0] == "rea_probe", f"registry.run 应被调用：{reg.calls}"
    last = ctx.steps[-1]
    assert last.tool_used == "rea_probe"
    assert "serialize" in last.observation, "探针产物必须进步骤历史供后续 plan 使用"
    assert ctx.forced_probes == {"rea_probe"}


def test_force_deep_probe_skipped_without_soft_hint(tmp_path):
    """软提示未注入（escalated_tools 空）→ 不强制（先让软提示说话）。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_shallow_streak(_FORCED_STREAK)
    ctx.escalated_tools.clear()
    ctx.question = q
    reg = _FakeRegistryWithRun(_inv_reverse())
    assert asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx)) is None
    assert reg.calls == [], "软提示未说话前不应强制调用"


def test_force_deep_probe_dedup_once_per_probe(tmp_path):
    """同探针每题只强制一次（第二次返回 None）。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_shallow_streak(_FORCED_STREAK)
    ctx.question = q
    reg = _FakeRegistryWithRun(_inv_reverse())
    agent = SimpleNamespace(registry=reg)
    assert asyncio.run(_force_deep_probe(agent, q, ctx)) == "rea_probe"
    assert asyncio.run(_force_deep_probe(agent, q, ctx)) is None
    assert len(reg.calls) == 1, f"每题只应强制一次，实得 {len(reg.calls)} 次"


def test_force_deep_probe_no_fire_below_threshold(tmp_path):
    """streak 不足 _FORCED_STREAK（如 4 步）→ 不强制。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_shallow_streak(_FORCED_STREAK - 1)
    ctx.question = q
    reg = _FakeRegistryWithRun(_inv_reverse())
    assert asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx)) is None
    assert reg.calls == []


def test_force_deep_probe_survives_registry_exception(tmp_path):
    """registry.run 抛异常 → 返回 None 不炸主循环。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_shallow_streak(_FORCED_STREAK)
    ctx.question = q
    reg = _FakeRegistryWithRun(_inv_reverse(), run_exc=RuntimeError("boom"))
    assert asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx)) is None
    assert ctx.forced_probes == set(), "失败的强制调用不应占用去重位"


def test_force_deep_probe_no_target_no_fire():
    """无附件 → 找不到目标 → 不强制。"""
    q = _q_with_atts([])
    ctx = _ctx_shallow_streak(_FORCED_STREAK)
    ctx.question = q
    reg = _FakeRegistryWithRun(_inv_reverse())
    assert asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx)) is None
    assert reg.calls == []


def test_force_deep_probe_respects_candidate_flag(tmp_path):
    """已有候选 flag → 不强制（不是空转了）。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_shallow_streak(_FORCED_STREAK)
    ctx.candidate_flag = "flag{x}"
    ctx.question = q
    reg = _FakeRegistryWithRun(_inv_reverse())
    assert asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx)) is None


# ── 4b. 纯推理空转形态（glm crushing/flecks 实证：真实步骤是 reason 不是 tool）──

def _ctx_reason_streak(n):
    """n 步纯 reason（tool_used 空）——glm 实证形态。"""
    ctx = _ctx_with([("reason", "", f"thinking-{i}") for i in range(n)])
    return ctx


def test_force_deep_probe_fires_on_reason_loop(tmp_path):
    """连续 5 步纯 reason 零工具 → 强制深挖（不需要软提示先说话：reason 链的
    软提示由监督强制路由在 3 步时已给，glm 实证不听从，机器 5 步直接动手）。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_reason_streak(_FORCED_STREAK)
    ctx.question = q
    assert ctx.escalated_tools == set(), "前置条件：reason 链不依赖浅层工具软提示"
    reg = _FakeRegistryWithRun(_inv_reverse(), run_result="int main(){...}")
    got = asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx))
    assert got == "rea_probe", f"reason 空转也应强制深挖，实得 {got}"
    assert ctx.steps[-1].tool_used == "rea_probe"


def test_force_deep_probe_no_fire_on_short_reason_loop(tmp_path):
    """reason 不足 5 步 → 不强制（给监督强制路由的 3 步提示留响应窗口）。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_reason_streak(_FORCED_STREAK - 1)
    ctx.question = q
    reg = _FakeRegistryWithRun(_inv_reverse())
    assert asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx)) is None
    assert reg.calls == []


def test_force_deep_probe_no_fire_on_mixed_reason_tool_window(tmp_path):
    """窗口里混了工具步（reason/reason/tool/reason/reason）→ 不是纯推理空转。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_with([("reason", "", "t0"), ("reason", "", "t1"),
                     ("tool:flag_scan", "flag_scan", "scan"), ("reason", "", "t3"),
                     ("reason", "", "t4")])
    ctx.question = q
    reg = _FakeRegistryWithRun(_inv_reverse())
    assert asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx)) is None


def test_force_deep_probe_picks_next_unused_probe(tmp_path):
    """rea_probe 已用过 → 选下一个未用探针，不重复强制同一个。"""
    elf = tmp_path / "crush"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    q = _q_with_atts([str(elf)])
    ctx = _ctx_with([("tool:rea_probe", "rea_probe", "code")] +
                    [("reason", "", f"t{i}") for i in range(_FORCED_STREAK + 1)])
    ctx.question = q
    inv = _inv_reverse() + [
        {"name": "wasm_probe", "categories": ["reverse", "misc"],
         "desc": "WASM 静态分析", "params": {}}]
    reg = _FakeRegistryWithRun(inv)
    got = asyncio.run(_force_deep_probe(SimpleNamespace(registry=reg), q, ctx))
    assert got == "wasm_probe", f"rea_probe 已用后应换 wasm_probe，实得 {got}"


# ── 5. 集成锁：强制深挖进真实循环 ─────────────────────────────────────

def _run_loop_with_probe(captured, budget=8):
    """真实循环 + 假注册表（rea_probe 返回反编译代码）→ 第 5 步后必须有强制深挖步。"""
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=budget)
    reg = _FakeRegistryWithRun(_inv_reverse(), run_result="int main(){...}")
    agent.registry = reg
    elf = os.path.join(captured["dir"], "crush")
    with open(elf, "wb") as fh:
        fh.write(b"\x7fELF" + b"\x00" * 64)
    q = SimpleNamespace(id="t-rev", category="reverse", difficulty="EASY",
                        description="ELF 逆向题面（模拟 crushing）", attachments=[elf],
                        flag_pattern=r"flag\{[^}]+\}")

    async def _plan(agent_, ctx, attempt):
        captured["ctx"] = ctx
        return {"action": "tool", "tool": "file_analyze", "hypothesis": "probe"}

    counter = {"i": 0}

    def _observe(agent_, ctx, plan, act):
        i = counter["i"]
        counter["i"] += 1
        return StepRecord(stage="recon", action="tool:file_analyze",
                          observation=f"distinct-{i}", tool_used="file_analyze",
                          error_category=None, plan_fp=f"fp{i}")

    async def _act(*a, **k):
        return {"kind": "tool", "tool": "file_analyze", "output": "x"}

    async def _async_none(*a, **k):
        return None

    async def _run():
        with patch("core.phases.plan_step", _plan), \
             patch("core.phases.act_step", _act), \
             patch("core.phases.supervise_step", _fake_supervise), \
             patch("core.phases.observe_step", _observe), \
             patch("core.presolve.presolve", _async_none):
            return await agent.solve(q)

    return asyncio.run(_run())


def test_loop_force_probes_after_soft_hint_ignored(tmp_path):
    """集成锁：模型 5 步不听软提示 → 机器必须自己调 rea_probe 并把代码写进历史。

    这是 glm crushing 8 步空烧 81,794 token 的硬修复：软提示（3 步）之后
    还有强制深挖（5 步），不把「模型自觉」当作唯一恢复路径。
    """
    captured = {"dir": str(tmp_path)}
    _run_loop_with_probe(captured, budget=8)
    ctx = captured["ctx"]
    used = [str(getattr(s, "tool_used", "") or "") for s in ctx.steps]
    assert "rea_probe" in used, (
        f"软提示被无视后必须强制深挖，实得工具序列 {used}")
    assert ctx.forced_probes == {"rea_probe"}
    probe_step = [s for s in ctx.steps if s.tool_used == "rea_probe"][0]
    assert "int main()" in probe_step.observation, "探针产物必须进步骤历史"


def _run_loop_reason(captured, budget=7):
    """真实循环 + 假 LLM 恒返 reason 计划（glm crushing/flecks 实证形态）。"""
    agent = MainAgent(per_question_wallclock=300, llm_call_budget=budget)
    reg = _FakeRegistryWithRun(_inv_reverse(), run_result="int main(){...}")
    agent.registry = reg
    elf = os.path.join(captured["dir"], "crush")
    with open(elf, "wb") as fh:
        fh.write(b"\x7fELF" + b"\x00" * 64)
    q = SimpleNamespace(id="t-rev", category="reverse", difficulty="EASY",
                        description="ELF 逆向题面（模拟 crushing）", attachments=[elf],
                        flag_pattern=r"flag\{[^}]+\}")

    async def _plan(agent_, ctx, attempt):
        captured["ctx"] = ctx
        return {"action": "reason", "hypothesis": "think-think"}

    counter = {"i": 0}

    def _observe(agent_, ctx, plan, act):
        i = counter["i"]
        counter["i"] += 1
        # 忠实复刻真实 observe_step 的 reason 分支：连续 2 步 reason 即打
        # ERR_STUCK_LOOP → stuck_count≥2 → 卡关块 continue 劫持（迁移前的死因）
        _recent = [s for s in (ctx.steps or [])[-2:] if s.action == "reason"]
        _stuck = ERR_STUCK_LOOP if len(_recent) >= 2 else None
        return StepRecord(stage="recon", action="reason",
                          observation=f"thinking-{i}", tool_used="",
                          error_category=_stuck, plan_fp=f"fp{i}")

    async def _act(*a, **k):
        return {"kind": "reason", "output": "thinking"}

    async def _async_none(*a, **k):
        return None

    async def _run():
        with patch("core.phases.plan_step", _plan), \
             patch("core.phases.act_step", _act), \
             patch("core.phases.supervise_step", _fake_supervise), \
             patch("core.phases.observe_step", _observe), \
             patch("core.presolve.presolve", _async_none):
            return await agent.solve(q)

    return asyncio.run(_run())


def test_loop_force_probes_on_reason_loop(tmp_path):
    """集成锁（glm 实证形态）：连续 5 步纯 reason 零工具 → 机器强制调 rea_probe。

    goal_log 实证：glm crushing/flecks 的真实步骤是 recon:reason（run_e2e 的
    tools 字段只反映 act 兜底的那一次 file_analyze，曾误导诊断为工具空转）。
    监督强制路由的 reason 提示在 3 步时已给过且模型不听从 → 5 步机器动手。
    """
    captured = {"dir": str(tmp_path)}
    _run_loop_reason(captured, budget=7)
    ctx = captured["ctx"]
    used = [str(getattr(s, "tool_used", "") or "") for s in ctx.steps]
    assert "rea_probe" in used, (
        f"纯推理空转 5 步后必须强制深挖，实得工具序列 {used}")
    assert ctx.forced_probes == {"rea_probe"}


# ── 6. 幻觉工具名自纠（registry.run 错误信息带可用工具清单）───────────

def test_registry_run_unknown_tool_lists_valid_tools():
    """glm 实证：模型幻觉调用 reverse_elf_general。错误信息必须带本题型可用
    工具清单，否则模型下一步继续幻觉（forced3 跑实证：2 步后就被止损）。"""
    import asyncio as _aio
    from tools.registry import ToolRegistry
    from tools.adapters.file_analysis_adapter import FileAnalysisAdapter
    from tools.adapters.rea_probe import ReaProbeAdapter

    reg = ToolRegistry()
    reg.register(FileAnalysisAdapter())
    reg.register(ReaProbeAdapter())
    q = SimpleNamespace(id="t", category="reverse", description="d", attachments=[])
    out = _aio.run(reg.run("reverse_elf_general", {"question": q}))
    assert out.ok is False
    assert "reverse_elf_general" in out.text, "错误信息要点名幻觉的工具名"
    assert "rea_probe" in out.text, (
        f"错误信息必须列出本题型可用工具供模型自纠，实得: {out.text}")
    assert "file_analyze" in out.text


def test_registry_run_unknown_tool_without_question():
    """无 question 上下文 → 退回全量工具名，不炸。"""
    import asyncio as _aio
    from tools.registry import ToolRegistry
    from tools.adapters.file_analysis_adapter import FileAnalysisAdapter

    reg = ToolRegistry()
    reg.register(FileAnalysisAdapter())
    out = _aio.run(reg.run("nope_tool", {}))
    assert out.ok is False
    assert "file_analyze" in out.text
