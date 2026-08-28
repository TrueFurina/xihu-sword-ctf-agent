# -*- coding: utf-8 -*-
"""MainAgent E3 附件证据强制注入测试（2026-08-25 桶C攻坚，v2：加 A/B 开关 + 信号度量）。

验证 E3（不依赖真 LLM/工具，全 mock / 纯函数）：
1. [开] ctx.e3_enabled=True 且 attachment_evidence 含全文 → plan 提示注入整段（桶C修复）
2. [基线] 有附件但无分析结果 → 不注入"附件分析全文"段，仅列路径（不破坏旧行为）
3. execute_tool 跑 file_analyze 后把全文累积进 ctx.attachment_evidence
4. [开] execute_tool 累积 → build_plan_prompt 下一轮注入全文（端到端）
5. [关] ctx.e3_enabled=False（默认）→ 即使有 evidence 也不注入（保证基线 KPI 不被改动）
6. [开] 注入时置 ctx.evidence_injected_into_prompt=True（供 error_struct 信号度量）
7-10. subclassify C 桶用 evidence_injected 三态真信号（向后兼容 tool_failure 代理）
11. goal_directive 透传 evidence_injected 三态进 error_struct（落盘链路）
"""
import sys
import os
import asyncio
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace

from core.main_agent import MainAgent, AgentContext
from core.prompts import build_plan_prompt
from core.action_executor import execute_tool
from core.goal_directive import GoalLogger

# scripts 无 __init__.py，按路径加载 _chain_stats 纯函数模块
_scripts_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)
from _chain_stats import subclassify  # noqa: E402


def _q(category="misc", description="压缩包附件解题", attachments=None):
    return SimpleNamespace(
        id="t",
        title="样本题",
        category=category,
        difficulty="EASY",
        description=description,
        attachments=attachments,
        flag_pattern=r"flag\{[^}]+\}",
    )


# ── 原 4 测试（E3 开启路径）─────────────────────────────

def test_plan_prompt_injects_attachment_evidence():
    """[开] attachment_evidence 有内容 → plan 提示注入整段全文（含真实参数）。"""
    ctx = AgentContext(
        question=_q(attachments=["a.zip"]),
        attachment_evidence=["【附件 a.zip】\nREAL FILE CONTENT n=999 e=65537"],
        e3_enabled=True,  # E3 开关：默认关，测试显式开
    )
    prompt = build_plan_prompt(ctx, 0)
    assert "附件分析全文" in prompt, "含证据时必须注入'附件分析全文'段（桶C修复）"
    assert "REAL FILE CONTENT n=999 e=65537" in prompt, "证据全文必须进 prompt（非仅路径）"
    print("✓ test_plan_prompt_injects_attachment_evidence")


def test_plan_prompt_no_evidence_section_without_analysis():
    """有附件但未分析（基线）→ 不注入全文段，仅列路径，旧行为不变。"""
    ctx = AgentContext(question=_q(attachments=["a.zip"]))  # attachment_evidence 默认 []
    prompt = build_plan_prompt(ctx, 0)
    assert "附件分析全文" not in prompt, "无证据时不应注入全文段（保基线）"
    assert "附件: a.zip" in prompt, "基线仍应列出附件路径"
    print("✓ test_plan_prompt_no_evidence_section_without_analysis")


class _FakeOut:
    text = "FILE CONTENT HERE"
    ok = True


class _FakeReg:
    def has(self, name):
        return True

    async def run(self, name, params):
        return _FakeOut()


def test_execute_tool_accumulates_attachment_evidence():
    """execute_tool 跑 file_analyze → ctx.attachment_evidence 累积全文。"""
    ctx = AgentContext(question=_q(attachments=["a.zip"]))
    res = asyncio.run(execute_tool(_FakeReg(), ctx, {"tool": "file_analyze"}, "analyze"))
    assert "FILE CONTENT HERE" in res["output"], "file_analyze 输出应含全文"
    assert ctx.attachment_evidence, "累积列表不应为空"
    assert "FILE CONTENT HERE" in ctx.attachment_evidence[0], "全文应进 attachment_evidence"
    print("✓ test_execute_tool_accumulates_attachment_evidence")


def test_execute_tool_then_plan_prompt_injects():
    """[开] 端到端：execute_tool 累积 → build_plan_prompt 下一轮注入全文。"""
    ctx = AgentContext(question=_q(attachments=["a.zip"]), e3_enabled=True)
    asyncio.run(execute_tool(_FakeReg(), ctx, {"tool": "file_analyze"}, "analyze"))
    prompt = build_plan_prompt(ctx, 0)
    assert "附件分析全文" in prompt, "端到端：累积证据必须进入 plan 提示"
    assert "FILE CONTENT HERE" in prompt
    print("✓ test_execute_tool_then_plan_prompt_injects")


# ── 新增：开关门控 + 信号标记 ─────────────────────────

def test_e3_gate_off_no_inject():
    """[关] e3_enabled=False（默认）→ 即使有 evidence 也不注入（保基线 KPI 不被改动）。"""
    ctx = AgentContext(
        question=_q(attachments=["a.zip"]),
        attachment_evidence=["【附件 a.zip】\nREAL FILE CONTENT"],
        e3_enabled=False,
    )
    prompt = build_plan_prompt(ctx, 0)
    assert "附件分析全文" not in prompt, "E3 关时即便有证据也不应注入（A/B 基线保护）"
    assert ctx.evidence_injected_into_prompt is False, "E3 关时不应置注入标记"
    print("✓ test_e3_gate_off_no_inject")


def test_prompts_sets_evidence_marker_on_inject():
    """[开] 注入时置 ctx.evidence_injected_into_prompt=True（供 error_struct 信号度量）。"""
    ctx = AgentContext(
        question=_q(attachments=["a.zip"]),
        attachment_evidence=["【附件 a.zip】\nREAL FILE CONTENT"],
        e3_enabled=True,
    )
    build_plan_prompt(ctx, 0)
    assert ctx.evidence_injected_into_prompt is True, "E3 开且注入时须置标记"
    print("✓ test_prompts_sets_evidence_marker_on_inject")


# ── 新增：subclassify C 桶三态真信号 ──────────────────

def test_subclassify_evidence_injected_false_to_c():
    """evidence_injected=False（有附件未进 prompt）→ 归 C（真·证据不进脑）。"""
    rec = {"error_struct": {"category": "wrong_direction", "evidence_injected": False}}
    assert subclassify(rec) == "C"
    print("✓ test_subclassify_evidence_injected_false_to_c")


def test_subclassify_evidence_injected_true_not_c():
    """evidence_injected=True（进了脑仍失败）→ 不归 C，按其他子类（wrong_direction→B）。"""
    rec = {"error_struct": {"category": "wrong_direction", "evidence_injected": True}}
    assert subclassify(rec) == "B", "进了脑仍失败不应归 C"
    print("✓ test_subclassify_evidence_injected_true_not_c")


def test_subclassify_evidence_injected_true_ignores_tool_failure_proxy():
    """evidence_injected=True 即便 cat=tool_failure 也不归 C（真信号优先于代理）。"""
    rec = {"error_struct": {"category": "tool_failure", "evidence_injected": True}}
    assert subclassify(rec) != "C", "进了脑的 tool_failure 不应被代理误归 C"
    print("✓ test_subclassify_evidence_injected_true_ignores_tool_failure_proxy")


def test_subclassify_evidence_injected_none_not_c():
    """evidence_injected=None（无附件）→ 不归 C，按其他子类。"""
    rec = {"error_struct": {"category": "wrong_direction", "evidence_injected": None}}
    assert subclassify(rec) == "B"
    print("✓ test_subclassify_evidence_injected_none_not_c")


def test_subclassify_legacy_tool_failure_proxy():
    """历史数据缺 evidence_injected 字段 → 回退 tool_failure→C 代理（向后兼容）。"""
    rec = {"error_struct": {"category": "tool_failure"}}  # 无 evidence_injected 键
    assert subclassify(rec) == "C"
    print("✓ test_subclassify_legacy_tool_failure_proxy")


# ── 新增：goal_directive 透传证据信号 ──────────────────

def test_goal_directive_passes_evidence_injected():
    """goal_log error_struct 透传 evidence_injected 三态（main_agent output → 落盘链路）。"""
    d = tempfile.mkdtemp()
    gl = GoalLogger(log_dir=d)

    def _last():
        with open(gl.log_path, encoding="utf-8") as f:
            return json.loads(f.readlines()[-1])

    # True
    gl.log({"task_id": "t1", "question_type": "misc", "validated": False,
            "error": {"category": "wrong_direction", "detail": "x", "evidence_injected": True}})
    assert _last()["error_struct"]["evidence_injected"] is True
    # False
    gl.log({"task_id": "t2", "question_type": "misc", "validated": False,
            "error": {"category": "wrong_direction", "detail": "x", "evidence_injected": False}})
    assert _last()["error_struct"]["evidence_injected"] is False
    # None（无附件）
    gl.log({"task_id": "t3", "question_type": "crypto", "validated": False,
            "error": {"category": "stuck_loop", "detail": "x", "evidence_injected": None}})
    assert _last()["error_struct"]["evidence_injected"] is None
    print("✓ test_goal_directive_passes_evidence_injected")


if __name__ == "__main__":
    test_plan_prompt_injects_attachment_evidence()
    test_plan_prompt_no_evidence_section_without_analysis()
    asyncio.run(test_execute_tool_accumulates_attachment_evidence())
    asyncio.run(test_execute_tool_then_plan_prompt_injects())
    test_e3_gate_off_no_inject()
    test_prompts_sets_evidence_marker_on_inject()
    test_subclassify_evidence_injected_false_to_c()
    test_subclassify_evidence_injected_true_not_c()
    test_subclassify_evidence_injected_true_ignores_tool_failure_proxy()
    test_subclassify_evidence_injected_none_not_c()
    test_subclassify_legacy_tool_failure_proxy()
    test_goal_directive_passes_evidence_injected()
    print("=== main_agent E3 附件证据注入 + A/B 开关 + 信号度量 测试全部通过 ===")
