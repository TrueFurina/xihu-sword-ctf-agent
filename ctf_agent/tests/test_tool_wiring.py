"""工具接线回归测试（2026-10-20）。

背景：三个新适配器（rea_probe / wasm_probe / pcap_probe）注册进 registry 后，
主链上其实**不可达**，两个独立缺口：

1. `core/action_executor.execute_tool` 只白名单透传 http_request 的 6 个字段，
   其余 plan 字段全丢 → `lane=decompile_batch` / `selector` / `flow` 永远到不了
   适配器，走默认值。
2. `core/prompts.build_plan_prompt` 从不列工具名 → 模型不知道这些工具存在。

本文件锁住修复后的三条不变量：
  · 声明过的参数必须直达适配器；
  · 未声明的参数绝不能直达（防 LLM 任意字段污染签名）；
  · 显式 path 必须直达（原实现在「有 path」时反而丢 path）。

铁律：测试全绿不等于测试有效 — 每条都配变异验证（见文件末尾注释）。
"""

from __future__ import annotations

import asyncio
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.action_executor import execute_tool  # noqa: E402
from tools.base import ToolAdapter, ToolOutput  # noqa: E402
from tools.registry import ToolRegistry  # noqa: E402


class _Ctx:
    """最小 ctx：只带 prompts / action_executor 真正读到的属性。

    刻意不导入 core.main_agent.AgentContext——那会把 provider 依赖拖进单测。
    """

    def __init__(self, question) -> None:
        self.question = question
        self.steps: list = []
        self.hint_text = None
        self.correction = None
        self.advisor_hint = None
        self.blackboard = None
        self.knowledge_hits = None
        self.registry = None
        self.few_shot = False
        self.e3_enabled = False
        self.attachment_evidence: list = []
        self._attachments_seen: set = set()
        self._attachment_analyzed = False


class _RecordingAdapter(ToolAdapter):
    """只记录收到的 params，不干活。"""

    name = "recorder"
    categories = ["reverse"]
    param_spec = {"lane": "通道", "selector": "定位"}

    def __init__(self) -> None:
        super().__init__(sandbox=None)
        self.seen: dict | None = None

    async def run(self, params: dict) -> ToolOutput:
        self.seen = dict(params)
        return ToolOutput(text="ok", ok=True)


def _ctx(attachment: str = "") -> _Ctx:
    q = types.SimpleNamespace(
        title="t", category="reverse", description="d",
        attachments=[attachment] if attachment else [],
        flag_pattern=r"flag\{[^}]+\}",
    )
    return _Ctx(q)


def _run(registry, plan: dict, attachment: str = "") -> dict:
    ctx = _ctx(attachment)
    asyncio.run(execute_tool(registry, ctx, plan, "detail"))
    return registry.get("recorder").seen or {}


# ── 不变量 1：声明过的参数必须直达 ─────────────────────────


def test_declared_params_reach_adapter():
    reg = ToolRegistry()
    reg.register(_RecordingAdapter())
    seen = _run(reg, {"tool": "recorder", "lane": "decompile_batch",
                      "selector": "0x140001000"})
    assert seen.get("lane") == "decompile_batch", "lane 被丢弃 → decompile_batch 永远不可达"
    assert seen.get("selector") == "0x140001000"


def test_undeclared_params_do_not_leak():
    """未声明的键（比如模型随手写的猜测字段）不能进适配器。"""
    reg = ToolRegistry()
    reg.register(_RecordingAdapter())
    seen = _run(reg, {"tool": "recorder", "evil_key": "boom", "timeout": 5})
    assert "evil_key" not in seen
    assert "timeout" not in seen


def test_explicit_path_reaches_adapter():
    """显式 path 必须直达：原实现在「plan 有 path」时反而不注入 params['path']。"""
    reg = ToolRegistry()
    reg.register(_RecordingAdapter())
    seen = _run(reg, {"tool": "recorder", "path": r"C:\tmp\a.bin"})
    assert seen.get("path") == r"C:\tmp\a.bin"


def test_first_attachment_used_when_path_absent():
    """没给 path 时仍按旧行为取首个附件（不破坏既有链路）。"""
    reg = ToolRegistry()
    reg.register(_RecordingAdapter())
    seen = _run(reg, {"tool": "recorder"}, attachment=r"C:\tmp\first.bin")
    assert seen.get("path") == r"C:\tmp\first.bin"


# ── 不变量 2：工具清单必须可见 ───────────────────────────


def test_inventory_filters_by_category_and_exposes_params():
    from tools.adapters.pcap_probe import PcapProbeAdapter
    from tools.adapters.rea_probe import ReaProbeAdapter

    reg = ToolRegistry()
    reg.register(ReaProbeAdapter())
    reg.register(PcapProbeAdapter())

    rev = {it["name"]: it for it in reg.inventory("reverse")}
    assert "rea_probe" in rev
    assert "pcap_probe" not in rev, "pcap_probe 不该出现在 reverse 题型里"
    assert "lane" in rev["rea_probe"]["params"]

    misc = {it["name"]: it for it in reg.inventory("misc")}
    assert {"rea_probe", "pcap_probe"} <= set(misc)
    assert "flow" in misc["pcap_probe"]["params"]


def test_plan_prompt_renders_inventory():
    from core.prompts import build_plan_prompt
    from tools.adapters.rea_probe import ReaProbeAdapter

    reg = ToolRegistry()
    reg.register(ReaProbeAdapter())
    ctx = _ctx()
    ctx.registry = reg
    prompt = build_plan_prompt(ctx, 0)
    assert "【可用工具】" in prompt
    assert "rea_probe" in prompt
    # 光有名字没用：必须告诉模型能传什么
    assert "decompile_batch" in prompt


def test_plan_prompt_unchanged_without_registry():
    """拿不到 registry 时不得凭空多出清单块（防污染既有 A/B 基线）。"""
    from core.prompts import build_plan_prompt

    ctx = _ctx()
    assert getattr(ctx, "registry", None) is None
    assert "【可用工具】" not in build_plan_prompt(ctx, 0)


# ── 变异验证记录（2026-10-20 实跑）──────────────────────
# M1 删掉 execute_tool 里的 param_spec 转发循环
#    → test_declared_params_reach_adapter FAIL（其余仍绿）
# M2 把转发循环的 `plan.get(_k)` 改成 `plan.get("path")`
#    → test_declared_params_reach_adapter FAIL
# M3 还原「只有 plan 无 path 才注入」的旧逻辑
#    → test_explicit_path_reaches_adapter FAIL，test_first_attachment... 仍 PASS
#       （正好证明两条测试各自守着不同的分支，不是重复断言）


def test_registry_without_get_method_does_not_break_chain():
    """只实现 run 的 registry 必须照样能用。

    真回归：首版用 `registry.get(tool_name)` 查 param_spec，遇到
    test_main_agent_e3_evidence 里只实现 `run` 的 _FakeReg 直接
    AttributeError，把整条工具执行链打断（全量测试暴露，2 条 FAILED）。
    """
    class _FakeReg:
        def __init__(self):
            self.seen = None

        async def run(self, name, params):
            self.seen = dict(params)
            return ToolOutput(text="ok", ok=True)

    reg = _FakeReg()
    asyncio.run(execute_tool(reg, _ctx(), {"tool": "anything", "lane": "pe"}, "d"))

    assert reg.seen is not None
