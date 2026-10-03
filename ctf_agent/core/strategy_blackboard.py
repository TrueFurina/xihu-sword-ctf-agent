"""strategy_blackboard：题内跨步「已试策略黑板」（P2 记忆层——2026-10-03）。

背景（P1 两轮 held-out 真跑诊断，外部池 0/10）：轨迹显示 agent 要么 ~8 步 recon
空转即弃，要么烧完预算 0 产出——共同根因之一是 plan prompt 只含「近 3 步摘要」
（prompts.build_plan_prompt 的 steps[-3:] 窗口），更早试过什么被挤出窗口后，
规划器反复重提已失败的同款策略，预算烧在重复路径上。

本模块把每步「策略签名 + 结局」结构化沉淀为题内黑板，经 build_plan_prompt
注入规划提示词（「已试策略黑板」块），让规划器显式避开已失败/无产出路径。
纯规则、零额外 LLM 调用、不改任何控制流与反思决策规则——行为改变仅通过
prompt 注入达成（与 E6 few-shot / E3 证据注入同一模式）。

边界：黑板是**题内**记忆（每次 solve 新建）；跨题/跨会话的 flag 缓存黑板是
data/results/blackboard.json（presolve），两者互不相干。
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class StrategyEntry:
    """同一策略签名的累计记录。"""

    signature: str
    count: int = 0                      # 试过几次
    failures: int = 0                   # 工具报错（error_category 非空）次数
    empties: int = 0                    # 无产出（observation 为空）次数
    last_error: Optional[str] = None    # 最近一次错误分类
    last_observation: str = ""          # 最近一次观察摘要


@dataclass
class StrategyBlackboard:
    """题内跨步策略黑板：record 每一步，summary 渲染为 plan prompt 注入块。

    A/B 安全：AgentContext.blackboard 默认 None → record 无操作、prompt 不变；
    仅 solve() 显式创建后生效。
    """

    max_entries: int = 32               # 签名条目上限（防 prompt 膨胀，LRU 淘汰最旧）
    window: int = 5                     # repeat_ratio 的滑动窗口
    _entries: "OrderedDict[str, StrategyEntry]" = field(
        default_factory=OrderedDict, repr=False
    )
    _recent: list = field(default_factory=list, repr=False)  # 最近 window 个签名

    # ── 签名：stage | action | tool ──
    @staticmethod
    def signature(step: Any) -> str:
        stage = str(getattr(step, "stage", "") or "").strip() or "-"
        action = str(getattr(step, "action", "") or "").strip() or "-"
        tool = str(getattr(step, "tool_used", "") or "").strip() or "-"
        return f"{stage}|{action}|{tool}"

    # ── 结局分类：失败 / 无产出 / 有进展 ──
    @staticmethod
    def _outcome(step: Any) -> str:
        err = getattr(step, "error_category", None)
        if err is not None:
            return "failure"
        obs = str(getattr(step, "observation", "") or "").strip()
        if not obs:
            return "empty"
        return "progress"

    def record(self, step: Any) -> None:
        """沉淀一步（duck typing：任何有 stage/action/tool_used/error_category/
        observation 属性的对象均可，StepRecord 或测试桩都行）。永不抛异常。"""
        try:
            sig = self.signature(step)
            entry = self._entries.get(sig)
            if entry is None:
                entry = StrategyEntry(signature=sig)
                self._entries[sig] = entry
                # LRU 淘汰最旧签名（保 max_entries 上限）
                while len(self._entries) > self.max_entries:
                    self._entries.popitem(last=False)
            outcome = self._outcome(step)
            entry.count += 1
            if outcome == "failure":
                entry.failures += 1
                entry.last_error = str(getattr(step, "error_category", "") or "")
            elif outcome == "empty":
                entry.empties += 1
            entry.last_observation = str(getattr(step, "observation", "") or "")[:200]
            self._recent.append(sig)
            if len(self._recent) > self.window:
                self._recent.pop(0)
        except Exception:  # noqa: BLE001 - 黑板故障不得影响求解主流程
            pass

    def is_repeat_failure(self, step: Any) -> bool:
        """该步签名此前已试过且失败过（供监督/测试用，主链路暂不接线）。"""
        entry = self._entries.get(self.signature(step))
        return bool(entry and entry.failures > 0)

    def repeat_ratio(self, window: Optional[int] = None) -> Optional[float]:
        """近 window 步中「重复已试签名」的比例；样本不足返回 None。

        这就是 P1 诊断中「recon:command ×2-3」空转模式的量化指标。
        """
        w = self.window if window is None else window
        if len(self._recent) < w or w <= 0:
            return None
        repeats = sum(1 for i, sig in enumerate(self._recent) if sig in self._recent[:i])
        return repeats / w

    def metrics(self) -> dict:
        """只读指标快照（看板/日志/测试用）。"""
        rr = self.repeat_ratio()
        return {
            "entries": len(self._entries),
            "failures": sum(e.failures for e in self._entries.values()),
            "repeat_ratio": rr,
        }

    def summary(self, max_items: int = 10) -> str:
        """渲染为 plan prompt 注入块；黑板为空返回 ''（prompt 不变）。"""
        if not self._entries:
            return ""
        lines = [
            "【已试策略黑板】以下策略签名已执行过，结局标注在后。"
            "对「失败/无产出」的策略请勿原样重复——要么换新方向，要么给出与之前"
            "实质不同的具体改动:"
        ]
        for sig, e in list(self._entries.items())[-max_items:]:
            tag_parts = []
            if e.failures:
                tag_parts.append(f"失败×{e.failures}")
            if e.empties:
                tag_parts.append(f"无产出×{e.empties}")
            if not tag_parts:
                tag_parts.append(f"已执行×{e.count}")
            line = f"- {sig}: {' / '.join(tag_parts)}"
            if e.last_error:
                line += f" | 最近错误: {e.last_error}"
            if e.last_observation:
                line += f" | 最近观察: {e.last_observation[:80]}"
            lines.append(line)
        rr = self.repeat_ratio()
        if rr is not None and rr >= 0.4:
            lines.append(f"⚠️ 近 {self.window} 步重复率 {rr:.0%}——正在原地打转，必须换策略")
        return "\n".join(lines)
