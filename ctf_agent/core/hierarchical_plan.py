"""hierarchical_plan：卡壳时的「分层作战视图」（P2 第三刀——分层规划，2026-10-03）。

背景（P1 两轮 held-out 真跑诊断，外部池 0/10）：flat Plan-Act-Observe 循环里，
每步 plan 只看「上一步 + 近 3 步摘要」，没有全局路径视图 → agent 在
「读附件→看输出→再读附件」间空转，预算烧完 0 产出。

本模块把「题型标准流程（候选路径，TemplateBank.standard_flow）」与
「已试失败签名（strategy_blackboard.failed_signatures）」桥接成一份分层视图：
顶层=题型，中层=有序候选路径，动态=已试失败项 + 决策规则。注入 plan prompt
后，规划器每步都能看到「全局路径图 + 当前卡点」，显式跳过已试失败路径、
优先走未试步骤。

设计约束（与黑板/E6/E3 同一 A/B 模式）：
- 纯规则、零额外 LLM 调用（只把两份已有信息摆一起 + 一句决策规则）；
- 仅当黑板启用**且**已有 ≥1 条失败/无产出签名时才返回非空——即只在「卡壳
  换路」这个真正需要分层视图的时点注入，首步/顺利推进时 prompt 不变；
- 不改任何反思决策规则，行为改变仅经 prompt 注入达成。
"""

from __future__ import annotations

from typing import Any, Optional


def build_hierarchical_view(ctx: Any, max_flow: int = 6, max_tried: int = 8) -> str:
    """生成「分层作战视图」提示块；非卡壳时返回 ''（prompt 不变）。

    Args:
        ctx: AgentContext（需 question.category / blackboard 两个属性）。
        max_flow: 候选路径最多列几条（防 prompt 膨胀）。
        max_tried: 已试失败签名最多列几条。
    """
    bb = getattr(ctx, "blackboard", None)
    if bb is None:
        return ""
    try:
        tried = bb.failed_signatures()
    except Exception:  # noqa: BLE001 - 黑板故障不影响主流程
        tried = []
    if not tried:
        return ""  # 尚无失败记录 = 未卡壳，无需换路视图

    category = str(getattr(getattr(ctx, "question", None), "category", "") or "").lower()
    flows: list = []
    try:
        from agents.templates import TemplateBank
        flows = TemplateBank().standard_flow(category)
    except Exception:  # noqa: BLE001 - 模板库故障不阻塞视图
        flows = []

    lines = ["【分层作战视图·卡壳换路】"]
    lines.append("你已陷入重复/失败路径。下面是本题型标准路径的重新编排，"
                "请跳过标为「已试」的路径，优先走尚未尝试的步骤：")
    if flows:
        for i, f in enumerate(flows[:max_flow], 1):
            # 取每条的首句（到第一个句号）作标题，避免整段重列挤占 prompt
            head = f.split("。", 1)[0][:60].strip()
            lines.append(f"  {i}. {head}")
    lines.append("已试且失败/无产出的策略签名（跳过这些，勿原样重复）：")
    for t in tried[-max_tried:]:
        lines.append(f"  × {t}")
    lines.append(
        "决策规则：优先选上述标准路径里你尚未真正尝试的步骤；"
        "若要重试某条，必须给出与之前实质不同的具体做法（换工具/换参数/换算法），"
        "否则就是原地空转。"
    )
    return "\n".join(lines)
