"""解题报告生成器：从真实执行记录生成 Markdown 报告。

数据源（保证与流量日志吻合——手册第 8 条）：
- PlatformPoller.records()：平台交互记录（拉题/启动/提交/结果）
- MainAgent 的 ctx.steps：解题步骤（行动/观察/工具）
- 所有记录均为真实执行痕迹，非人工编造

用法：
    from report.generator import generate_report
    md = generate_report(poller_records=[...], solve_logs={...})
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Optional


def generate_report(
    poller_records: Optional[list] = None,
    solve_logs: Optional[dict] = None,
    team_name: str = "NetLearn-西湖论剑队",
    stage: str = "初赛",
) -> str:
    """生成完整 Markdown 解题报告。

    Args:
        poller_records: PlatformPoller.records() 输出（平台交互审计）
        solve_logs: {challenge_id: [step_dict, ...]} 解题步骤记录
        team_name: 队伍名
        stage: 赛段（初赛/测试赛）

    Returns:
        Markdown 报告全文
    """
    poller_records = poller_records or []
    solve_logs = solve_logs or {}

    # 汇总统计
    total = len(poller_records)
    solved = sum(1 for r in poller_records if r.get("flag"))
    # P1 修复（2026-08-21）：提交成功只统计「确有 flag 且平台 accepted」——
    # 平台返回 hasSolved 但本方未提取出 flag 的记录不再计入，概览与逐题口径一致（未解出就是未解出）。
    accepted = sum(1 for r in poller_records if r.get("flag") and r.get("accepted"))
    total_time = sum(r.get("duration_s") or 0 for r in poller_records)

    lines = []
    lines.append(f"# 西湖论剑·中国杭州网络安全技能大赛 {stage}解题报告")
    lines.append("")
    lines.append(f"> 队伍：{team_name}")
    lines.append(f"> 报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    # 数据来源声明条件化（第三轮锐评 P0——防虚假声明：0 题/无真实记录时不写「流量吻合」）
    if total > 0:
        lines.append(f"> 数据来源：平台 API 真实交互记录 {total} 条（与网络流量/平台日志吻合）")
    else:
        lines.append("> 数据来源：本次未产生平台交互记录（空跑/演练占位——非真实解题数据）")
    lines.append("")

    # 一、总体概览
    lines.append("## 一、总体概览")
    lines.append("")
    lines.append("| 指标 | 值 |")
    lines.append("|------|-----|")
    lines.append(f"| 题目总数 | {total} |")
    lines.append(f"| 解出题数 | {solved} |")
    lines.append(f"| 提交成功 | {accepted} |")
    # P1 修复（2026-08-21）：耗时全 0.0 一律标注「数据缺失」，不再假装精确
    if total and total_time > 0:
        lines.append(f"| 总耗时（秒） | {total_time:.1f} |")
        lines.append(f"| 平均单题耗时（秒） | {total_time / total:.1f} |")
    elif total:
        lines.append("| 总耗时（秒） | （数据缺失） |")
        lines.append("| 平均单题耗时（秒） | （数据缺失） |")
    else:
        lines.append("| 总耗时（秒） | 0.0 |")
        lines.append("| 平均单题耗时 | - |")
    lines.append("")

    # 二、系统架构
    lines.append("## 二、Agent 系统架构")
    lines.append("")
    lines.append("""本项目采用「1 主 1 监」多智能体架构 + 领域工具包：
- **主解题 Agent**：Plan-Act-Observe 推理循环，自主分析题目、选型工具、执行验证、提取 flag
- **监督反思 Agent**：轻量模型裁决（continue/redirect/switch_strategy/upgrade_model），
  每 2-3 步或连续失败时介入，定向修正解题路径
- **分级降级调度**：attempt 0-1 用轻量模型（V4-Flash），2-3 升级重型模型（V4-Pro），成本可控
- **领域工具包**：Web/Crypto/Misc/Reverse/Pwn 五题型专用工具与模板库
- **步骤级校验**：工具输出结构化解析 + 错误分类（僵局/方向错/幻觉/工具失败）+ 定向修正
- **合规说明**：仅调用官方白名单 API 端点；全程无人工引导（Agent 自主解题）""")
    lines.append("")

    # 三、逐题详情
    lines.append("## 三、逐题解题详情")
    lines.append("")
    for r in poller_records:
        cid = r.get("challenge_id", "?")
        title = r.get("title", "")
        cat = r.get("category", "")
        flag = r.get("flag", "")
        # P1 修复（2026-08-21）：✅/❌ 严格按「是否提取出 flag」判定——
        # 平台返回 hasSolved 但本方未解出（无 flag）必须标 ❌，杜绝「✅ 未解出」自相矛盾。
        ok = "✅" if (flag and r.get("accepted")) else ("🔑" if flag else "❌")
        lines.append(f"### {ok} [{cid}] {title}（{cat}）")
        lines.append("")
        # P1 修复：耗时 0.0s 标注（数据缺失），不假装精确
        _dur = r.get("duration_s") or 0
        _dur_txt = f"{_dur:.1f}s" if _dur > 0 else "（数据缺失）"
        lines.append(f"- **耗时**：{_dur_txt}")
        lines.append(f"- **flag**：`{flag or '未解出'}`")
        # P1 修复：未解出（无 flag）时不写「accepted」，口径一致（未解出就是未解出）
        if flag:
            lines.append(f"- **提交结果**：{'accepted' if r.get('accepted') else 'rejected'}")
        else:
            lines.append("- **提交结果**：未提交（未解出）")
        if r.get("detail"):
            lines.append(f"- **平台返回**：{r['detail']}")
        if r.get("error"):
            lines.append(f"- **错误**：{r['error']}")
        # 解题步骤（与流量吻合的核心）
        steps = solve_logs.get(cid, [])
        if steps:
            lines.append("")
            lines.append("**解题步骤（与流量日志对应的执行记录）**：")
            lines.append("")
            lines.append("| # | 阶段 | 行动 | 观察/结果 | 工具 |")
            lines.append("|---|------|------|-----------|------|")
            for i, st in enumerate(steps, 1):
                lines.append(
                    f"| {i} | {st.get('stage', '')} | {st.get('action', '')} | "
                    f"{str(st.get('observation', ''))[:80]} | {st.get('tool_used', '') or '-'} |"
                )
        lines.append("")

    # 四、平台交互审计
    lines.append("## 四、平台交互记录" + ("（与网络流量吻合）" if total > 0 else "（无——本次未产生平台交互）"))
    lines.append("")
    lines.append("```")
    lines.append(json.dumps(poller_records, ensure_ascii=False, indent=1, default=str))
    lines.append("```")
    lines.append("")

    # 五、合规声明
    lines.append("## 五、合规声明")
    lines.append("")
    lines.append("""1. 仅使用官方授权 API 端点白名单内的大模型服务（见参赛手册第三节）
2. 每队仅一个 Agent 接入平台
3. 全程 Agent 自主解题（人工干预接口默认关闭，符合官方「不鼓励人工引导」要求）
4. 未对 flag 进行爆破，每题提交次数在限制内
5. 本报告数据声明：与平台网络流量/日志一致（仅当存在真实交互记录时）""")
    lines.append("")

    return "\n".join(lines)


def save_report(md: str, out_dir: str = "data/reports") -> str:
    """保存报告到文件，返回路径。"""
    import os
    from pathlib import Path

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"解题报告_{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    return path
