"""Goal 指令模块：/goal 顶层目标的运行时实现。

职责：
- 生成 Goal 系统提示词片段（注入 MainAgent._plan 的 system prompt）
- 解析 Agent 输出中的 self_reflection 字段
- 解析 Agent 输出中的 skill_require 字段并交给 SkillManager 处理
- 持久化所有反思日志到 data/results/（赛后复盘 + 扩充 skill 库素材）

设计原则：
- 不侵入 MainAgent 核心循环，通过 system prompt 注入 + 后置解析实现
- self_reflection / skill_require 是可选扩展字段，不影响原有契约
- Skill 加载走本地仓库，不发起外网请求（赛事环境无外网）
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Goal 系统提示词片段（注入 MainAgent._plan system prompt）────────

GOAL_SYSTEM_PROMPT = """
【顶层 Goal 指令】
你是 CTF 解题智能体。核心运行规则（每一轮思考都必须遵守）：

1. 任务完整性：每题走完「分析→规划→工具调用→执行→校验→反思」全流程。
   单题失败不阻塞整体任务，标记失败根因后进入下一题。

2. 自我反思闭环：每一轮操作后，必须在输出末尾追加结构化反思 JSON：
   self_reflection（what_i_did / success_or_failure_reason / ability_gap /
   strategy_adjust_suggestion）。

3. 动态 Skill 请求：能力缺口需要新技能/脚本/模板时，输出 skill_require
   （need_download / skill_name / skill_purpose / input_spec / output_spec /
   safety_risk / priority）。

4. 失败重试边界：达到 max_retries 后标记 failed_give_up_after_max_retry，
   记录反思与能力缺口后流转到下一题。

5. 已解跳过：攻克前先查 hasSolved 状态；解题中每 3 轮同步一次平台状态，
   避免对已被其他会话解出的题目继续消耗资源。

6. 实战优先/快速止损：简单可解的题先拿分（模板直出/静态 strings 直取
   flag）；卡题 2 轮无进展立即止损换题；静态能解的题不深挖动态。

【确定性门禁（系统强制——违反即拦截，无需自行遵守）】
- 第一步必须调工具（Crypto 读附件提参数/Misc file_analyze/Web 访问靶机/
  Reverse strings 静态分析）——纯 reason 第一步会被系统拦截。
- 禁止猜测 flag——提交前系统校验 flag 来源（工具输出/附件/确定性计算）。
- script 动作必须含完整可运行 code（python: 前缀）——空/伪代码被系统拒绝。
- 连续 2 步 action=reason 且无工具输出——系统强制切换 script。
- 哈希/编码/参数提取——必须 script 计算，禁止纯推理猜明文。

【题型流程】见对应 skill/模板（PWN 流程/Java 反序列化/web 源码审计/格攻击/
misc 编码隐写/文本附件直读）——按需加载，不占顶层指令。
"""


# ── 数据结构 ─────────────────────────────────────────────────────

@dataclass
class SelfReflection:
    """Agent 单轮反思结构体。"""

    what_i_did: str = ""
    success_or_failure_reason: str = ""
    ability_gap: list = field(default_factory=list)
    strategy_adjust_suggestion: list = field(default_factory=list)
    reasoning_jump: bool = False  # 是否检测到推理跳步


@dataclass
class SkillRequirement:
    """Agent 请求新 Skill 的结构体。"""

    need_download: bool = True
    skill_name: str = ""
    skill_purpose: str = ""
    input_spec: str = ""
    output_spec: str = ""
    safety_risk: str = "low"
    priority: str = "mid"


@dataclass
class GoalLogEntry:
    """单题 Goal 日志条目（持久化到 data/results/）。"""

    task_id: str = ""
    question_type: str = ""
    timestamp: str = ""
    flag: Optional[str] = None
    validated: bool = False
    retries: int = 0
    self_reflection: Optional[dict] = None
    skill_require: Optional[dict] = None
    error: Optional[str] = None
    # 结构化错误（2026-08-22 赛后重锐评 M1.3）：error 从字符串升级为
    # {"category", "detail", "class4"}，回归报表按 class4 聚合 4 类失败分布。
    error_struct: Optional[dict] = None


# 4 类失败映射（2026-08-22 赛后重锐评 M1.3）：error.category → 失败大类
FAILURE_CLASS4 = {
    "wallclock_timeout": "超时",
    "tool_failure": "工具调用错",
    "wrong_direction": "决策错",
    "stuck_loop": "决策错",
    "extract_fail": "提取错",
    "hallucination": "提取错",
    "budget_exceeded": "other",
}


def classify_failure(category: Optional[str]) -> str:
    """error.category → 4 类失败大类（未知归 other）。"""
    return FAILURE_CLASS4.get(category or "", "other")


# ── 解析 ─────────────────────────────────────────────────────────

def parse_self_reflection(output: dict) -> Optional[SelfReflection]:
    """从 AgentOutput 中解析 self_reflection 字段。

    Args:
        output: MainAgent.solve() 返回的 AgentOutput dict

    Returns:
        SelfReflection 或 None（Agent 未输出反思时）
    """
    raw = output.get("self_reflection")
    if not raw or not isinstance(raw, dict):
        return None
    return SelfReflection(
        what_i_did=str(raw.get("what_i_did", "")),
        success_or_failure_reason=str(raw.get("success_or_failure_reason", "")),
        ability_gap=list(raw.get("ability_gap", [])),
        strategy_adjust_suggestion=list(raw.get("strategy_adjust_suggestion", [])),
        reasoning_jump=bool(raw.get("reasoning_jump", False)),
    )


def parse_skill_require(output: dict) -> Optional[SkillRequirement]:
    """从 AgentOutput 中解析 skill_require 字段。

    Args:
        output: MainAgent.solve() 返回的 AgentOutput dict

    Returns:
        SkillRequirement 或 None（Agent 未请求 Skill 时）
    """
    raw = output.get("skill_require")
    if not raw or not isinstance(raw, dict):
        return None
    return SkillRequirement(
        need_download=bool(raw.get("need_download", True)),
        skill_name=str(raw.get("skill_name", "")),
        skill_purpose=str(raw.get("skill_purpose", "")),
        input_spec=str(raw.get("input_spec", "")),
        output_spec=str(raw.get("output_spec", "")),
        safety_risk=str(raw.get("safety_risk", "low")),
        priority=str(raw.get("priority", "mid")),
    )


# ── 日志持久化 ───────────────────────────────────────────────────

class GoalLogger:
    """Goal 反思日志持久化（写入 data/results/goal_log.jsonl）。

    每道题一个 GoalLogEntry，追加写入。赛后可统计高频 ability_gap，
    直接对接训练评估报表，批量扩充 skill 库。
    """

    def __init__(self, log_dir: str = "data/results"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.log_path = os.path.join(log_dir, "goal_log.jsonl")

    def log(self, output: dict) -> GoalLogEntry:
        """从 AgentOutput 提取 Goal 字段并追加日志。

        Args:
            output: MainAgent.solve() 返回的 AgentOutput dict

        Returns:
            生成的 GoalLogEntry
        """
        reflection = parse_self_reflection(output)
        skill_req = parse_skill_require(output)
        raw_err = output.get("error")
        error_struct = None
        if isinstance(raw_err, dict):
            _cat = raw_err.get("category")
            error_struct = {
                "category": _cat,
                "detail": str(raw_err.get("detail") or ""),
                "class4": classify_failure(_cat),
                # E3（2026-08-25 桶C攻坚）：透传三态证据信号，使 C 桶成为"证据不进脑"真实度量
                "evidence_injected": raw_err.get("evidence_injected"),
            }

        entry = GoalLogEntry(
            task_id=str(output.get("task_id", "")),
            question_type=str(output.get("question_type", "")),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            flag=output.get("flag"),
            validated=bool(output.get("validated", False)),
            retries=int(output.get("retries", 0)),
            self_reflection=asdict(reflection) if reflection else None,
            skill_require=asdict(skill_req) if skill_req else None,
            error=str(raw_err) if raw_err else None,
            error_struct=error_struct,
        )

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
            logger.info(
                "[Goal] 日志已记录: task=%s flag=%s gaps=%d",
                entry.task_id,
                "✅" if entry.flag else "❌",
                len(entry.self_reflection.get("ability_gap", []))
                if entry.self_reflection
                else 0,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("[Goal] 日志写入失败: %s", exc)

        return entry

    def load_all(self) -> list[dict]:
        """读取全部历史日志（赛后复盘用）。"""
        if not os.path.exists(self.log_path):
            return []
        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries

    def ability_gap_summary(self) -> dict[str, int]:
        """统计全部历史日志中的高频能力缺口（赛后扩充 skill 库参考）。"""
        counter: dict[str, int] = {}
        for entry in self.load_all():
            ref = entry.get("self_reflection") or {}
            for gap in ref.get("ability_gap", []):
                counter[gap] = counter.get(gap, 0) + 1
        return dict(sorted(counter.items(), key=lambda x: -x[1]))
