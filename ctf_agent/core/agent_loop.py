"""G2 · planner → executor → reflect 闭环骨架（LLM 真推理闭环）。

移植自 NYU EnIGMA / D-CIPHER（planner→executor→auto-prompter 闭环）
与 CAI（multi-agent handoffs），见 `2027-prep/差异分析-SOTA对比-20260928.md` 第 G2 项。

设计约束（与项目铁律一致，逐条对应差异分析文档）：
- **不污染「确定性优先」**：本闭环只应在 presolve 未解出后启用（由上层 supervisor
  决策），绝不能绕过 presolve 直接上 LLM。本模块不主动调用任何 presolve，也不读取
  任何 KPI/账本——它只是"活环境交互 + 失败重规划"的纯能力层。
- **LLM 以可注入 callable 形式存在**：`llm: Callable[[str], str]`。默认 `None` 时
  任何需要 LLM 的入口都显式抛 `NotImplementedError`（诚实声明"未接 LLM"），
  绝不在代码里硬编码 / 伪造任何 flag 或解法。生产环境由轨道 B 接入真 LLM。
- **与活环境解耦**：executor 通过 `Session`（G1）执行命令；Session 的 exec 后端
  在 Windows/Linux 通用，轨道 B 接 Docker 只需替换 `_exec`，本层接口不变。
- **不烧 token**：本模块零网络调用；单测全部使用 mock llm + 真实/ mock Session。
- **失败重规划**：reflect 三态（SUCCESS / FAIL_REPLAN / STUCK），FAIL_REPLAN 时把
  反馈喂回 planner 做下一轮分解（D-CIPHER auto-prompter 同类机制）。

这是把本仓从"LLM 贡献 0/14"推向"有贡献"的核心杠杆，但**接活环境验证必须等
轨道 B（Linux/Docker）**——Windows 上只做抽象与单测。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .session import Session, CommandRecord


# ── 数据结构 ────────────────────────────────────────────────
class SubtaskKind(str, Enum):
    COMMAND = "command"        # 直接执行 shell 命令（经 Session）
    LLM_REASON = "llm_reason"  # 交由注入的 LLM 做一步推理（不执行命令）
    SUBGOAL = "subgoal"        # 声明性子目标（仅用于规划，不参与执行统计）


@dataclass
class Subtask:
    """一个结构化子任务（planner 的分解产物）。"""

    kind: SubtaskKind
    payload: str                 # command 字符串，或 llm_reason 的提示词
    expect: str = ""            # 期望信号（如 flag 模式 / 关键词），供 reflect 参考
    id: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind.value, "payload": self.payload,
                "expect": self.expect, "id": self.id}


@dataclass
class Plan:
    """planner 产出的一份分解计划。"""

    subtasks: list[Subtask] = field(default_factory=list)
    raw: str = ""               # LLM 原始输出（审计留痕，永不丢弃）

    def non_subgoal(self) -> list[Subtask]:
        return [s for s in self.subtasks if s.kind != SubtaskKind.SUBGOAL]


@dataclass
class StepResult:
    """executor 执行单条 subtask 的结果。"""

    subtask: Subtask
    record: Optional[CommandRecord]
    observation: str            # 给 reflect 的精简观察（截断后的输出）
    ok: bool


class Verdict(str, Enum):
    SUCCESS = "SUCCESS"         # 已解出（flag 命中）
    FAIL_REPLAN = "FAIL_REPLAN" # 未解出但可重规划
    STUCK = "STUCK"             # 卡死，停止


@dataclass
class Reflection:
    verdict: Verdict
    feedback: str = ""          # 重规划提示（FAIL_REPLAN 时非空）
    reason: str = ""


@dataclass
class LoopOutcome:
    verdict: Verdict
    rounds: int
    session: Session
    reflection: Reflection
    plans: list[Plan] = field(default_factory=list)


# ── Planner ─────────────────────────────────────────────────
class PlannerAgent:
    """把挑战分解为结构化 subtask 列表。

    LLM 以可注入 callable 形式存在：``llm(prompt: str) -> str``。
    默认 ``None`` 时 ``plan()`` 显式抛 ``NotImplementedError``——诚实声明
    未接 LLM，绝不内置任何硬编码解法。
    """

    def __init__(self, llm: Optional[Callable[[str], str]] = None) -> None:
        self.llm = llm
        # 调用计数，便于单测验证"重规划时 planner 被再次调用"
        self.call_count = 0

    def plan(self, challenge: str, session: Session,
             replan_hint: str = "") -> Plan:
        self.call_count += 1
        prompt = self._build_prompt(challenge, session, replan_hint)
        if self.llm is None:
            raise NotImplementedError(
                "PlannerAgent 需要注入 LLM 后端（轨道 B 接入真模型）；"
                "当前为脚手架，单测请注入 mock llm"
            )
        raw = self.llm(prompt)
        return self._parse(raw)

    def _build_prompt(self, challenge: str, session: Session,
                      replan_hint: str) -> str:
        ctx = session.transcript() if session else "(no session)"
        hint = f"\n# 上一轮失败反馈（请据此重规划）:\n{replan_hint}" if replan_hint else ""
        return (
            "你是 CTF 解题规划器。把下列挑战分解为可执行的 subtask 列表。\n"
            f"# 挑战描述:\n{challenge}\n"
            f"# 已执行会话上下文:\n{ctx}{hint}\n"
            "输出格式：每行一个 subtask，前缀 `command: ` 或 `reason: `。"
        )

    @staticmethod
    def _parse(raw: str) -> Plan:
        """解析 LLM 输出为 Plan（支持 `command:` / `reason:` 前缀行）。

        纯函数，可独立单测（即便无 LLM）。
        """
        subtasks: list[Subtask] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("command:"):
                subtasks.append(Subtask(SubtaskKind.COMMAND,
                                         line[len("command:"):].strip()))
            elif line.startswith("reason:"):
                subtasks.append(Subtask(SubtaskKind.LLM_REASON,
                                         line[len("reason:"):].strip()))
            # 其它行（解释性文字）忽略
        return Plan(subtasks=subtasks, raw=raw)


# ── Executor ────────────────────────────────────────────────
class ExecutorAgent:
    """执行 planner 产出的 subtask。

    - ``command`` 类经 ``Session.run`` 在活环境执行（G1 提供跨步记忆）。
    - ``llm_reason`` 类交由注入的 LLM 做一步推理（不执行命令）。
    - ``subgoal`` 类不执行，仅为规划语义。
    """

    def __init__(self, llm: Optional[Callable[[str], str]] = None) -> None:
        self.llm = llm

    def execute(self, subtask: Subtask, session: Session) -> StepResult:
        if subtask.kind == SubtaskKind.COMMAND:
            rec = session.run(subtask.payload)
            obs = (rec.stdout or "") + (rec.stderr or "")
            return StepResult(subtask, rec, obs[:2000], rec.returncode == 0)
        if subtask.kind == SubtaskKind.LLM_REASON:
            if self.llm is None:
                raise NotImplementedError(
                    "ExecutorAgent 的 llm_reason subtask 需要注入 LLM 后端"
                )
            out = self.llm(subtask.payload)
            return StepResult(subtask, None, out, True)
        # SUBGOAL：不执行
        return StepResult(subtask, None, "", True)


# ── Reflect ─────────────────────────────────────────────────
class ReflectAgent:
    """判定当前轮是否解出 / 需重规划 / 卡死。

    判定优先级（确定性优先）：
    1. 会话输出已命中 flag → SUCCESS（不看 LLM，避免伪造）。
    2. 若注入了 LLM，可叠加语义判定（可选，不强制）。
    3. 默认启发式：轮次用尽 → STUCK；否则 FAIL_REPLAN（带反馈）。
    """

    def __init__(self, llm: Optional[Callable[[str], str]] = None,
                 flag_pattern: str = r"flag\{.*?\}") -> None:
        self.llm = llm
        self.flag_pattern = flag_pattern

    def reflect(self, plan: Plan, session: Session,
                results: list[StepResult], round_no: int,
                max_rounds: int) -> Reflection:
        # 1) 确定性：flag 已在会话输出里出现
        if session and session.grep_output(self.flag_pattern):
            return Reflection(Verdict.SUCCESS, "",
                              "flag 已在会话输出中命中（确定性判定）")

        # 2) 可选 LLM 语义判定（注入时才用）
        if self.llm is not None:
            sem = self._semantic(session, results)
            if sem is not None:
                return sem

        # 3) 默认启发式
        if round_no >= max_rounds:
            return Reflection(Verdict.STUCK, "",
                              f"轮次用尽（{max_rounds}）仍未解出")
        feedback = self._feedback(plan, results)
        return Reflection(Verdict.FAIL_REPLAN, feedback,
                          "存在失败步骤，需基于反馈重规划")

    def _semantic(self, session: Optional[Session],
                  results: list[StepResult]) -> Optional[Reflection]:
        """可选：用注入的 LLM 做"是否已接近解出"的语义判定。

        返回 None 表示 LLM 未给出明确结论，回退到启发式。
        """
        ctx = session.transcript() if session else "(no session)"
        prompt = f"基于以下解题轨迹判断是否已解出或需重规划:\n{ctx}"
        try:
            out = (self.llm(prompt) or "").strip().upper()  # type: ignore[union-attr]
        except Exception:
            return None
        if "STUCK" in out:
            return Reflection(Verdict.STUCK, "", "LLM 判定卡死")
        if "SUCCESS" in out:
            return Reflection(Verdict.SUCCESS, "", "LLM 判定已解出")
        return None

    @staticmethod
    def _feedback(plan: Plan, results: list[StepResult]) -> str:
        failed = [r for r in results if not r.ok]
        lines = [f"上一轮 {len(results)} 步中 {len(failed)} 步失败。"]
        for r in failed[:5]:
            lines.append(f"- 失败: `{r.subtask.payload}` -> {r.observation[:300]}")
        return "\n".join(lines)


# ── Loop 编排 ───────────────────────────────────────────────
class AgentLoop:
    """串联 planner → executor → reflect，最多 max_rounds 轮。

    FAIL_REPLAN 时把 feedback 作为 replan_hint 喂回 planner（D-CIPHER
    auto-prompter 机制）。SUCCESS / STUCK 时终止。
    """

    def __init__(self, planner: PlannerAgent, executor: ExecutorAgent,
                 reflect: ReflectAgent, session: Session, challenge: str,
                 flag_pattern: str = r"flag\{.*?\}") -> None:
        self.planner = planner
        self.executor = executor
        self.reflect = reflect
        self.session = session
        self.challenge = challenge
        self.flag_pattern = flag_pattern

    def run(self, max_rounds: int = 5) -> LoopOutcome:
        replan_hint = ""
        plans: list[Plan] = []
        for rnd in range(1, max_rounds + 1):
            plan = self.planner.plan(self.challenge, self.session, replan_hint)
            plans.append(plan)
            results = [self.executor.execute(st, self.session)
                       for st in plan.non_subgoal()]
            refl = self.reflect.reflect(plan, self.session, results,
                                         rnd, max_rounds)
            if refl.verdict == Verdict.SUCCESS:
                return LoopOutcome(refl.verdict, rnd, self.session, refl, plans)
            if refl.verdict == Verdict.STUCK:
                return LoopOutcome(refl.verdict, rnd, self.session, refl, plans)
            # FAIL_REPLAN → 下一轮带反馈重规划
            replan_hint = refl.feedback
        return LoopOutcome(Verdict.STUCK, max_rounds, self.session,
                           Reflection(Verdict.STUCK, "", "轮次耗尽"),
                           plans)


__all__ = [
    "SubtaskKind", "Subtask", "Plan", "StepResult", "Verdict", "Reflection",
    "LoopOutcome", "PlannerAgent", "ExecutorAgent", "ReflectAgent", "AgentLoop",
]
