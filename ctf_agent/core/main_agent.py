"""主解题 Agent：通用推理内核（Plan-Act-Observe 循环）。

v2.0 架构核心：唯一的大脑。
- 分析题目 → 制定计划 → 调用工具/推理 → 观察结果 → 提炼 flag
- 每 2-3 步 / 连续失败 3 次 → 咨询监督反思 Agent 获得裁决
- 输出统一 JSON 契约 {flag, confidence, evidence, error{category,detail}, supervision, ...}

依赖注入设计：registry/sandbox/checker/supervisor 均可选注入；
未注入时退化为纯 LLM 推理（便于先跑通链路，后续接工具链）。
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from core.goal_directive import GOAL_SYSTEM_PROMPT, GoalLogger, parse_skill_require

logger = logging.getLogger(__name__)

# 阶段常量
STAGE_RECON = "recon"          # 信息收集
STAGE_EXPLOIT = "exploit"      # 漏洞利用/求解
STAGE_FLAG_EXTRACT = "flag_extract"  # flag 提取
STAGE_STUCK = "stuck"          # 僵局

# 监督裁决
VERDICT_CONTINUE = "continue"
VERDICT_REDIRECT = "redirect"
VERDICT_SWITCH = "switch_strategy"
VERDICT_UPGRADE = "upgrade_model"
VERDICT_GIVE_UP = "give_up"

# 错误分类（v2.0 步骤级校验）
ERR_STUCK_LOOP = "stuck_loop"
ERR_UNRESOLVED = "unresolved"  # 2026-08-28：未解出且无明确归因（非死循环）——区分真死循环
ERR_WRONG_DIRECTION = "wrong_direction"
ERR_HALLUCINATION = "hallucination"
ERR_TOOL_FAILURE = "tool_failure"
ERR_ENV_FAILURE = "env_failure"
# KNOWN_GAP 题集（从台账 REAL_SOLVES_LEDGER.md「可复现脚本待固化/缺运行时参数」条目自动派生）：
# 10732（PKCS#1 v1.5，缺 hint_enc/AES_KEY_ENC 运行时参数）、10735（logbool 流量包，pcap 攻击链+7z 未固化）
# —— 题面缺参解不出是题缺参（extract_fail），非方向错（wrong_direction），避免污染失败桶统计。
# 注意：anwang_crypto1（安网杯八进制+Vigenère）是 presolve 可解题（台账 offline_verified），
# 不属于 KNOWN_GAP——它曾经的 wrong_direction 是 presolve 路由未覆盖所致，正确修法是路由覆盖（83f2fa1），
# 而非归类为 KNOWN_GAP。
_KNOWN_GAP_IDS = {"10732", "10735"}
# 墙钟硬止损（2026-08-20 锐评 P0-2）：单题墙钟超限强制放弃，防单步极慢拖死并发池
ERR_WALLCLOCK_TIMEOUT = "wallclock_timeout"
# 提取错（2026-08-22 赛后重锐评 M1.3）：候选 flag 被提取校验拒绝（模板/幻觉/无工具证据）
ERR_EXTRACT_FAIL = "extract_fail"

# 墙钟硬止损默认阈值（秒）：可被 config.per_question_wallclock / env 覆盖
DEFAULT_PER_QUESTION_WALLCLOCK = 300


@dataclass
class StepRecord:
    """单步执行记录（供监督 Agent 评估，结构化而非原始日志）。"""

    stage: str = STAGE_RECON
    action: str = ""                  # 做了什么（简述）
    observation: str = ""             # 观察到什么（关键信息摘要）
    error_category: Optional[str] = None  # 错误分类（如有）
    tool_used: Optional[str] = None   # 使用的工具名（如有）
    duration_ms: int = 0


@dataclass
class SupervisionVerdict:
    """监督反思 Agent 的裁决。"""

    action: str = VERDICT_CONTINUE
    reason: str = ""
    suggestion: str = ""              # 明确的修正方向（非"再试一次"）


def _extract_confidence(ctx) -> Optional[float]:
    """从最近步骤的 LLM 输出中解析置信度（P1-1 盲区分析管道）。

    SOLVE_DISCIPLINE R7 要求每步分析末尾输出 `confidence: <0-100>`。
    倒序遍历 steps（最近优先），从 reason 步骤的 observation 提取；
    解析失败返回 None → 调用方回退硬编码（解出 0.9 / 未解出 0.0），
    保证模型不配合时契约不破坏（confidence 只是自评记录，不参与判定）。
    """
    for s in reversed(ctx.steps or []):
        if not s.observation:
            continue
        m = re.search(r"confidence\s*[:=]\s*(\d{1,3})(?:\.\d+)?", s.observation)
        if m:
            try:
                v = float(m.group(1))
                return max(0.0, min(1.0, v / 100.0))
            except ValueError:
                continue
    return None


@dataclass
class AgentContext:
    """解题上下文：步骤历史 + 候选 flag + 僵局计数。"""

    question: Any = None
    steps: list = field(default_factory=list)
    candidate_flag: Optional[str] = None
    stuck_count: int = 0
    strategy_switches: int = 0
    model_upgrades: int = 0
    hint_text: Optional[str] = None
    correction: Optional[dict] = None   # 结构化修正指令（v2.0 错误归因）
    advisor_hint: Optional[str] = None  # 监督建议累积（抄 NUS Advisor：定向提示注入）
    _attachment_analyzed: bool = False  # 附件是否已被工具读取（防止空想）
    _attachments_seen: set = field(default_factory=set)  # 已实际分析过的附件路径（多附件遍历）
    attachment_evidence: list = field(default_factory=list)  # E3(2026-08-25 桶C攻坚): file_analyze 全文累积，强制注入 plan prompt 防"证据不进脑"
    # 墙钟硬止损标记（2026-08-20 锐评 P0-2）：墙钟超限时置 True，_finalize 据此分类
    _wallclock_hit: bool = False
    _start_monotonic: Optional[float] = None  # solve() 入口时间戳
    # 4 类失败埋点（2026-08-22 赛后重锐评 M1.3）：
    # _extract_failed=True  → 候选 flag 被提取校验拒绝（提取错）
    # give_up_reason 非空   → 监督裁决放弃（决策错方向）
    _extract_failed: bool = False
    give_up_reason: Optional[str] = None
    # 放弃前确定性兜底已跑标记（M3 2026-08-29）：每题至多一次，避免重复嗅探
    _last_chance_done: bool = False
    # 2026-08-24 诚实化：静态分析器（presolve）直出标记，零 LLM 调用时置 True
    solved_by_presolve: bool = False
    # E2（2026-08-25 桶B攻坚）可观测计数：每题 LLM 调用数 / 每步超时次数
    llm_calls: int = 0
    step_timeouts: int = 0
    # E6（2026-08-25 桶B攻坚）：few-shot 方向决策范例注入开关（默认关，A/B 可切）
    few_shot: bool = False
    # E3（2026-08-25 桶C攻坚）：附件证据强制注入 plan prompt 开关（默认关，A/B 可切）
    # 照搬 E6 模式：env CTF_AGENT_E3=1 开启；开启后 file_analyze 全文才会注入 prompt。
    e3_enabled: bool = False
    # E3 效果埋点：本题求解过程中附件全文是否真注入过 plan prompt（供 error_struct.evidence_injected 度量"证据不进脑"）
    evidence_injected_into_prompt: bool = False
    # 监督裁决流水（2026-08-23 质检④采纳率统计）：每次 _supervise 咨询记录一条
    # {action, step_index}——用于量化"监督建议被采纳率"，证明监督者非摆设
    supervisor_verdicts: list = field(default_factory=list)
    # race-intelligence 微观态势快照（2026-08-27）：单题信心，由 _log_situation 每 5 步写入
    last_confidence: Optional[float] = None
    # Writeup RAG（IDEA-5 务实落地）：每步检索到的历史解法/工具手册，注入 plan prompt
    knowledge_hits: Optional[list] = None
    # budget-reflection（race-intelligence 第二层，2026-08-27）：预算反思决策快照（只读日志写入）
    last_reflection: Optional[dict] = None

    def is_stuck(self) -> bool:
        return self.stuck_count >= 3

    def record(self, step: StepRecord) -> None:
        self.steps.append(step)
        # 僵局计数：错误累计，无错误即重置（P0修复2026-08-21：所有错误类型都累加，成功即重置）
        if step.error_category is not None:
            self.stuck_count += 1
        else:
            self.stuck_count = 0

    def apply_verdict(self, verdict: SupervisionVerdict) -> None:
        """根据监督裁决更新上下文（策略切换/升级重置僵局计数）。

        抄 NUS Advisor：把监督的 suggestion 累积为 advisor_hint，
        注入后续 plan（定向提示注入闭环——AI 卡壳时人工/监督提示修正路径）。
        """
        if verdict.action == VERDICT_SWITCH:
            self.strategy_switches += 1
            self.stuck_count = 0
        elif verdict.action == VERDICT_UPGRADE:
            self.model_upgrades += 1
            self.stuck_count = 0
        # 定向提示注入：非 continue 且带 suggestion 时累积（避免重复覆盖）
        if (
            verdict.action != VERDICT_CONTINUE
            and verdict.suggestion
            and verdict.suggestion != self.advisor_hint
        ):
            self.advisor_hint = verdict.suggestion

    def last_step(self) -> Optional[StepRecord]:
        return self.steps[-1] if self.steps else None


def _should_upgrade_heavy(diff: str, cat: str, attempt: int, upgrades: int = 0) -> bool:
    """B-20：重型模型升级判定（决赛备战，可单测）。

    - HARD/VERY_HARD：首步（attempt<2）即升级重型（深推理从头介入）
    - crypto/pwn/reverse 的 EASY/MEDIUM：仅卡壳重试（attempt>=1）才升级，
      简单题走轻量模型（便宜快），避免浪费 reasoner 额度与墙钟
    - 已升级过（upgrades!=0）或 attempt>=2 不再升级
    """
    diff = str(diff or "").upper()
    cat = str(cat or "").lower()
    if attempt >= 2 or upgrades != 0:
        return False
    if diff in ("HARD", "VERY_HARD"):
        return True
    return attempt >= 1 and cat in ("crypto", "pwn", "reverse")


def _supervision_stats(ctx: AgentContext) -> dict:
    """监督采纳率统计（2026-08-23 质检④）：量化监督裁决分布。

    解决"监督 Agent 无法证明自己不是摆设"的可审计缺口：
    - total：本次 solve 内监督咨询次数（_supervise 调用数）
    - corrective：非 continue 裁决次数（真正干预而非默认放行）
    - corrective_rate：非 continue 占比——监督实际"改变方向"的频率
    - by_action：各 action 计数（continue/redirect/switch_strategy/upgrade_model/give_up）
    跨题聚合由赛后报告层按 total/corrective 求和即可。
    """
    verdicts = getattr(ctx, "supervisor_verdicts", None) or []
    total = len(verdicts)
    if not total:
        return {"total": 0, "corrective": 0, "corrective_rate": 0.0, "by_action": {}}
    by_action: dict = {}
    corrective = 0
    for v in verdicts:
        action = str(v.get("action", VERDICT_CONTINUE))
        by_action[action] = by_action.get(action, 0) + 1
        if action != VERDICT_CONTINUE:
            corrective += 1
    return {
        "total": total,
        "corrective": corrective,
        "corrective_rate": round(corrective / total, 3),
        "by_action": by_action,
    }


class MainAgent:
    """主解题 Agent：Plan-Act-Observe 循环。"""

    def __init__(
        self,
        llm_client=None,
        registry=None,      # tools.registry.ToolRegistry（可选）
        sandbox=None,       # sandbox.Executor（可选）
        checker=None,       # verify.FlagChecker（可选）
        supervisor=None,    # core.supervisor_agent.SupervisorAgent（可选）
        router=None,        # 模型路由（可选，默认用 llm.client.get_model_for_attempt）
        coordinator=None,   # core.intervention.InterventionCoordinator（可选，人工干预协调）
        max_retries: int = 3,
        goal_logger=None,   # core.goal_directive.GoalLogger（可选，反思日志持久化）
        skill_manager=None, # tools.skill_manager.SkillManager（可选，动态 Skill 加载）
        provider=None,      # LLM provider 名（baidu/mimo/...，供报告与流量吻合）
        per_question_wallclock: Optional[int] = None,  # 单题墙钟硬止损（秒，None→读 config）
        hard_wallclock: Optional[int] = None,          # HARD/VERY_HARD 分级墙钟（秒，None→读 config）
        step_timeout_s: Optional[float] = None,        # E2 每步超时（秒，None→env/默认60）
        llm_call_budget: Optional[int] = None,         # E2 每题 LLM 调用上限（None→env/默认12）
        few_shot: Optional[bool] = None,               # E6 few-shot 方向范例注入（None→env/默认关）
        e3_enabled: Optional[bool] = None,             # E3 附件证据注入开关（None→env/默认关）
    ):
        self.llm_client = llm_client
        self.registry = registry
        self.sandbox = sandbox
        self.checker = checker
        self.supervisor = supervisor
        self.router = router
        self.coordinator = coordinator
        self.max_retries = max_retries
        self.goal_logger = goal_logger or GoalLogger()
        self.skill_manager = skill_manager
        self.provider = provider
        self._last_skill_require = None  # 上一轮 skill_require（供 solve 循环加载）
        # 墙钟硬止损阈值：显式传入 > 环境变量 > config 默认 300
        if per_question_wallclock is not None:
            self.per_question_wallclock = per_question_wallclock
        else:
            try:
                from config import AppConfig
                self.per_question_wallclock = AppConfig.from_env().per_question_wallclock
            except Exception:  # noqa: BLE001 - config 不可用时兜底默认
                self.per_question_wallclock = DEFAULT_PER_QUESTION_WALLCLOCK
        # HARD 分级墙钟（P1-2 2026-08-21）：600s→480s，保留 env 覆盖
        if hard_wallclock is not None:
            self.hard_wallclock = hard_wallclock
        else:
            try:
                from config import AppConfig
                self.hard_wallclock = AppConfig.from_env().hard_wallclock
            except Exception:  # noqa: BLE001 - config 不可用时兜底默认
                self.hard_wallclock = 480
        # E2（2026-08-25 桶B攻坚）：每步超时 + 每题 LLM 调用预算（可 env 覆盖，与墙钟同风格）
        # step_timeout_s：单步 LLM+工具执行硬上限，防单步极慢拖死并发池（区别于每题墙钟）。
        # llm_call_budget：每题 LLM 调用硬上限，收敛"无限试错"——真题回归验收要求 ≤12。
        self.step_timeout_s = float(step_timeout_s) if step_timeout_s is not None \
            else float(os.getenv("CTF_AGENT_STEP_TIMEOUT_S", "60"))
        self.llm_call_budget = int(llm_call_budget) if llm_call_budget is not None \
            else int(os.getenv("CTF_AGENT_LLM_CALL_BUDGET", "12"))
        # E6（2026-08-25 桶B攻坚）：few-shot 方向决策范例注入开关（可 env 覆盖，默认关）
        # 仅在 LLM plan 提示注入精选「先判断题型→正确首步」范例，帮模型少走错方向
        # （桶B=方向决策错 占失败 57.1%）。默认关：保证基线 KPI（presolve 主导）不被改动。
        self.few_shot = bool(few_shot) if few_shot is not None \
            else bool(os.getenv("CTF_AGENT_FEWSHOT", ""))
        # E3（2026-08-25 桶C攻坚）：附件证据注入开关（默认关，保证基线 KPI 不被改动；
        # 仅 A/B 实验开启 CTF_AGENT_E3=1）。开启后 file_analyze 全文才注入 plan prompt，
        # 使"证据不进脑"可被 error_struct.evidence_injected 真实度量（见 _chain_stats）。
        self.e3_enabled = bool(e3_enabled) if e3_enabled is not None \
            else bool(os.getenv("CTF_AGENT_E3", ""))

    # ── 放弃前确定性兜底（M3 2026-08-29）────────────────

    async def _deterministic_last_chance(self, question, ctx: AgentContext) -> Optional[str]:
        """放弃/墙钟过半前的最后一次确定性兜底（每题至多一次）。

        根因（08-28 破冰回归 7 败逐题分析）：
        1. 监督常在 steps<5 就裁决 give_up（3 道 wrong_direction 均源于
           "已升级重型模型仍连续失败"），而「≥5 步强制路由」尚未触发 →
           确定性工具链根本没机会跑；
        2. 3 道 TIMEOUT 是墙钟先到，工具链同样没机会跑。

        对策：在两条放弃路径 + 墙钟 60% 处各给一次完整 presolve 机会
        （force=True 绕开"同题只嗅探一次"的去重，确保真跑）。
        """
        if getattr(ctx, "_last_chance_done", False) or getattr(ctx, "candidate_flag", None):
            return None
        ctx._last_chance_done = True
        try:
            from core.presolve import presolve

            flag = await presolve(question, registry=self.registry, sandbox=self.sandbox,
                                  answers=None, force=True)
            if flag:
                logger.info("[%s] 放弃前确定性兜底命中: %s",
                            getattr(question, "id", "?"), flag[:60])
                ctx.candidate_flag = flag
                ctx.solved_by_presolve = True
            else:
                logger.info("[%s] 放弃前确定性兜底未命中，进入放弃流程",
                            getattr(question, "id", "?"))
            return flag
        except Exception as _exc:  # noqa: BLE001 - 兜底失败不阻塞放弃
            logger.warning("[%s] 放弃前确定性兜底异常: %s", getattr(question, "id", "?"), _exc)
            return None

    # ── 主循环 ──────────────────────────────────────────

    async def solve(self, question, attempt: int = 0, hint: Optional[str] = None,
                    correction: Optional[dict] = None) -> dict:
        """对一道题执行 Plan-Act-Observe 循环，返回统一 JSON 契约。

        Args:
            question: Question 对象（需含 id/title/category/description/flag_pattern）
            attempt: 当前重试次数（用于分级模型调度）
            hint: 平台结构化提示（可选）
            correction: 结构化修正指令（错误归因：error_category/key_info/suggestion）
        """
        ctx = AgentContext(question=question, hint_text=hint, correction=correction)
        ctx.few_shot = self.few_shot  # E6 开关透传：plan 提示按需注入方向决策范例
        ctx.e3_enabled = self.e3_enabled  # E3 开关透传：plan 提示按需注入附件全文
        # 2026-08-21 攻坚（解出数优先）+ P1-3 收敛（赛后）：确定性预扫统一入口——
        # 原入口手工 flag_scan/crypto_auto 收敛为 core.presolve.presolve，按序
        # flag_scan → crypto_auto → math_engine → 关键词 fast_solve；命中即直接
        # 出答案，杜绝模型幻觉（web2/reverse_js 实测第一步就编 flag 被拦截）。
        try:
            from core.presolve import presolve

            _pre = await presolve(question, registry=self.registry, sandbox=self.sandbox,
                                  answers=None)
            if _pre:
                logger.info("[%s] 确定性预扫命中: %s",
                            getattr(question, "id", "?"), _pre[:60])
                ctx.candidate_flag = _pre
                ctx.solved_by_presolve = True  # 2026-08-24 诚实化：标记静态分析器直出，零 LLM
        except Exception as _exc:  # noqa: BLE001 - 预扫失败不阻塞主流程
            logger.warning("[%s] 确定性预扫异常: %s", getattr(question, "id", "?"), _exc)
        # 墙钟硬止损起点（2026-08-20 锐评 P0-2）：solve() 入口记 monotonic 时间，
        # 每步检查 elapsed，超 per_question_wallclock 即 break + 标记 wallclock_timeout。
        ctx._start_monotonic = time.monotonic()
        # 高难题首步上重型深推理（2026-08-21 锐评高难题攻坚）：
        # HARD/VERY_HARD 题第一步就升级到重型模型（attempt>=2 触发 heavy_model），
        # 不等 stuck_count 累积——难题深推理需要重型模型从头介入，轻量模型试错浪费墙钟。
        # P0修复（2026-08-21）：仅当未升级过时才首步升级，避免重复升级。
        # B-20修复（2026-08-21 决赛备战）：重型升级判定收敛为 _should_upgrade_heavy——
        # HARD/VERY_HARD 首步重型；crypto/pwn/reverse 的 EASY/MEDIUM 仅卡壳(attempt>=1)
        # 才重型，简单题走轻量（便宜快），避免正式赛简单 crypto 浪费 reasoner 额度与墙钟。
        _diff = str(getattr(question, "difficulty", "")).upper()
        _cat = str(getattr(question, "category", "")).lower()
        if _should_upgrade_heavy(_diff, _cat, attempt, ctx.model_upgrades):
            attempt = 2
            logger.info("[%s] 重型模型升级（%s/%s, attempt=%d）", getattr(question, "id", "?"), _diff or _cat, _cat, attempt)
        # 抄 CyberStrikeAI/NUS：人工干预运行时接口
        # - 每步轮询人工注入的定向提示（高优先级上下文）→ advisor_hint 修正路径
        # - 卡壳（僵局计数≥2）时标记待人工介入（Web 面板可见）
        if self.coordinator is not None:
            task_id = str(getattr(question, "id", "?"))
            human_hint = self.coordinator.poll(task_id)
            if human_hint:
                ctx.advisor_hint = human_hint
        # P0修复（2026-08-21）：步数上限按难度分级，简单题9步、中等12步、难题15步，避免复杂题步骤不够
        _diff = str(getattr(question, "difficulty", "")).upper()
        if _diff in ("HARD", "VERY_HARD"):
            _max_steps = self.max_retries * 5
        elif _diff == "MEDIUM":
            _max_steps = self.max_retries * 4
        else:
            _max_steps = self.max_retries * 3
        # E2（2026-08-25 桶B攻坚）：每题 LLM 调用预算硬封顶（默认12），收敛"无限试错"——
        # 真题回归验收要求每题 LLM 调用 ≤12。简单题 9/中等 12 不变，难题 15 收敛到 12。
        _max_steps = min(_max_steps, self.llm_call_budget)
        try:
            for step_index in range(_max_steps):  # 分级步骤上限保护（E2：封顶 llm_call_budget）
                # ── 墙钟硬止损检查（每步顶部，先于一切重活）──
                # 防止单步 LLM+工具执行过长（实测单步可达数百秒）把并发池拖死。
                if ctx._start_monotonic is not None:
                    elapsed = time.monotonic() - ctx._start_monotonic
                    if elapsed >= self._wallclock_for(question):
                        ctx._wallclock_hit = True
                        logger.warning(
                            "[%s] 墙钟超限 %.1fs >= %.0fs，强制止损放弃（防拖死并发池）",
                            getattr(question, "id", "?"), elapsed,
                            self._wallclock_for(question),
                        )
                        break
                    # M3（2026-08-29）：墙钟 60% 仍未解出 → 确定性兜底提前跑一次。
                    # 根因：3 道 TIMEOUT 是墙钟先到，确定性工具链全程没机会跑。
                    if elapsed >= 0.6 * self._wallclock_for(question) and not ctx.candidate_flag:
                        if await self._deterministic_last_chance(question, ctx):
                            break

                # ── 人工干预轮询：有新提示则注入（高优先级上下文，修正路径）──
                if self.coordinator is not None:
                    hint_inj = self.coordinator.poll(question.id)
                    if hint_inj:
                        ctx.advisor_hint = hint_inj
                        logger.info("[%s] 注入人工提示: %s", question.id, hint_inj[:60])

                # ── Plan：生成下一步行动（E2 每步超时 + 每题 LLM 调用计数）──
                # step_timeout_s 单步硬上限：防单步 LLM 调用极慢拖死并发池（区别于每题墙钟）。
                ctx.llm_calls += 1
                try:
                    plan = await asyncio.wait_for(self._plan(ctx, attempt), timeout=self.step_timeout_s)
                except asyncio.TimeoutError:
                    ctx.step_timeouts += 1
                    ctx.record(StepRecord(stage=STAGE_STUCK, action="reason",
                                          observation="", error_category=ERR_TOOL_FAILURE))
                    logger.warning("[%s] 单步 _plan 超时(>%.0fs)，记一步失败继续循环",
                                   getattr(question, "id", "?"), self.step_timeout_s)
                    continue
                # 仅当已有经校验的候选 flag 才 break；
                # 模型 plan 声称 done 时仍走 _act（触发 flag→crypto/misc 兜底真算，防猜 flag）
                if ctx.candidate_flag:
                    break

                # ── Act：执行一步（E2 每步超时：单步工具/脚本执行硬上限）──
                try:
                    act_result = await asyncio.wait_for(self._act(ctx, plan, attempt), timeout=self.step_timeout_s)
                except asyncio.TimeoutError:
                    ctx.step_timeouts += 1
                    ctx.record(StepRecord(stage=STAGE_STUCK, action="reason",
                                          observation="", error_category=ERR_TOOL_FAILURE))
                    logger.warning("[%s] 单步 _act 超时(>%.0fs)，记一步失败继续循环",
                                   getattr(question, "id", "?"), self.step_timeout_s)
                    continue

                # ── Observe：解析结果，更新上下文 ──
                step = self._observe(ctx, plan, act_result)
                ctx.record(step)
                # race-intelligence 微观态势快照（只读日志，不改控制流）
                self._log_situation(ctx)
                # budget-reflection 第二层（race-intelligence）：每 5 步预算反思日志（只读）
                self._log_budget_reflection(ctx)
                # 早停闸门（默认关 CTF_AGENT_BUDGET_REFLECTION=1）：预算将尽+零进展+低信心→提前放弃
                if self._budget_reflection_should_abandon(ctx):
                    logger.info(
                        "[%s] budget_reflection 早停(ABANDON)：预算将尽+零进展+低信心，放弃止损",
                        getattr(question, "id", "?"),
                    )
                    ctx.give_up_reason = "budget_reflection 早停(ABANDON)"
                    break
                # Writeup RAG（IDEA-5 务实落地）：每步按"题型+最新观察"检索历史解法/工具手册
                self._retrieve_knowledge(ctx, step)

                # ── 卡关处理（P0-A 修复：先升级再放弃，而非直接 break）──
                # 原逻辑在监督咨询前就 break，导致 HARD 题未升级重型模型就被放弃，
                # 监督的 upgrade/switch/reset 在连续失败场景永远到不了（死锁）。
                # 现改为：连续失败先咨询监督——允许升级重型模型/换策略后重试一次；
                # 已升级过（attempt>=2）仍连续失败才放弃。墙钟硬止损(300s)仍是最终兜底。
                if ctx.stuck_count >= 2 or self._situation_override_triggered(ctx):
                    verdict = await self._supervise(ctx)
                    if verdict.action == VERDICT_GIVE_UP:
                        # M3（2026-08-29）：放弃前给确定性工具链最后一次机会——
                        # 监督常在 steps<5 就裁决放弃，强制路由（≥5 步）尚未触发。
                        if await self._deterministic_last_chance(question, ctx):
                            break
                        logger.info("[%s] 监督裁决放弃: %s", question.id, verdict.reason)
                        ctx.give_up_reason = verdict.reason or "监督裁决放弃"
                        break
                    ctx.apply_verdict(verdict)
                    if verdict.action == VERDICT_UPGRADE:
                        if attempt >= 2:
                            # M3（2026-08-29）：同上，放弃前先确定性兜底
                            # （此类"已升级仍失败"正是 3 道 wrong_direction 的直接来源）
                            if await self._deterministic_last_chance(question, ctx):
                                break
                            logger.info("[%s] 已升级重型模型仍连续失败，放弃止损（换下一题）",
                                        question.id)
                            ctx.give_up_reason = "已升级重型模型仍连续失败"
                            break
                        attempt = 2  # 强制升级到重型模型重试一次
                        logger.info("[%s] 连续失败→监督升级重型模型重试", question.id)
                        continue
                    # continue / switch / redirect：继续循环（stuck_count 可能已被 reset）
                    continue

                # ── E2（2026-08-25 桶B攻坚）：连续同动作 3 次 → 强制切换策略 ──
                # 仅看 action（不要求 observation 完全相同），比下方"完全相同 observation 死循环放弃"
                # 更宽松：真在"换参数重试"也算重复，主动换策略而非空等到监督已放弃。
                # 与下方"完全相同 observation → presolve 兜底 → 放弃"互补（软 switch 优先于硬放弃）。
                if len(ctx.steps) >= 3:
                    _acts = [getattr(s, "action", "") for s in ctx.steps[-3:]]
                    if all(_a and _a == _acts[0] for _a in _acts):
                        ctx.strategy_switches += 1
                        ctx.stuck_count = 0
                        ctx.advisor_hint = (
                            f"⚠️ 检测到连续 3 步执行相同动作（{_acts[0]}），疑似策略空转死循环，"
                            "强制切换解题策略：换个切入点/工具/参数，禁止重复同一动作。"
                        )
                        logger.info("[%s] 连续同动作3次检测：强制切换策略 (action=%s)",
                                    question.id, _acts[0])
                        continue

                # ── 同参数重复检测（第五轮锐评：连续同工具同参数=死循环，快速终止）──
                # P0修复（2026-08-21）：改为连续3步相同才判定死循环，避免误判正常相似步骤
                # 2026-08-23 收敛：web 题需更多试错步（SQLi/SSTI 要发 GET→分析→构造 POST），
                # 放宽到连续5步相同才判死循环，避免误杀 web 题的正常推理链路。
                _is_web = str(getattr(ctx.question, "category", "")).lower() == "web"
                _dup_thresh = 5 if _is_web else 3
                if len(ctx.steps) >= _dup_thresh:
                    _window = ctx.steps[-_dup_thresh:]
                    def _step_sig(s):
                        return (str(getattr(s, "action", "")),
                                str(getattr(s, "observation", ""))[:200],
                                str(getattr(s, "tool_used", "")))
                    if all(_step_sig(s) == _step_sig(_window[0]) for s in _window):
                        # 2026-08-21 攻坚（解出数优先）+ P1-3 收敛（赛后）：死循环前
                        # 先强制确定性兜底——统一走 core.presolve（flag_scan → crypto_auto
                        # → math_engine → fast_solve）。若入口已嗅探过（同附件只嗅探一次），
                        # presolve 直接返回 None，落到下方死循环止损。
                        try:
                            from core.presolve import presolve

                            _fb_flag = await presolve(
                                question, registry=self.registry, sandbox=self.sandbox,
                                answers=None)
                            if _fb_flag:
                                logger.info("[%s] 确定性兜底命中: %s",
                                            question.id, _fb_flag[:60])
                                ctx.candidate_flag = _fb_flag
                                ctx.solved_by_presolve = True  # 2026-08-24 诚实化：兜底静态分析器直出，零 LLM
                                break
                        except Exception as _exc:  # noqa: BLE001 - 兜底失败不阻塞止损
                            logger.warning("[%s] 确定性兜底异常: %s", question.id, _exc)
                        logger.info("[%s] 同参数重复（%s）——判定死循环，止损换题",
                                    question.id, getattr(_window[0], "action", "?"))
                        break

                # ── web 无靶机快速失败：连续 reason 空转 → 强制模板兜底（本地 web 空转教训）──
                cat = str(getattr(question, "category", "")).lower()
                qdesc = str(getattr(question, "description", "") or "")
                has_target = any(k in qdesc for k in
                                 ("http://", "https://", "靶机", "host:", "url:", "端口", "endpoint"))
                if cat == "web" and not has_target and len(ctx.steps) >= 2:
                    recent_actions = [s.action for s in ctx.steps[-2:]]
                    if all(a == "reason" for a in recent_actions):
                        ctx.advisor_hint = (
                            "⚠️ 检测到 web 题连续 2 步纯推理无进展。这类题通常是「源码审计题」："
                            "附件里是 CMS/Web 服务器源码包（joomla/wordpress/drupal/ghost/cmsms/"
                            "nginx/httpd/caddy/redis 等），flag 藏在被植入的后门/危险函数/敏感配置/"
                            "已知 CVE 里，**不需要靶机交互**。正确动作：① file_analyze 读附件"
                            "（若是目录先列内容再读具体文件）→ 解压 tar.gz/zip；② 调 web_source_audit "
                            "工具做后门/危险函数/敏感文件/版本-CVE 扫描；③ 命中后门或 CVE 后构造 "
                            "payload 或直接提取 flag。禁止继续 reason 空转或空等靶机地址。"
                        )
                        logger.info("[%s] web 无靶机空转检测：注入模板兜底提示", question.id)

                # ── 监督强制路由（战役A/IDEA-1 最小实现，2026-08-27 多轮实测迭代）──
                # 触发：① 连续 3 步纯 reason 空转；或 ② 总步数≥5 仍无 candidate_flag
                #   （LLM 交替做无效 tool 调用也会卡死，仅靠①漏判）。最多强制 3 次，避免无限干预主循环。
                # 级联：flag_scan → crypto_auto → file_analyze(内嵌文件头扫描) → stego_lsb(图片LSB)。
                # 仅在区间失败路径触发（presolve 命中的题早已 break），不影响 14/15 主导解出路径。
                _recent = [s.action for s in ctx.steps[-3:]] if ctx.steps else []
                _consec_reason = len(ctx.steps) >= 3 and all(a == "reason" for a in _recent)
                _forced_count = getattr(ctx, "_forced_route_count", 0)
                _no_flag_yet = not getattr(ctx, "candidate_flag", None)
                if (_consec_reason or (len(ctx.steps) >= 5 and _no_flag_yet)) and _forced_count < 3:
                    ctx._forced_route_count = _forced_count + 1
                    if _consec_reason:
                        ctx.advisor_hint = (
                            "⚠️ 检测到连续 3 步纯推理无任何工具/脚本调用——立即停止推理空转！"
                            "必须执行具体动作：附件用 file/strings/capstone 反汇编，crypto 用 script 计算，"
                            "web 用 http_request 发包，pwn 用 pwntools 交互，禁止继续输出 reason。"
                        )
                        logger.info("[%s] 连续 reason 空转检测：强制转工具调用", question.id)
                    _cat = str(getattr(question, "category", "")).lower()
                    _atts = list(getattr(question, "attachments", []) or [])
                    if _atts:
                        import re as _re
                        _hit = None
                        # 1) 明文 flag 直扫
                        try:
                            _fo = await self.registry.run("flag_scan", {"attachments": _atts})
                            _txt = getattr(_fo, "text", "") or ""
                            _m = _re.search(r"flag\{[^}\s]{3,}\}", _txt, _re.IGNORECASE)
                            if _m:
                                _hit = _m.group(0)
                        except Exception as _fe:  # noqa: BLE001
                            logger.warning("[%s] 监督强制 flag_scan 异常: %s", question.id, _fe)
                        # 2) crypto/misc 确定性求解（crypto_auto：RSA 全套 + 哈希 + 多层编码 + 已知key 维吉尼亚 + 八进制）
                        if _hit is None and _cat in ("crypto", "misc"):
                            try:
                                _fo = await self.registry.run("crypto_auto", {"attachments": _atts})
                                _txt = getattr(_fo, "text", "") or ""
                                _m = _re.search(r"flag\{[^}\s]{3,}\}", _txt, _re.IGNORECASE)
                                if _m:
                                    _hit = _m.group(0)
                            except Exception as _fe:  # noqa: BLE001
                                logger.warning("[%s] 监督强制 crypto_auto 异常: %s", question.id, _fe)
                        # 3) 通用文件分析（binwalk 式内嵌文件头扫描 + 字符串flag提取；覆盖 JPEG尾附PNG等）
                        if _hit is None:
                            try:
                                for _a in _atts:
                                    _fo = await self.registry.run("file_analyze", {"path": _a})
                                    _txt = getattr(_fo, "text", "") or ""
                                    _m = _re.search(r"flag\{[^}\s]{3,}\}", _txt, _re.IGNORECASE)
                                    if _m:
                                        _hit = _m.group(0)
                                        break
                            except Exception as _fe:  # noqa: BLE001
                                logger.warning("[%s] 监督强制 file_analyze 异常: %s", question.id, _fe)
                        # 4) misc 含图片 → LSB 隐写提取（仅当上述未命中）
                        if _hit is None and _cat == "misc":
                            for _im in [a for a in _atts if str(a).lower().endswith(
                                    (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".webp"))]:
                                try:
                                    _fo = await self.registry.run("stego_lsb", {"path": _im})
                                    _txt = getattr(_fo, "text", "") or ""
                                    _m = _re.search(r"flag\{[^}\s]{3,}\}", _txt, _re.IGNORECASE)
                                    if _m:
                                        _hit = _m.group(0)
                                        break
                                except Exception as _fe:  # noqa: BLE001
                                    logger.warning("[%s] 监督强制 stego_lsb 异常: %s", question.id, _fe)
                        if _hit is not None:
                            ctx.candidate_flag = _hit
                            logger.info("[%s] 监督强制路由命中 flag: %s", question.id, _hit[:40])
                            break
                        logger.info("[%s] 监督强制路由第%d次未命中，继续循环", question.id, ctx._forced_route_count)

                # ── crypto/misc 无数据快速失败：附件/靶机/题面全缺 → 连续 reason 空转 → 快速放弃 ──
                # （可解的 crypto/misc 题数据全在附件里，附件为空=无数据可算，纯推理必然空转）
                # P0-④（2026-08-21 赛后）：平台题同样适用——赛中因 429 导致 get_challenge
                # 失败（detail_fetch_failed）或 poller 未补全，question.attachments 为空，
                # 若豁免则无限空转（赛中 87% 流量耗在此）。给 2 步重试窗口（应对瞬时 429
                # 后重试成功的有数据题），2 步后仍无任何数据则强制止损标记 no_data。
                if cat in ("crypto", "misc"):
                    _qextra = getattr(question, "extra", {}) or {}
                    _platform_meta = _qextra.get("platform_meta") or {}
                    _detail_failed = bool(_platform_meta.get("_detail_fetch_failed"))
                    has_attachment = bool(getattr(question, "attachments", None))
                    has_target = any(k in str(getattr(question, "description", "") or "")
                                     for k in ("http://", "https://", "靶机", "host:", "url:", "端口"))
                    has_any_data = has_attachment or has_target or bool(getattr(question, "description", ""))
                    if (not has_any_data) and len(ctx.steps) >= 2:
                        recent_actions = [s.action for s in ctx.steps[-2:]]
                        if all(a == "reason" for a in recent_actions):
                            logger.info("[%s] crypto/misc 无数据空转检测：快速放弃（detail_failed=%s, att=%s）",
                                        question.id, _detail_failed, has_attachment)
                            ctx.task_status = "skipped_no_data"
                            break

                # ── pwn/reverse 快速失败止损（锐评：静态分析 N 步无突破口 → 止损，
                #    防死磕卡题浪费后面快题时间——reverse 40% 短板的时间管理）──
                if cat in ("pwn", "reverse") and len(ctx.steps) >= 4:
                    recent_actions = [getattr(s, "action", "") for s in ctx.steps[-4:]]
                    if all(a == "reason" for a in recent_actions):
                        ctx.advisor_hint = (
                            "⚠️ pwn/reverse 连续 4 步纯推理无突破口——立即止损！"
                            "若静态分析未见明确漏洞原语/加密特征/可读字符串，"
                            "标记超出能力边界，记录归因后换题（防卡题浪费后面快题时间）。"
                        )
                        logger.info("[%s] pwn/reverse 快速失败：无突破口止损", question.id)

                # ── 校验 flag ──
                flag = self._extract_flag(ctx, act_result)
                if flag:
                    ctx.candidate_flag = flag
                    if self.coordinator is not None:
                        self.coordinator.clear_human_flag(question.id)
                    break

                # ── 卡壳标记待人工（Web 面板可见并可介入）──
                # 阈值 2：须在 supervise 之前检查——apply_verdict 的
                # upgrade/switch 会重置 stuck_count，阈值 3 永远到不了
                if (
                    self.coordinator is not None
                    and ctx.stuck_count >= 2
                    and ctx.steps
                ):
                    last = ctx.steps[-1]
                    reason = f"连续 {ctx.stuck_count} 步失败/无进展（{last.error_category or 'stuck'}）"
                    self.coordinator.request_human(question.id, reason=reason)

                # ── 监督裁决（每 2 步常规咨询）──
                # P0-A 整改（2026-08-21）：stuck_count>=2 的连续失败已在上面
                # "卡关处理"分支先咨询监督并 continue/break，到不了这里；
                # 原 `or ctx.stuck_count >= 2` 是死条件（上方必 continue），已移除。
                if (step_index + 1) % 2 == 0:
                    verdict = await self._supervise(ctx)
                    if verdict.action == VERDICT_GIVE_UP:
                        logger.info("[%s] 监督裁决放弃: %s", question.id, verdict.reason)
                        break
                    ctx.apply_verdict(verdict)
                    if verdict.action == VERDICT_UPGRADE:
                        attempt = max(attempt, 2)  # 强制升级到重型模型

            return self._finalize(ctx, attempt)
        except Exception as exc:  # noqa: BLE001 - 主循环兜底
            logger.warning("[%s] 主循环异常: %s", question.id, exc)
            return self._finalize(ctx, attempt, error=exc)

    # ── 各阶段实现 ──────────────────────────────────────

    async def _plan(self, ctx: AgentContext, attempt: int) -> dict:
        """生成下一步行动计划（JSON）。[P1 拆分：逻辑迁 core/phases.plan_step]"""
        from core.phases import plan_step
        return await plan_step(self, ctx, attempt)

    async def _act(self, ctx: AgentContext, plan: dict, attempt: int) -> dict:
        """执行一步：推理 / 调工具 / 跑脚本。[P1 拆分：逻辑迁 core/phases.act_step]"""
        from core.phases import act_step
        return await act_step(self, ctx, plan, attempt)

    def _observe(self, ctx: AgentContext, plan: dict, act: dict) -> StepRecord:
        """解析执行结果，生成结构化步骤记录。[P1 拆分：逻辑迁 core/phases.observe_step]"""
        from core.phases import observe_step
        return observe_step(self, ctx, plan, act)

    async def _supervise(self, ctx: AgentContext) -> SupervisionVerdict:
        """咨询监督反思 Agent；未注入时用确定性兜底。[P1 拆分：逻辑迁 core/phases.supervise_step]"""
        from core.phases import supervise_step
        verdict = await supervise_step(self, ctx)
        # 监督裁决流水（2026-08-23 质检④采纳率统计）：每次咨询记录 action + 当时步数
        try:
            ctx.supervisor_verdicts.append({
                "action": getattr(verdict, "action", VERDICT_CONTINUE),
                "step_index": len(ctx.steps),
            })
        except Exception:  # noqa: BLE001 - 统计埋点失败不影响主流程
            pass
        return verdict
    # ── 工具方法 ────────────────────────────────────────

    # ── 态势感知快照（race-intelligence 微观态势，只读日志，不改控制流）──
    def _log_situation(self, ctx: AgentContext) -> None:
        """每 5 步从已有步骤历史计算单题信心并日志（纯规则，零额外 LLM 调用）。

        设计：仅读取 ctx.steps（已在 record 阶段累积），不改动解题控制流；
        计算出的信心写入 ctx.last_confidence 供看板/后续决策消费。
        """
        try:
            from core.confidence import ConfidenceEstimator, classify_step
        except Exception:  # noqa: BLE001 - 态势日志不应影响主流程
            return
        recent = ctx.steps[-5:]
        if not recent:
            return
        step_history = [s.observation for s in recent]
        error_history = [classify_step(s.observation, s.error_category) for s in recent]
        _budget_cap = getattr(self, "llm_call_budget", 1) or 1
        budget_ratio = min(1.0, ctx.llm_calls / max(_budget_cap, 1))
        conf = ConfidenceEstimator().estimate(step_history, error_history, budget_ratio)
        ctx.last_confidence = conf
        if len(ctx.steps) % 5 == 0:
            logger.info(
                "[%s] 态势快照: 信心=%.2f (步=%d, 卡壳=%d, LLM调用=%d)",
                getattr(ctx.question, "id", "?"), conf, len(ctx.steps),
                ctx.stuck_count, ctx.llm_calls,
            )

    def _situation_override_triggered(self, ctx: AgentContext) -> bool:
        """态势接管闸门（race-intelligence）：默认关闭，CTF_AGENT_SITUATION_OVERRIDE=1 开启。

        开启后，单题信心过低且已过半预算时，提前触发监督咨询换策略（复用既有
        _supervise 块），避免低信心题空转到预算耗尽。默认关闭 = 不影响现有调优行为/回归。
        """
        if os.environ.get("CTF_AGENT_SITUATION_OVERRIDE") != "1":
            return False
        try:
            from core.confidence import should_early_switch
        except Exception:  # noqa: BLE001
            return False
        return should_early_switch(
            ctx.last_confidence, ctx.llm_calls,
            getattr(self, "llm_call_budget", 12) or 12, override=True,
        )

    def _log_budget_reflection(self, ctx: AgentContext) -> None:
        """每 5 步做预算反思并日志（纯规则，零额外 LLM 调用，不改控制流，除非闸门开启）。"""
        try:
            from core.budget_reflection import (
                reflect as _reflect_budget, BudgetState as _BudgetState,
                DECISION_ABANDON,
            )
        except Exception:  # noqa: BLE001 - 反思日志不应影响主流程
            return
        _st = _BudgetState(
            budget_total=getattr(self, "llm_call_budget", 12) or 12,
            budget_used=len(ctx.steps),
        )
        _res = _reflect_budget(_st, ctx.steps, getattr(ctx, "last_confidence", None))
        ctx.last_reflection = {
            "decision": _res.decision, "reason": _res.reason, "metrics": _res.metrics,
        }
        if len(ctx.steps) % 5 == 0:
            logger.info(
                "[%s] budget_reflection: %s | %s",
                getattr(ctx.question, "id", "?"), _res.decision, _res.reason,
            )

    def _budget_reflection_should_abandon(self, ctx: AgentContext) -> bool:
        """预算反思早停闸门（budget-reflection）：默认关闭，CTF_AGENT_BUDGET_REFLECTION=1 开启。

        开启且反思决策为 ABANDON（预算将尽+零进展+低信心）时，提前 break 放弃，
        避免把整段预算空烧在 hopeless 路径上。复用既有 give_up 语义（ctx.give_up_reason）。
        默认关闭 = 不影响现有调优行为/回归。
        """
        if os.environ.get("CTF_AGENT_BUDGET_REFLECTION") != "1":
            return False
        try:
            from core.budget_reflection import (
                reflect as _reflect_budget, BudgetState as _BudgetState,
                DECISION_ABANDON,
            )
        except Exception:  # noqa: BLE001
            return False
        _st = _BudgetState(
            budget_total=getattr(self, "llm_call_budget", 12) or 12,
            budget_used=len(ctx.steps),
        )
        _res = _reflect_budget(_st, ctx.steps, getattr(ctx, "last_confidence", None))
        return _res.decision == DECISION_ABANDON

    # ── Writeup RAG（IDEA-5 务实落地：知识增强检索，默认关、零回归）──
    def _get_knowledge_index(self):
        """懒加载知识索引（仅 CTF_AGENT_WRITEUP_RAG=1 时构建；否则返回 None）。

        知识库 = 项目自有真实资产（writeups_corpus.jsonl 已验证解法 + skills/ 文档），
        不依赖外网爬取。构建失败绝不中断解题主流程。
        """
        if os.environ.get("CTF_AGENT_WRITEUP_RAG") != "1":
            return None
        if getattr(self, "_knowledge_index", None) is None:
            try:
                from knowledge.writeup_rag import WriteupIndex
                idx = WriteupIndex()
                n1 = idx.load_corpus_jsonl()
                n2 = idx.load_skills_docs()
                idx.build()
                self._knowledge_index = idx
                logger.info("[RAG] 知识索引就绪: 语料=%d 篇（solutions=%d, skills=%d）",
                            n1 + n2, n1, n2)
            except Exception as e:  # noqa: BLE001 - RAG 失败绝不应中断解题
                logger.warning("[RAG] 索引构建失败，跳过知识增强: %s", e)
                return None
        return self._knowledge_index

    def _retrieve_knowledge(self, ctx: AgentContext, step) -> None:
        """每步按"题型 + 最新观察"检索 top-k，写入 ctx.knowledge_hits 供 prompts 注入。

        仅当 RAG 启用时执行；任何异常都被吞掉，保证解题控制流不受影响。
        """
        idx = self._get_knowledge_index()
        if idx is None:
            return
        try:
            q_parts = [
                getattr(ctx.question, "title", "") or "",
                getattr(ctx.question, "category", "") or "",
                (step.observation or "")[:400],
            ]
            ctx.knowledge_hits = idx.retrieve(" ".join(q_parts), k=5)
        except Exception as e:  # noqa: BLE001
            logger.warning("[RAG] 检索失败，跳过本次注入: %s", e)

    def _wallclock_for(self, question) -> float:
        """分级墙钟（速度系统性优化：简单题更快止损，3h 吞吐提升）。

        EASY/VERY_EASY 120s（简单题应秒级解决，抢一血窗口）、MEDIUM 300s、
        HARD+ 480s（难题深推理窗口，P1-2 由 600s 下调，≤ specialcurve2 487s 灾难值；
        CTF_AGENT_HARD_WALLCLOCK 可覆盖）、未知默认 per_question_wallclock（300s）。
        """
        diff = str(getattr(question, "difficulty", "")).upper()
        if diff in ("VERY_EASY", "EASY"):
            return 120.0
        if diff in ("HARD", "VERY_HARD"):
            return float(getattr(self, "hard_wallclock", 480) or 480)
        return float(getattr(self, "per_question_wallclock", 300) or 300)

    def _extract_flag(self, ctx: AgentContext, act: dict) -> Optional[str]:
        """从执行结果中提取 flag。[P1 拆分：逻辑迁 core/phases.extract_flag]"""
        from core.phases import extract_flag
        return extract_flag(self, ctx, act)

    def _finalize(self, ctx: AgentContext, attempt: int, error: Optional[Exception] = None) -> dict:
        """生成统一 JSON 契约输出（含 self_reflection + skill_require 扩展字段）。"""
        # 真实 provider/模型标签（报告需与流量日志吻合，不硬编码 deepseek）
        from config import AppConfig, _resolve_provider_defaults

        _prov = self.provider or AppConfig.from_env().llm_provider
        _, _model, _, _ = _resolve_provider_defaults(_prov)
        provider_label = f"{_prov}/{_model}"
        last = ctx.last_step()
        flag = ctx.candidate_flag
        # 墙钟硬止损优先分类（2026-08-20 锐评 P0-2）：
        # 墙钟命中时 error.category=wallclock_timeout，区别于 stuck_loop，
        # 便于赛后复盘区分"连续失败放弃"与"单步极慢被时间闸掐断"。
        if ctx._wallclock_hit and not flag:
            err_category = ERR_WALLCLOCK_TIMEOUT
            _wc = self._wallclock_for(ctx.question)
            err_detail = (
                f"单题墙钟超限（>={_wc:.0f}s，难度={getattr(ctx.question, 'difficulty', '') or '默认'}），"
                "强制止损防拖死并发池"
            )
        elif error and not flag:
            # 2026-08-28 步级硬停：异常自带 category（如 BudgetExceeded.category=
            # budget_exceeded）时优先采用，不一律落进 hallucination 桶。
            err_category = getattr(error, "category", None) or ERR_HALLUCINATION
            err_detail = str(error)
        # ── 4 类失败埋点（2026-08-22 赛后重锐评 M1.3）──
        # 提取错：候选 flag 被提取校验拒绝（模板/幻觉/无工具证据）
        elif getattr(ctx, "_extract_failed", False) and not flag:
            err_category = ERR_EXTRACT_FAIL
            err_detail = "候选 flag 被提取校验拒绝（模板占位/疑似幻觉/无工具证据）"
        # 工具调用错：步骤级工具失败累积后仍未解出
        elif not flag and any(
            getattr(s, "error_category", None) == ERR_TOOL_FAILURE for s in ctx.steps
        ):
            err_category = ERR_TOOL_FAILURE
            err_detail = "工具调用失败累积后未解出"
        # 决策错：监督裁决放弃（方向性失败）
        # 2026-08-27 修复误判：KNOWN_GAP 题（题面缺运行时参数，如 anwang_crypto1 缺
        # hint_enc/AES_KEY_ENC，台账 REAL_SOLVES_LEDGER.md）解不出是题缺参，非方向错——
        # 归 extract_fail（题缺参）而非 wrong_direction（方向错），避免污染失败桶统计。
        elif getattr(ctx, "give_up_reason", None) and not flag:
            if str(getattr(ctx.question, "id", "")).lower() in _KNOWN_GAP_IDS:
                err_category = ERR_EXTRACT_FAIL
                err_detail = f"{ctx.give_up_reason}（题面缺运行时参数，KNOWN_GAP）"
            else:
                err_category = ERR_WRONG_DIRECTION
                err_detail = ctx.give_up_reason
        elif not flag:
            # 2026-08-28 修复兜底污染：此前所有"未解出 flag"都归 stuck_loop，但实测
            # 98.2% 案例 stuck_count=0（非真死循环）——只有连续同动作（stuck_count>=3）
            # 才算死循环，其余归 unresolved（未解出且无明确归因），使失败桶口径诚实。
            if getattr(ctx, "stuck_count", 0) >= 3:
                err_category = ERR_STUCK_LOOP
                err_detail = "未解出 flag（连续同动作死循环）"
            else:
                err_category = ERR_UNRESOLVED
                err_detail = "未解出 flag（无明确归因，非死循环）"
        else:
            err_category = None
            err_detail = None
        # ── 构造 self_reflection（从步骤历史自动生成 + LLM 输出合并）──
        reflection = self._build_self_reflection(ctx, flag, error)
        # ── 构造 skill_require（从 ability_gap 推断 + LLM 输出合并）──
        skill_req = self._infer_skill_require(ctx, reflection)
        if skill_req:
            self._last_skill_require = skill_req
        result = {
            "task_id": getattr(ctx.question, "id", ""),
            "question_type": getattr(ctx.question, "category", ""),
            "stage": last.stage if last else STAGE_RECON,
            "solved_by": "presolve" if getattr(ctx, "solved_by_presolve", False) else "main_agent_llm",
            "flag": flag,
            "confidence": _extract_confidence(ctx) or (0.9 if flag else 0.0),
            "evidence": [f"{s.stage}: {s.action} -> {s.observation[:100]}" for s in ctx.steps[-3:]],
            "error": (
                {
                    "category": err_category,
                    "detail": err_detail,
                    # E3（2026-08-25 桶C攻坚）效果埋点：三态信号，使 C 桶成为"证据不进脑"真实度量
                    #   None = 本题无附件（E3 不相关，不归 C 桶）
                    #   True = 有附件且附件全文曾注入 plan prompt（进了脑，失败归其他桶）
                    #   False = 有附件但未注入（"证据不进脑"，归 C 桶——正是 E3 想修的）
                    "evidence_injected": (
                        bool(ctx.evidence_injected_into_prompt)
                        if getattr(ctx.question, "attachments", None) else None
                    ),
                }
                if not flag
                else None
            ),
            "supervision": VERDICT_CONTINUE,
            # 监督采纳率统计（2026-08-23 质检④）：量化"监督建议被采纳率"，证明监督者非摆设。
            # corrective_rate = 非 continue 裁决占比（真正干预而非默认放行）。
            # 统计口径：一次 solve 内全部 _supervise 咨询；跨题聚合见赛后报告。
            "supervision_stats": _supervision_stats(ctx),
            # E2（2026-08-25 桶B攻坚）可观测：每题 LLM 调用数 / 每步超时次数，
            # 供 goal_log 统计与真题回归验收（平均每题 LLM 调用数下降 = 验收指标）
            "llm_calls": ctx.llm_calls,
            "step_timeouts": ctx.step_timeouts,
            "duration_ms": 0,  # 由调度层填充
            "provider": provider_label,
            "retries": attempt,
            "steps": [s.__dict__ for s in ctx.steps],
            # ── Goal 扩展字段 ──
            "self_reflection": reflection,
            "skill_require": skill_req,
            "task_status": "solved" if flag else (
                getattr(ctx, "task_status", "") or (
                    "failed_give_up_after_max_retry" if attempt >= self.max_retries else "failed"
                )
            ),
        }
        # ── Goal 日志持久化 ──
        if self.goal_logger:
            try:
                self.goal_logger.log(result)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[%s] Goal 日志写入异常: %s", getattr(ctx.question, "id", ""), exc)
        return result

    async def _llm_json(self, system: str, user: str, attempt: int) -> Optional[dict]:
        # 上帝模块拆分：LLM 封装归 core/llm_wrapper（2026-08-20 锐评整改）
        from core.llm_wrapper import llm_json

        return await llm_json(system, user, attempt, self.llm_client)

    async def _llm_text(self, system: str, user: str, attempt: int) -> str:
        # 上帝模块拆分：LLM 封装归 core/llm_wrapper
        from core.llm_wrapper import llm_text

        return await llm_text(system, user, attempt, self.llm_client)

    def _build_plan_prompt(self, ctx: AgentContext, attempt: int) -> str:
        # 上帝模块拆分：提示词组装归 core/prompts（2026-08-20 锐评整改）
        from core.prompts import build_plan_prompt

        return build_plan_prompt(ctx, attempt)

    def _build_reason_prompt(self, ctx: AgentContext, detail: str) -> str:
        # 上帝模块拆分：提示词组装归 core/prompts
        from core.prompts import build_reason_prompt

        return build_reason_prompt(ctx, detail)

    # ── Goal 反思与 Skill 推断 ─────────────────────────────

    def _build_self_reflection(self, ctx: AgentContext, flag: Optional[str], error: Optional[Exception]) -> dict:
        """自动生成结构化反思（上帝模块拆分：逻辑归 core/prompts）。"""
        from core.prompts import build_self_reflection

        return build_self_reflection(ctx, flag, error)

    def _infer_skill_require(self, ctx: AgentContext, reflection: dict) -> Optional[dict]:
        """从 ability_gap 推断是否需要请求新 Skill（上帝模块拆分：逻辑归 core/prompts）。"""
        from core.prompts import infer_skill_require

        return infer_skill_require(ctx, reflection, self.skill_manager)

    # ── 兜底脚本构造（薄委托：领域逻辑在各 toolkit，按附件内容嗅探而非题库描述）──

    def _build_crypto_fallback_script(self, ctx: AgentContext) -> Optional[str]:
        # 上帝模块拆分：兜底脚本归 core/fallbacks（2026-08-20 锐评整改）
        from core.fallbacks import build_crypto_fallback_script

        return build_crypto_fallback_script(ctx)

    def _build_misc_fallback_script(self, ctx: AgentContext) -> Optional[str]:
        # 上帝模块拆分：兜底脚本归 core/fallbacks
        from core.fallbacks import build_misc_fallback_script

        return build_misc_fallback_script(ctx)

    def _build_web_fallback_script(self, ctx: AgentContext) -> Optional[str]:
        # 上帝模块拆分：兜底脚本归 core/fallbacks
        from core.fallbacks import build_web_fallback_script

        return build_web_fallback_script(ctx)

    def _build_reverse_fallback_script(self, ctx: AgentContext) -> Optional[str]:
        # 上帝模块拆分：兜底脚本归 core/fallbacks
        from core.fallbacks import build_reverse_fallback_script

        return build_reverse_fallback_script(ctx)
