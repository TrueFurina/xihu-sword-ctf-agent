"""CTF-Agent 一键启动入口（CLI + Web + 平台 三入口）。

用法：
    python run.py --mode cli --category crypto     # CLI 解题模式
    python run.py --mode web                       # Web 看板模式（默认）
    python run.py --mode platform [--once]         # 平台对战：拉题→解题→提交
                                                   #   （需 DASCTF_BASE_URL + DASCTF_TOKEN）
    python run.py --mock                           # Mock 模式（无 API Key 可跑）
    python run.py --verify                         # 跑全部验证脚本
"""

from __future__ import annotations
from typing import Optional

import argparse
import asyncio
import logging
import os
import sys

# 全局解题步骤记录（模块级，供赛后报告生成——--compete/演练/run_platform 共用）
_solve_logs: dict = {}

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# 全局人工干预协调器（Web 面板与所有 solver 共享；初赛现场人工可实时介入卡壳题）
from core.intervention import InterventionCoordinator  # noqa: E402

_intervention = InterventionCoordinator()


def build_solver(use_mock: bool, is_correct=None, provider: Optional[str] = None,
                 model_override: Optional[str] = None, validate_locally: bool = True,
                 skip_presolve: bool = False, race_controller=None):
    """构建求解器（反馈循环 + 主 Agent + 监督）。

    Args:
        use_mock: 使用 Mock LLM（预置答案）还是真实 LLM
        is_correct: 可选正确性判定回调 callable(flag)->bool
                    （本地评测=与题库 flag 比对；比赛=平台 submit accepted）
        provider: 显式指定 LLM provider（deepseek/qwen/...）；None 时读环境变量
                  （多模型竞速时不同 solver 各传不同 provider）
        model_override: 显式模型名覆盖（百炼竞速：同 provider=qwen、不同 model）
        validate_locally: True 时 is_correct=None 会回落「与本地题库 flag 比对」；
                          False（平台单解模式）无本地 ground truth，仅做格式校验，
                          正确性由 poller 提交后 accepted 回流判定。P0-1 修复：
                          用显式开关取代 is_correct=lambda f: True 恒真判定。
        skip_presolve: True 时跳过确定性预扫（presolve），强制走主 Agent 全链路——
                      用于回归集饱和场景（真题集 14/15 被 presolve 直出，主 Agent 改进
                      测不到），构造「必须走主 Agent」的子集做 A/B 对比。

    Returns:
        solver callable(question, attempt, correction) -> AgentOutput dict
    """
    from eval.cases import load_questions, preset_answers

    questions = load_questions("data/questions")
    answers = preset_answers(questions)
    # 2026-08-24 真 flag 红线：id→Question 映射，供 sha256 占位题的正确性比对。
    _answers_q = {str(q.id): q for q in questions}

    if use_mock:
        # Mock 模式：直接走 mock_solve（可靠命中预置答案），绕过 LLM 链路
        from llm.mock import mock_solve, set_preset_answers

        set_preset_answers(answers)

        async def solver(question, attempt, correction=None):
            return mock_solve(question.id, question.to_prompt_text(), question.category)

        return solver

    # ── 真实 LLM 模式：1 主 1 监 + 工具层 + 校验闭环 ──
    from config import AppConfig
    from core.main_agent import MainAgent
    from core.supervisor_agent import SupervisorAgent
    from llm.client import ai_chat_json, get_model_for_attempt
    from scheduler.budget import BUDGET_STOP, BudgetExceeded, BudgetTracker
    from verify.feedback import FeedbackLoop
    from verify.flag_checker import FlagChecker

    _cfg = AppConfig.from_env()

    # 生效配置快照（2026-08-22 锐评第五节整改）：真实 LLM 模式启动即打印
    # provider/端点/模型/key 状态——防 BASE_URL/模型残留打错端点（初赛灾难根因）。
    try:
        from config import print_effective_config_snapshot

        print_effective_config_snapshot(provider=provider)
    except Exception:  # noqa: BLE001 - 快照失败不阻塞
        pass

    # ── 工具层（真实模式必须接入！否则主 Agent 无手无脚只能纯推理）──
    from sandbox.subprocess_executor import SubprocessExecutor
    from tools.registry import ToolRegistry
    from tools.adapters.file_analysis_adapter import FileAnalysisAdapter
    from tools.adapters.stego_adapter import StegoAdapter
    from tools.adapters.python_adapter import PythonAdapter
    from tools.adapters.hash_crack_adapter import HashCrackAdapter
    from tools.adapters.wordlist_crack_adapter import WordlistCrackAdapter
    from tools.adapters.web_request_adapter import WebRequestAdapter
    from tools.adapters.openssl_adapter import OpensslAdapter
    from tools.adapters.bkcrack_adapter import BkcrackAdapter
    from tools.adapters.xxe_adapter import XxeFileReadAdapter
    from tools.adapters.zip_chain_adapter import ZipChainDecodeAdapter
    from tools.adapters.deterministic_decode_adapter import DeterministicDecodeAdapter
    from tools.adapters.crypto_auto_adapter import CryptoAutoAdapter
    from tools.adapters.flag_scan_adapter import FlagScanAdapter
    from tools.skill_manager import SkillManager

    sandbox = SubprocessExecutor(default_timeout=_cfg.sandbox_timeout)
    registry = ToolRegistry()
    registry.register(FileAnalysisAdapter())
    registry.register(StegoAdapter())
    registry.register(PythonAdapter(sandbox=sandbox))
    registry.register(HashCrackAdapter())
    registry.register(WordlistCrackAdapter())
    registry.register(WebRequestAdapter())
    registry.register(OpensslAdapter(sandbox=sandbox))
    registry.register(BkcrackAdapter(sandbox=sandbox))   # zip 已知明文攻击（2026-08-22 整改 R1）
    registry.register(XxeFileReadAdapter())          # XXE 文件读取（web 上传题）
    registry.register(ZipChainDecodeAdapter())       # 多层 zip 文件名链解码（misc）
    registry.register(DeterministicDecodeAdapter())  # 确定性解码 fallback（P1-6：postmortem #3）
    registry.register(CryptoAutoAdapter(sandbox=sandbox))  # 确定性 crypto 嗅探/攻击一键直出（2026-08-21 攻坚）
    registry.register(FlagScanAdapter())                    # 确定性 flag 明文扫描（源码注释/HTML alert 类）
    # ── Skill 管理器：本地仓库发现 / 加载（/goal 动态能力拓展）──
    _skills_dir = os.path.join(_ROOT, "skills")
    skill_manager = SkillManager(skills_dir=_skills_dir, registry=registry)
    skill_manager.discover()
    for _sn in skill_manager.list_available():
        skill_manager.load(_sn)
    logger.info("真实模式工具层就绪: %s", registry.names())
    logger.info("本地 Skill 仓库就绪: 发现=%s 已加载=%s", skill_manager.list_available(), skill_manager.list_loaded())
    # 未实证 skill 汇总（2026-08-22 锐评第三节整改）：决赛前需找题验证或标占位
    _unverified = skill_manager.unverified_skills()
    if _unverified:
        logger.warning(
            "⚠️ %d 个 skill 从未在真题/测试赛实证（未上场）：%s\n"
            "   决赛前每个都要找题验证或明确标注占位——临场加载未验证 skill 会消耗墙钟",
            len(_unverified), ", ".join(_unverified),
        )

    # 预算熔断（v2.0 三级保护）
    budget = BudgetTracker()

    # ── 真实 token 记账（P1-1 修复 2026-08-21 赛后）──
    # 模块级 _LAST_USAGE 并发失真：多题并发互相覆盖，且只记最后一次调用。
    # 这里用 ContextVar 把"本任务本次 solve 的累计 usage"挂到当前 asyncio 任务
    # 上下文，llm_client 闭包每次调用累加（plan/reason/supervise 多次调用求和），
    # solve_once 结束后取累计值记入 budget——per-question 80000 预算基于真实数据。
    from contextvars import ContextVar

    _usage_cv: ContextVar = ContextVar("solve_usage", default=None)

    async def llm_client(system, user, attempt):
        from llm.client import ai_chat_json_async_with_usage

        model = model_override or get_model_for_attempt(attempt, provider)
        data, usage = await ai_chat_json_async_with_usage(
            [{"role": "user", "content": user}], system=system,
            model=model, provider=provider,
        )
        box = _usage_cv.get()
        if box is not None:
            box["prompt_tokens"] += int(usage.get("prompt_tokens") or 0)
            box["completion_tokens"] += int(usage.get("completion_tokens") or 0)
            box["total_tokens"] += int(usage.get("total_tokens") or 0)
            # 步级硬停（2026-08-28 Claim 1 超调整改）：已记账 + 本次 attempt 累计
            # ≥ 单题 cap → 立即抛 BudgetExceeded 终止该题（不再等 attempt 结束才
            # record/check，超调从「一整次 attempt」收敛到「单次 LLM 调用」）。
            _qid = box.get("question_id")
            if _qid:
                _used = budget.usage(_qid) + box["total_tokens"]
                if _used >= budget.config.per_question_token_budget:
                    raise BudgetExceeded(_qid, _used, budget.config.per_question_token_budget)
        return data

    checker = FlagChecker()
    agent = MainAgent(
        llm_client=llm_client,
        supervisor=SupervisorAgent(llm_client=llm_client),  # 监督也走同一 provider（修复多 provider 时监督打默认端点 402）
        checker=checker,
        registry=registry,   # ← 关键修复：接入工具层
        sandbox=sandbox,     # ← 关键修复：接入沙盒执行
        coordinator=_intervention,  # 人工干预协调（卡壳标记 + 提示注入闭环）
        skill_manager=skill_manager,  # ← /goal 动态 Skill 加载
        provider=provider,   # ← 报告与流量吻合（真实 provider 标签）
    )
    # 正确性判定：未显式传入时，本地题库评测默认与题库 flag 比对（防幻觉 flag 假阳性）；
    # 平台单解模式（validate_locally=False）无本地 ground truth，仅做格式校验
    # （P0-1 修复：正确性归 poller accepted 回流，不把「格式合法」伪装成「已校验正确」）
    if is_correct is None and answers and validate_locally:
        is_correct = lambda f: f in answers.values()  # noqa: E731
    loop = FeedbackLoop(checker=checker, is_correct=is_correct, race_controller=race_controller)

    async def solve_once(question, attempt, correction=None):
        """单次求解（走预算检查 + 主 Agent；由 FeedbackLoop 循环调用）。"""
        # 预算检查：超限直接返回终止（不发起 LLM 调用）
        status = budget.check(question.id)
        if status == BUDGET_STOP:
            return {
                "task_id": question.id,
                "question_type": question.category,
                "flag": None,
                "error": {"category": "budget_exceeded", "detail": "预算超限，终止该题"},
                "duration_ms": 0,
                "retries": attempt,
            }
        # 降级阈值：接近上限时强制轻量模型
        if status == "downgrade":
            attempt = 0
        budget.record_retry(question.id)
        hint = None
        if correction and correction.get("suggestion"):
            hint = correction["suggestion"]
        # P1-1 修复（2026-08-21 赛后）：真实 token 记账——本次 solve 内
        # plan/reason/supervise 多次 LLM 调用 usage 经 ContextVar 累计，
        # 结束后求和记入 budget（不再只记最后一次 / 不再依赖并发失真的全局 _LAST_USAGE）。
        _usage_box = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        _usage_box["question_id"] = question.id  # 步级硬停需要题号定位 budget.usage
        _usage_tok = _usage_cv.set(_usage_box)
        try:
            out = await agent.solve(question, attempt=attempt, hint=hint, correction=correction)
        finally:
            _usage_cv.reset(_usage_tok)
        # token 记账（P1-2 修复 2026-08-21）：优先用真实 usage 累计值，
        # 回退到长度估算（仅当无真实 usage 记录时）——让预算熔断基于真实数据。
        est = _usage_box["total_tokens"] or (len(str(hint or "")) // 4 + 200)
        budget.record(question.id, est)
        return out

    async def solver(question, attempt, correction=None):
        """对外求解器：通过 FeedbackLoop 执行，is_correct 正确性校验生效。"""
        # 攻坚② + P1-3 收敛（2026-08-21 赛后）：确定性预扫统一入口——
        # 原 fast_solve 关键词预检（仅 crypto/misc）收敛为 core.presolve.presolve，
        # 按序 flag_scan → crypto_auto → math_engine → 关键词 fast_solve，
        # 同一附件只嗅探一次（per-question 标记），命中即秒解优先。
        try:
            from core.presolve import presolve, presolve_candidates

            _pflag = None
            if not skip_presolve:
                _pflag = await presolve(question, registry=registry, sandbox=sandbox,
                                        answers=answers)
            if _pflag:
                # 2026-08-22 锐评「差最后一步」修复：presolve 多候选透传——
                # 提交迭代逐候选尝试，避免「解出但 flag 提取失败/单候选猜错」
                # 2026-08-24 诚实化：solver 层 presolve 直出，零 LLM，标记 solved_by=presolve
                return {"task_id": getattr(question, "id", ""),
                        "flag": _pflag, "validated": True,
                        "solved_by": "presolve",
                        "evidence": {"presolve": "unified", "engine": "presolve"},
                        "candidates": presolve_candidates(question) or [_pflag]}
        except Exception:  # noqa: BLE001 - 预检失败降级 LLM 推理
            pass
        out = await loop.run(question, solve_once, max_retries=_cfg.max_retries)
        # 精确校验：本地评测时 flag 必须匹配本题答案（防跨题误判，如 web-004 输出 web-010 的 flag）
        # 2026-08-24 真 flag 红线整改：答案可能是 sha256 占位，用 Question.flag_matches 统一比对。
        expected = answers.get(str(question.id)) if answers else None
        _expected_q = _answers_q.get(str(question.id)) if _answers_q else None
        if expected and out.get("flag"):
            _ok = _expected_q.flag_matches(out["flag"]) if _expected_q else (out["flag"] == expected)
            if not _ok:
                out["validated"] = False
                out["error"] = {"category": "hallucination",
                                "detail": "flag 不匹配本题答案（跨题误判）"}
        # 正确性兜底：未通过 is_correct 校验的 flag 一律视为未解出（防幻觉 flag 误判）
        if not out.get("validated"):
            # 复盘修复（misc-008/pwn-005 伪成功）：标记幻觉归因，便于报表统计『幻觉率』
            if out.get("flag"):
                err = out.get("error") or {}
                out["error"] = {
                    "category": "hallucination",
                    "detail": "模型输出 flag 但未通过正确性校验（疑似猜测/幻觉）",
                    **{k: v for k, v in err.items() if k not in ("category", "detail")},
                }
            out["flag"] = None
        return out

    # 暴露预算信息供看板/报表使用
    solver.budget = budget
    # 暴露工具注册表（P1 收敛 2026-08-21 赛后：race 第 0 号选手复用任一 provider
    # 的 registry 走 presolve 完整四引擎，避免直调 MathEngineMatrix 绕过去重）
    solver.registry = registry
    return solver


async def _auto_advisor(question, results: dict) -> str:
    """竞速失败后自动生成定向解题提示（对标 verialabs coordinator LLM）。

    收集各 provider 失败原因 → 用白名单 provider 轻量调用 LLM →
    生成 1 句下一步解题方向（供下一轮 attempt 注入为 advisor_hint）。
    失败/超时不阻塞主流程（返回空串）。
    """
    try:
        # 收集失败信息（题目描述 + 各 provider 的 error detail）
        fails = []
        for name, out in results.items():
            err = (out.get("error") or {})
            detail = str(err.get("detail") or err.get("category") or "无信息")
            obs = str(out.get("observation") or "")[:80]
            fails.append(f"[{name}] {detail} {obs}")
        fail_text = "\n".join(fails) or "全部无输出"

        desc = str(getattr(question, "description", ""))[:300]
        prompt = (
            f"CTF 题: {desc}\n多模型竞速失败信息:\n{fail_text}\n"
            "请给出 1 条最可能的下一步解题方向（简短，中文，30 字内，直接给建议不要解释）"
        )

        # P1-4 修复（2026-08-21）：走统一 LLM 封装 ai_chat，而非硬编码 httpx.post
        # 裸调。统一封装自带白名单校验 / 400 降级重试 / thinking 关闭 / fail-open /
        # 信号量限流。provider 主源 deepseek 优先，失败回落 baidu/mimo 免费源。
        from llm.client import ai_chat

        def _call(prov: str) -> str:
            text = ai_chat(
                [{"role": "user", "content": prompt}],
                model=None, provider=prov, max_tokens=80, temperature=0.3,
            )
            return (text or "").strip()

        for prov in ("deepseek", "baidu", "mimo"):
            try:
                text = await asyncio.to_thread(_call, prov)
                if text:
                    return text
            except Exception:  # noqa: BLE001 - 单 provider 失败继续下一个
                continue
    except Exception:  # noqa: BLE001 - advisor 失败不阻塞主流程
        pass
    return ""


def build_race_solver(use_mock: bool = False, is_correct=None,
                      providers=("baidu", "mimo", "deepseek"),
                      models=("qwen3.8-27b", "deepseek-v4-flash-0731",
                              "glm-5.2", "kimi-k2.7-code"),
                      tokenhub_models=("hy3", "deepseek-v4-pro", "deepseek-v4-flash",
                                       "glm-5.3", "kimi-k2.7-code"),
                      extra_models=None):
    """决赛多模型矩阵默认（12 模型同时开干）：providers（千帆 ernie-3.5 + MiMo +
    官方 DeepSeek） + models（百炼 4 个）+ tokenhub_models（腾讯 TokenHub 5 个主力，
    含 deepseek-v4-pro 免费重型；deepseek-v4-pro-0813 留重型 attempt≥2 升级用）。
    全部白名单合规；任一先得有效 flag 即终止其余，先得 flag 者胜。"""
    """构建多模型竞速求解器（抄 verialabs：多模型并发，先得有效 flag 者胜）。

    两种竞速模式：
    - providers 模式（默认）：同题并行跑多个 provider（需多个 Key）
    - models 模式（百炼同 Key）：同题并行跑多个模型（同端点同 Key，仅 model 不同）
      阿里云百炼一个 DASHSCOPE_API_KEY 通吃 deepseek/kimi/glm/qwen 全模型

    Args:
        use_mock: Mock 模式（不竞速，直接 mock）
        is_correct: 正确性判定回调
        providers: 参与竞速的 provider 列表（默认 baidu 主 + mimo 备选）
        models: 参与竞速的模型名列表（同 provider 竞速；非空时 providers 被忽略）

    Returns:
        solver callable(question, attempt, correction) -> AgentOutput dict
    """
    if use_mock:
        return build_solver(use_mock=True, is_correct=is_correct)

    import asyncio

    # P0-1 修复（2026-08-21）：平台题竞速不再用 `is_correct = lambda f: True` 全放行。
    # 平台 submit_flag 的 accepted 才是正确性权威，本地题库答案会误伤 DASCTF{} 等
    # 平台 flag。因此平台模式下 is_correct 保持 None → FeedbackLoop 仅做格式校验，
    # validated 只代表"格式合法候选"，正确性由 poller 提交后 accepted 回流判定。
    # 绝不把"格式合法"伪装成"已校验正确"（原 lambda f:True 正是这个谎言）。
    if is_correct is None:
        pass  # 保持 None：正确性归 poller accepted 回流，竞速层只做格式闸门

    solvers = {}
    if models:
        # 百炼多模型：同 qwen provider、同 DASHSCOPE_API_KEY、不同 model 竞速
        for m in models:
            solvers[f"qwen:{m}"] = build_solver(
                use_mock=False, is_correct=is_correct, provider="qwen", model_override=m)
    for name in providers:
        if name == "qwen":
            continue  # 已由 models 覆盖
        solvers[name] = build_solver(use_mock=False, is_correct=is_correct, provider=name)
    for m in tokenhub_models:
        solvers[f"tokenhub:{m}"] = build_solver(
            use_mock=False, is_correct=is_correct, provider="tokenhub", model_override=m)
    if extra_models is None:
        extra_models = (("glm", "glm-4.7"), ("ark", "doubao-seed-2-1-pro-260628"),
                        ("moonshot", "kimi-k2.6"), ("xfyun", "lite"))
    for prov, m in extra_models:
        solvers[f"{prov}:{m}"] = build_solver(
            use_mock=False, is_correct=is_correct, provider=prov, model_override=m)
    primary = list(solvers.keys())[0]

    async def race(question, attempt=0, correction=None):
        """并发执行多个 provider 的 solver，先得有效 flag 者胜。

        双矩阵竞速（2026-08-21 攻坚）：数学引擎矩阵（确定性秒解）作为第 0 号
        选手先行——LLM 矩阵识别题型/写代码，数学引擎真算（RSA 变种/编码/LFSR/
        二次剩余/静态分析）；任一先得有效 flag 即胜。数学引擎命中直接返回，
        省掉整个 LLM 推理链路（8/9 真库题中 5+ 类由数学引擎秒解）。
        """
        # ── 第 0 号选手：确定性预扫统一入口（P1-3 收敛 + 赛后 P1 去重）──
        # 此前直调 MathEngineMatrix.solve 绕过 presolve 的 per-question 去重标记，
        # race 模式下 math_engine 会被嗅探 2 次（0 号一次 + 首个 provider presolve 一次）。
        # 现在改走 core.presolve：复用任一 provider 的 registry（flag_scan/crypto_auto
        # 适配器与 provider 无关），让 race 级预扫覆盖完整四引擎并打标记，
        # provider solver 的 presolve 因标记直接跳过——同一附件只嗅探 1 次。
        try:
            from core.presolve import presolve

            _reg0 = None
            for _s in solvers.values():
                _reg0 = getattr(_s, "registry", None)
                if _reg0 is not None:
                    break
            _mflag = await presolve(question, registry=_reg0, sandbox=None, answers=None)
            if _mflag:
                # P0-1 修复（2026-08-21）：确定性命中必须过 is_correct 校验。
                # 此前硬编码 validated=True + confidence=1.0 直接 return，确定性
                # 攻击链算错（如 RSA 变种/编码分支判错）也被当真，且跳过 LLM 竞速。
                # 本地评测模式（is_correct 非 None）比对不通过即丢弃，改用 LLM。
                if is_correct is not None:
                    try:
                        if not bool(is_correct(_mflag)):
                            logger.warning(
                                "[%s] 预扫 flag 未过正确性校验，丢弃: %s",
                                question.id, _mflag[:40])
                            _mflag = None
                    except Exception:  # noqa: BLE001 - 校验回调异常视为不通过
                        _mflag = None
                if _mflag:
                    logger.info("[%s] 确定性预扫命中 flag=%s（跳过 LLM 竞速）",
                                question.id, _mflag)
                    return {
                        "task_id": question.id,
                        "question_type": getattr(question, "category", ""),
                        "flag": _mflag,
                        "validated": True,
                        "confidence": 1.0,
                        "error": None,
                        "provider": "presolve",
                        "retries": 0,
                        "steps": [{"stage": "exploit", "action": "presolve",
                                   "observation": f"确定性求解命中: {_mflag}"}],
                        "task_status": "solved",
                    }
        except Exception as exc:  # noqa: BLE001 - 预扫故障不阻塞 LLM 竞速
            logger.warning("[%s] 确定性预扫异常（继续 LLM 竞速）: %s", question.id, exc)

        # ── LLM 竞速整体墙钟（2026-08-21 攻坚）：数学引擎未命中后，LLM 矩阵
        #    最多跑 race_wallclock 秒即放弃换题——3h 赛制下 487s 死磕一道题是灾难
        #    （specialcurve2 实测 487s 深推理仍未解出）。默认 300s 可被 env 覆盖。
        #    P0修复（2026-08-21）：默认150s太短，中难题深推理不够用，调至300s
        import os as _os
        _race_wc = float(_os.getenv("CTF_AGENT_RACE_WALLCLOCK", "300"))

        async def _race_with_wallclock(tasks: dict):
            # P0 熔断过滤（2026-08-21 赛后落地）：solver 名形如 "moonshot:kimi-k2.6" /
            # "deepseek" / "qwen:qwen3.8-max"，首段即 provider。已熔断（401/402/403
            # 连续达阈值）的源直接剔除，避免坏源空转拖慢竞速、把墙钟烧在死路上。
            from llm.client import provider_circuit_open
            live_solvers = {
                name: solver for name, solver in solvers.items()
                if not provider_circuit_open(name.split(":")[0])
            }
            if not live_solvers:
                logger.warning("[%s] 全部 LLM provider 已熔断——竞速无可用源", question.id)
                live_solvers = solvers  # 兜底：仍尝试原池（避免 0 选手）
            tasks.update({
                name: asyncio.create_task(solver(question, attempt, correction))
                for name, solver in live_solvers.items()
            })
            name_of = {t: n for n, t in tasks.items()}
            pending = set(tasks.values())
            results = {}
            votes: dict[str, list] = {}  # flag -> 各 solver 的完整结果列表
            # P0-1 修复（2026-08-21）：竞速收敛从"首个 validated 即 cancel 全部"
            # 改为"多数票互证才立即胜出"。旧逻辑删掉 `or True` 后仍是谁先到谁赢——
            # 因为 build_solver 尾部保证 flag 非 None ⟹ validated=True，单票即胜
            # 就是"谁先编（或谁先格式合法）谁赢"。现在：单票只入票池等待，
            # 两票及以上一致（多个独立模型同解）幻觉概率极低，才立即胜出抢一血。
            while pending:
                finished, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for task in finished:
                    name = name_of[task]
                    try:
                        out = task.result()
                    except Exception as exc:  # noqa: BLE001 - 单 provider 异常不拖垮竞速
                        logger.warning("[%s] 竞速 %s 异常: %s", question.id, name, exc)
                        continue
                    results[name] = out
                    flag = out.get("flag")
                    if flag and out.get("validated"):
                        votes.setdefault(flag, []).append(out)
                        # 两票互证：立即胜出（不必等墙钟，抢一血窗口）
                        if len(votes[flag]) >= 2:
                            for t in pending:
                                t.cancel()
                            # P0修复（2026-08-21）：等待所有任务真正退出，避免子进程/HTTP连接泄漏
                            await asyncio.gather(*pending, return_exceptions=True)
                            winner = dict(votes[flag][0])
                            winner["flag"] = flag
                            winner["race_votes"] = len(votes[flag])
                            winner["race_consensus"] = flag
                            logger.info("[%s] 竞速两票一致胜出: %s (%d票)",
                                        question.id, flag, len(votes[flag]))
                            return winner
            # 墙钟/全部完成：无两票互证，返回最高票（单票兜底，不浪费已解 flag）
            if votes:
                best_flag = max(votes, key=lambda f: len(votes[f]))
                winner = dict(votes[best_flag][0])
                winner["flag"] = best_flag
                winner["race_votes"] = len(votes[best_flag])
                winner["race_consensus"] = best_flag
                logger.info("[%s] 竞速墙钟兜底返回最高票: %s (%d票)",
                            question.id, best_flag, len(votes[best_flag]))
                return winner
            # 无 validated flag：返回主 solver 结果；否则竞速失败 + 自动生成定向提示
            if primary in results:
                return results[primary]
            hint = await _auto_advisor(question, results)
            return {
                "task_id": question.id, "flag": None,
                "error": {"category": "race_all_failed", "detail": "多模型竞速均未解出",
                          "advisor_hint": hint or ""},
            }

        # P0-2 修复（2026-08-21 赛后）：墙钟超时/取消时 finally 取消全部
        # in-flight solver tasks 并等待退出——此前 wait_for 超时只取消外层协程，
        # 12 路 solver 继续后台空转烧 API 额度/挂子进程（正式赛 deepseek 402 前
        # "数小时空转"即此类资源黑洞）。subprocess 层已补 CancelledError 杀进程。
        _tasks: dict = {}

        async def _cancel_all() -> None:
            if not _tasks:
                return
            for _t in _tasks.values():
                if not _t.done():
                    _t.cancel()
            await asyncio.gather(*_tasks.values(), return_exceptions=True)

        try:
            return await asyncio.wait_for(_race_with_wallclock(_tasks), timeout=_race_wc)
        except asyncio.TimeoutError:
            await _cancel_all()
            logger.warning("[%s] LLM 竞速墙钟超时（%.0fs），放弃换题",
                           question.id, _race_wc)
            return {
                "task_id": question.id, "flag": None,
                "error": {"category": "wallclock_timeout",
                          "detail": f"LLM 竞速超过 {_race_wc:.0f}s 未解出，止损换题"},
            }
        except asyncio.CancelledError:
            await _cancel_all()
            raise
        finally:
            # 其余路径兜底：任何残留 in-flight 任务一律取消并等待退出，绝不泄漏
            await _cancel_all()

    return race


def run_cli(use_mock: bool, category: str | None = None) -> None:
    """CLI 解题模式：加载题库并发求解并打印报表。"""
    from eval.cases import load_questions
    from scheduler.task_pool import TaskPool

    questions = load_questions("data/questions")
    if category:
        questions = [q for q in questions if q.category == category]
    # 锐评整改（2026-08-22）：先易后难排序——简单题（crypto/misc EASY）优先拿分，
    # 治正式赛 CRYPTO-01 埋头难题 3h 0 解出。race_strategy.plan_challenges 在此接线。
    try:
        from core.race_strategy import plan_challenges
        questions = plan_challenges(questions)
    except Exception:
        pass
    if not questions:
        logger.warning("题库为空，请检查 data/questions/")
        return

    solver = build_solver(use_mock)
    pool = TaskPool()
    results = asyncio.run(pool.run_all(questions, solver))

    print("\n=== 解题结果 ===")
    solved = 0
    for q, out in zip(questions, results):
        flag = out.get("flag")
        ok = bool(flag)
        solved += 1 if ok else 0
        print(f"  [{'✓' if ok else '✗'}] {q.id:16s} {q.category:6s} "
              f"{flag or (out.get('error') or {}).get('detail', '未解出')}")

    print(f"\n解出率: {solved}/{len(questions)} = {solved / len(questions):.1%}")


def run_web(use_mock: bool) -> None:
    """Web 看板模式：启动 FastAPI 服务。"""
    import uvicorn
    from web.server import configure

    solver = build_solver(use_mock)

    def question_loader():
        from eval.cases import load_questions
        qs = load_questions("data/questions")
        # 锐评整改（2026-08-22）：先易后难排序（race_strategy.plan_challenges 接线）
        try:
            from core.race_strategy import plan_challenges
            qs = plan_challenges(qs)
        except Exception:
            pass
        return qs

    configure(solver_fn=solver, question_loader=question_loader,
              coordinator=_intervention, use_mock=use_mock)
    print("看板已启动: http://127.0.0.1:8000  （Ctrl+C 退出）")
    uvicorn.run("web.server:app", host="127.0.0.1", port=8000, log_level="info")


def build_platform_solver(platform, use_mock: bool = False, cache_dir: str = "data/platform_downloads",
                          core_solver=None, race_controller=None):
    """构造平台求解器：ChallengeInfo → Question（下载附件+注入靶机访问信息）→ 本地核心 solver。

    Args:
        platform: DasCTFPlatform 实例（下载附件用）
        use_mock: Mock 模式（core_solver 未注入时生效）
        cache_dir: 附件本地缓存目录（相对 ctf_agent/）
        core_solver: 可注入自定义核心 solver callable(question, attempt, correction)
                     （测试/竞速模式用）

    Returns:
        solver callable(ChallengeInfo) -> dict（供 PlatformPoller 使用）
    """
    import os
    from eval.cases import Question

    # 平台题：禁用本地正确性校验（平台 submit 的 accepted 才是权威，本地题库答案会误伤 DASCTF{}）。
    # P0-1 修复：原 is_correct=(lambda f: True) 恒真判定 → validate_locally=False（无本地
    # ground truth，仅格式校验；正确性由 poller 提交后 accepted 回流判定，不再把幻觉 flag 当真提交）。
    core = core_solver or build_solver(use_mock, validate_locally=False, race_controller=race_controller)
    os.makedirs(cache_dir, exist_ok=True)

    async def _download(url: str) -> str:
        """下载平台附件到本地缓存，返回本地路径（失败返回空串）。"""
        from urllib.parse import urlparse

        try:
            name = os.path.basename(urlparse(url).path) or f"att_{abs(hash(url))}.bin"
            local = os.path.join(cache_dir, name)
            if os.path.exists(local) and os.path.getsize(local) > 0:
                return local
            # P0修复（2026-08-21）：复用平台客户端下载（自动带鉴权头，避免403）
            if hasattr(platform, "download_attachment_bytes"):
                content = await platform.download_attachment_bytes(url)
            else:
                import httpx
                async with httpx.AsyncClient(timeout=60, follow_redirects=True, trust_env=False) as client:
                    headers = {}
                    token = getattr(platform, "token", "")
                    auth_header = getattr(platform, "auth_header", "Authorization")
                    if token:
                        headers[auth_header] = token
                    resp = await client.get(url, headers=headers)
                    if resp.status_code != 200:
                        raise RuntimeError(f"HTTP {resp.status_code}")
                    content = resp.content
            if content:
                with open(local, "wb") as fh:
                    fh.write(content)
                logger.info("附件已下载: %s (%d B)", name, len(content))
                return local
        except Exception as exc:  # noqa: BLE001 - 附件下载失败不阻塞解题
            logger.warning("附件下载失败 %s: %s", url, exc)
        return ""

    async def solver(ch) -> dict:
        """平台题 → 本地 Question → 核心求解 → 返回含 flag 的 dict。"""
        # ── P0① 双保险（2026-08-21 赛中）：solver 入口无条件补全详情 ──
        #    列表接口仅返回 {id,name,order,isOpen,hasSolved}，无 endpoints/attachment；
        #    竞速抢一血路径走 _to_question 不经 poller，ch.extra 缺 endpoints →
        #    靶机永不注入 → supervisor 误判"题目缺少附件或靶机地址" → 死循环 0 解出。
        #    此处 solver 入口自行 get_challenge 补全，确保任意入口都拿到真实靶机/附件/题面。
        try:
            _detail = await platform.get_challenge(ch.id)
            # P0-④（2026-08-21 赛后）：429 限流下 get_challenge 可能返回空 ChallengeInfo
            # （detail 拉取失败）。再重试一次（利用 5 分钟缓存命中或限流窗口过去），
            # 仍失败才标记 _detail_fetch_failed 交由下游止损，避免一枪毙命式空转。
            if _detail is None or not getattr(_detail, "extra", None):
                await asyncio.sleep(2.0)
                _detail = await platform.get_challenge(ch.id)
            if _detail is not None:
                _dextra = dict(getattr(_detail, "extra", None) or {})
                _cextra = dict(getattr(ch, "extra", None) or {})
                for _k in ("endpoints", "attachment", "attachments", "difficulty", "description", "score", "flag_format"):
                    if _dextra.get(_k) is not None:
                        _cextra[_k] = _dextra[_k]
                ch.extra = _cextra
                # 同步布尔属性（关键：list 阶段这两个字段恒 False，必须从 detail 更新）
                if getattr(_detail, "has_attachment", False):
                    ch.has_attachment = True
                if getattr(_detail, "has_instance", False):
                    ch.has_instance = True
                # P0 数据链路修复（2026-08-21）：详情 description 权威覆盖——
                # _parse_challenge 可能已把标题兜底进 ch.description（非空），
                # 若仍只按"为空才填"则真实题面永远合并不进去（0 解出回归）。
                _dd = getattr(_detail, "description", "") or ""
                if _dd and _dd != getattr(ch, "title", ""):
                    ch.description = _dd
                if not getattr(ch, "flag_format", "") and getattr(_detail, "flag_format", ""):
                    ch.flag_format = _detail.flag_format
        except Exception as _e:  # noqa: BLE001 - 补全失败不阻塞解题
            logger.warning("[%s] solver 入口 get_challenge 补全失败: %s", ch.id, _e)
            # P0-④（2026-08-21 赛后）：补全失败（多为 429 限流导致 detail 拉取失败）
            # 标记无数据，下游 main_agent 据此快速止损，不再空转烧墙钟。
            ch.extra = dict(getattr(ch, "extra", None) or {})
            # P0 数据链路修复（2026-08-21）：仅当 ch 确实无任何真实数据时才标记
            # _detail_fetch_failed——若已有 endpoints/attachment/题面（来自 poller
            # 或前一帧），不得用"拉详情失败"覆盖成无数据，否则真实题被误杀。
            _has_real = bool(
                ch.extra.get("endpoints")
                or ch.extra.get("attachment") or ch.extra.get("attachments")
                or getattr(ch, "description", "")
            )
            if not _has_real:
                ch.extra["_detail_fetch_failed"] = True
        question = Question(
            id=ch.id,
            title=ch.title,
            category=ch.category,
            description=str(ch.description or ""),
            flag_pattern=getattr(ch, "flag_format", None) or r"flag\{[^}]+\}",
            # O1 联动（2026-08-21 P0-2 修复）：平台难度写入 Question.difficulty 字段
            # （main_agent 统一读 question.difficulty；空串而非省略，避免落默认 "easy"
            #  导致全题误判 120s 墙钟；未知难度回落 300s MEDIUM）。
            difficulty=str((ch.extra or {}).get("difficulty", "")),
            # 平台附加元信息（access 靶机访问等）仍经 extra 透传
            extra={"difficulty": (ch.extra or {}).get("difficulty", ""),
                   "platform_meta": (ch.extra or {})},
        )
        # 附件下载（平台 URL → 本地缓存；失败不阻塞）
        if ch.has_attachment:
            urls = await platform.download_attachment(ch.id)
            local_paths = []
            for u in urls:
                p = await _download(str(u))
                if p:
                    local_paths.append(p)
            question.attachments = local_paths
            if local_paths:
                logger.info("[%s] 附件就绪: %s", ch.id, local_paths)
        # 靶机访问信息注入描述（web/pwn 需要真实地址）
        access = (ch.extra or {}).get("access") if hasattr(ch, "extra") else None
        if access:
            host = access.get("host") or ""
            port = access.get("port") or 0
            url = access.get("url") or ""
            if host or url:
                question.description = (
                    f"{question.description}\n\n[靶机访问] host={host} port={port} url={url}"
                )
        # ── P0 修复（2026-08-21 正式赛）：endpoints 靶机地址注入——
        #    列表接口无 endpoints，get_challenge 详情才有（poller 已补全到 ch.extra）。
        #    复用 _scan_firstblood._extract_targets 解析 portMappings/proxyIps →
        #    拼进 description（LLM 提示词可见）+ question.extra["targets"]（工具层可用）。
        try:
            from scripts._scan_firstblood import _extract_targets

            _targets = _extract_targets(ch.extra or {})
            if _targets:
                question.extra["targets"] = _targets
                if "靶机" not in question.description:
                    question.description = (
                        (question.description + "\n" if question.description else "")
                        + "靶机地址: " + " ".join(_targets)
                    )
        except Exception as _texc:  # noqa: BLE001 - 靶机注入失败不阻塞
            logger.warning("[%s] 靶机地址注入跳过: %s", ch.id, _texc)
        return await core(question, 0, None)

    return solver


def run_platform(use_mock: bool, once: bool = False, interval: float = 30.0) -> None:
    """平台对战模式：拉官方赛题 → 自动解题 → 提交 flag（测试赛/初赛主战场）。

    环境变量：DASCTF_BASE_URL（平台地址）、DASCTF_TOKEN（鉴权 Token）
    用法：python run.py --mode platform [--once] [--interval 30]
    """
    import asyncio
    from ctfplatform.dasctf import DasCTFPlatform
    from ctfplatform.poller import PlatformPoller

    platform = DasCTFPlatform()
    if not platform.base_url or not platform.token:
        print("⚠️  需要设置环境变量：DASCTF_BASE_URL + DASCTF_TOKEN")
        print("    （测试赛/初赛平台地址与 Token 见官方通知）")
        return

    # 全局解题步骤记录（赛后生成报告，与流量日志吻合——手册第 8 条）
    # _solve_logs 为模块级全局（本函数写入，报告生成处读取）
    global _solve_logs
    # race-intelligence 接入（2026-08-29 换题决策完整化）：控制器同时喂给 solver 层
    # （FeedbackLoop 换题钩子）与 poller 层（plan 分配）。缺失/异常 → fail-open。
    race_controller = None
    try:
        from core.race_orchestrator import RaceController
        race_controller = RaceController()
    except Exception as exc:  # noqa: BLE001 - 控制器不可用不阻塞对战
        print(f"ℹ️ race-intelligence 控制器不可用（{exc}），降级硬编码调度")
    _core_solver = build_platform_solver(platform=platform, use_mock=use_mock,
                                         race_controller=race_controller)

    async def _solve_with_log(ch) -> dict:
        out = await _core_solver(ch)
        steps = out.get("steps") or []
        if steps:
            _solve_logs[str(getattr(ch, "id", ""))] = [
                {"stage": s.get("stage", ""), "action": s.get("action", ""),
                 "observation": s.get("observation", ""), "tool_used": s.get("tool_used", "")}
                for s in steps
            ]
        return out

    poller = PlatformPoller(platform=platform, solver=_solve_with_log,
                            race_controller=race_controller)

    if once:
        print(f"平台模式：拉题→解题→提交（单轮） @ {platform.base_url}")
        records = asyncio.run(poller.run_once())
    else:
        print(f"平台模式：定时轮询（间隔 {interval:.0f}s，Ctrl+C 退出） @ {platform.base_url}")
        records = asyncio.run(poller.run_forever(interval))

    # 打印本轮报表
    summary = poller.summary()
    print(f"\n=== 平台对战汇总 ===")
    print(f"处理 {summary['processed']} 题 | 解出 {summary['solved']} | 提交成功 {summary['accepted']} | 失败 {summary['failed']}")
    for rec in poller.records():
        mark = "✅" if rec["accepted"] else ("🔑" if rec["flag"] else "❌")
        print(f"  {mark} [{rec['challenge_id']}] {rec['title']} "
              f"flag={rec['flag'] or '—'} detail={rec['detail'] or rec['error'] or ''}")

    # 赛后生成解题报告（手册第 8 条：必须提交且与流量日志吻合）
    try:
        from report.generator import generate_report, save_report
        md = generate_report(poller_records=poller.records(), solve_logs=_solve_logs)
        path = save_report(md)
        print(f"\n📋 解题报告已生成: {path}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("解题报告生成失败: %s", exc)
    return records


def run_verify() -> None:
    """运行全部验证脚本。"""
    import subprocess

    scripts = ["scripts/_verify_failopen.py", "scripts/_verify_stage2.py", "scripts/_verify_stage3.py"]
    for s in scripts:
        print(f"\n=== 运行 {s} ===")
        r = subprocess.run([sys.executable, s], cwd=_ROOT)
        if r.returncode != 0:
            logger.error("验证失败: %s", s)
            sys.exit(r.returncode)
    print("\n全部验证通过 ✅")


def main() -> None:
    parser = argparse.ArgumentParser(description="CTF-Agent 一键启动")
    parser.add_argument("--mode", choices=["cli", "web", "verify", "platform"], default="web")
    parser.add_argument("--category", default=None, help="CLI 模式题型过滤")
    parser.add_argument("--mock", action="store_true", help="Mock 模式（无需 API Key）")
    parser.add_argument("--once", action="store_true", help="平台模式只跑一轮（不轮询）")
    parser.add_argument("--interval", type=float, default=30.0, help="平台模式轮询间隔秒数")
    args = parser.parse_args()

    if args.mode == "verify":
        run_verify()
    elif args.mode == "cli":
        run_cli(use_mock=args.mock, category=args.category)
    elif args.mode == "platform":
        run_platform(use_mock=args.mock, once=args.once, interval=args.interval)
    else:
        run_web(use_mock=args.mock)


if __name__ == "__main__":
    main()
