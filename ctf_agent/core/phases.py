"""Plan-Act-Observe 阶段实现（2026-08-21 锐评 P1 拆分：从 main_agent 上帝模块迁出）。

把 _plan/_act/_observe/_supervise/_extract_flag 五个阶段方法迁到本模块，
main_agent 只保留 solve() 主循环编排 + _finalize 契约生成。

迁出原则：行为完全不变，只改归属。所有方法以 agent 实例为第一参数（bound 风格），
便于访问 agent 的依赖（llm_client/registry/sandbox/checker/supervisor/skill_manager）。
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from core.main_agent import (
    AgentContext,
    StepRecord,
    SupervisionVerdict,
    STAGE_RECON,
    STAGE_EXPLOIT,
    ERR_STUCK_LOOP,
    ERR_HALLUCINATION,
    ERR_TOOL_FAILURE,
    VERDICT_CONTINUE,
    VERDICT_UPGRADE,
    GOAL_SYSTEM_PROMPT,
)

logger = logging.getLogger(__name__)


async def plan_step(agent, ctx: AgentContext, attempt: int) -> dict:
    """生成下一步行动计划（JSON）。原 MainAgent._plan。"""
    last = ctx.last_step()

    # ── web 题首步强制发包（2026-08-23 修复：web 0/10 根因）──
    # 题库 web 题含靶机地址（http://127.0.0.1:9001/...），但 LLM 倾向首步 reason 空转，
    # 触发 main_agent 同参数重复止损 → web 全 0 分。此处确定性强制：web 题首步若尚未
    # 发过 http_request，直接返回发包 plan，绕过 LLM 的 reason 倾向。
    _cat = str(getattr(ctx.question, "category", "")).lower()
    _qdesc = str(getattr(ctx.question, "description", "") or "")
    _has_target = any(k in _qdesc for k in
                      ("http://", "https://", "靶机", "host:", "url:", "端口", "endpoint"))
    _sent_http = any(getattr(s, "tool_used", "") == "http_request" for s in ctx.steps)
    if _cat == "web" and _has_target and not _sent_http:
        # 从题面抽取靶机 URL（首个 http(s):// 链接）
        _m = re.search(r"https?://[^\s，。、）)]+", _qdesc)
        _url = _m.group(0) if _m else "http://127.0.0.1:9001/"
        logger.info("[%s] web 首步强制 http_request 发包: %s", getattr(ctx.question, "id", "?"), _url)
        return {"action": "tool", "tool": "http_request", "detail": f"访问靶机 {_url} 分析响应",
                "target_url": _url, "stage": STAGE_RECON, "done": False,
                "_forced_web_probe": True}

    has_attachment = bool(getattr(ctx.question, "attachments", None))
    attachment_hint = ""
    if has_attachment:
        _atts = list(getattr(ctx.question, "attachments", None) or [])
        _seen = getattr(ctx, "_attachments_seen", None) or set()
        _unseen = [str(a) for a in _atts if str(a) not in _seen]
        if _unseen:
            # 多附件完整性（2026-08-21 攻坚修复）：列出未读附件清单，强制遍历
            attachment_hint = (
                "⚠️ 题目有多个附件文件，以下附件尚未分析，必须先用 file_analyze 逐个读取：\n"
                + "\n".join(f"  - {p}" for p in _unseen)
                + "\n输出 {\"action\": \"tool\", \"tool\": \"file_analyze\", "
                '"detail": "读取全部附件", "stage": "recon", "done": false}，'
                "file_analyze 会一次性分析所有未读附件。"
            )
        elif not ctx._attachment_analyzed:
            attachment_hint = (
                "题目提供了附件文件！第一步必须先用工具读取附件："
                '输出 {"action": "tool", "tool": "file_analyze", '
                '"detail": "读取附件并提取 flag/关键信息", "stage": "recon", "done": false}。'
            )
        else:
            attachment_hint = (
                "附件已分析过，接下来根据附件内容决定："
                "需要计算/解密用 script 执行 Python，需要网络请求用 tool:http_request。"
            )

    crypto_param_hint = ""
    if getattr(ctx.question, "category", "") == "crypto":
        recent_obs = ""
        for s in reversed(ctx.steps[-3:]):
            if s.observation:
                recent_obs = s.observation
                break
        if any(k in recent_obs for k in (
            "n =", "e =", "c =", "n=", "e=", "c=",
            "N =", "E =", "C =", "N=", "E=", "C=",
            "# n", "# e", "# c", "# N", "# E", "# C",
            "密文", "cipher", "明文", "加密参数", "密钥", "私钥", "公钥",
            "key:", "key=", "iv =", "iv=", "mod =", "mod=", "ct =", "ct=",
            "p =", "q =", "d =", "p=", "q=", "d=", "g =", "y =", "x =",
            "S-box", "sbox", "nonce", "enc =", "flag enc", "enc_flag",
            "flag_enc", "result =", "output =", "primes =", "prime",
            "0x")):
            crypto_param_hint = (
                "⚠️ 已从附件/输出中识别到加密参数（n/e/c/密文/密钥等，含注释行/换行分隔形式）！"
                "下一步必须输出 script 动作执行 Python 计算/解密脚本，"
                '格式: {"action": "script", "code": "python: <完整可运行 Python 代码>", "stage": "exploit", "done": false}。'
                "⚠️ code 必须以 python: 前缀开头，否则沙盒走 bash 执行会报 WSL 错误！"
                "不要只做文字推理，必须实际运行代码得到结果；"
                "若 1 步内未输出 script，视为推理空转（复盘修复：crypto-004 155s 空转）。"
            )

    system = (
        GOAL_SYSTEM_PROMPT
        + "\n你是资深 CTF 选手。根据题目信息与已执行步骤，决定下一步行动。"
        "优先选择能获得真实证据的动作："
        "tool=调用工具（file_analyze 读附件/http_request 发包/python 跑脚本/deterministic_decode 确定性解码）; "
        "script=执行 Python 脚本（计算/解密/爆破）; reason=纯推理分析; "
        '输出 JSON: {"action": "reason|tool|script|flag", "detail": "...", '
        '"stage": "recon|exploit|flag_extract", "done": false}。'
        '若已能确定 flag，输出 {"action": "flag", "done": true, "flag": "..."}。'
        "禁止猜测或凭直觉输出 flag。flag 必须来自：①工具/脚本的实际输出，"
        "②附件内容的直接提取，③数学计算的确定性结果；"
        "任何未经验证的 flag 一律视为未解出，继续取证（赛后复盘修复：misc-008/pwn-005 伪成功）。"
        "【web 题】若题目提供靶机地址（host/port/url），第一步必须用 tool:http_request "
        "访问目标并分析响应（含源码/robots/备份文件探测）；"
        "若未提供靶机且无附件（本地评测环境），明确当前无靶机，直接走 web_toolkit "
        "模板判断题型并输出可复现 payload，禁止纯推理空转（复盘修复：本地 web 0/6 空转）。"
        "若常规推理/工具均失败、连续 stuck_loop 或附件编码不明，必须调用 tool:deterministic_decode "
        "自动尝试多策略解码（base64/hex/morse/ROT13/zip链/DNS隧道/RAID0）；"
        "【重要】只输出一个 JSON 对象，禁止输出 JSON 以外的任何文字、"
        "前言、解释、代码围栏或 Markdown 标记，严格以 { 开头以 } 结尾。"
    )
    try:
        from agents.templates import TemplateBank
        flow = TemplateBank().standard_flow(str(getattr(ctx.question, "category", "")))
        if flow:
            system += "\n【题型标准流程参考】\n" + "\n".join(flow)
    except Exception:  # noqa: BLE001
        pass
    if crypto_param_hint:
        system = crypto_param_hint + "\n" + system
    elif attachment_hint:
        system = attachment_hint + "\n" + system
    # 2026-09-01 P1 反幻觉实算强制：猜 flag 被丢弃后，下一 plan 必须真实计算
    if getattr(ctx, "_anti_hallucination", False):
        _cat = str(getattr(getattr(ctx, "question", None), "category", "") or "").lower()
        if _cat == "crypto":
            system += (
                "\n【反幻觉·强制实算】你前几步提交的 flag 不在任何工具/脚本输出中，"
                "已被系统判定为幻觉并丢弃。绝对禁止再凭空猜 flag。下一步必须输出 "
                'action=script，写一段可运行 Python（pycryptodome 等）读取附件中的 '
                "key/IV/mode 等参数，对密文做真实 AES/RSA/编码解密或数论求解，"
                "把脚本运行得到的真实结果作为 flag 提交。"
            )
        else:
            system += (
                "\n【反幻觉·强制实算】你前几步提交的 flag 不在任何工具/脚本输出中，"
                "已被系统判定为幻觉并丢弃。绝对禁止再凭空猜 flag。下一步必须输出 "
                "action=script 或 tool，真实执行计算/解码/利用，"
                "把运行得到的真实结果作为 flag 提交。"
            )
    user = agent._build_plan_prompt(ctx, attempt)
    result = await agent._llm_json(system, user, attempt, recover_script=True)
    if not result:
        if has_attachment and not ctx._attachment_analyzed:
            return {"action": "tool", "tool": "file_analyze",
                    "detail": "读取附件", "stage": STAGE_RECON, "done": False}
        return {"action": "reason", "detail": "继续分析", "stage": STAGE_RECON, "done": False}
    return result


async def act_step(agent, ctx: AgentContext, plan: dict, attempt: int) -> dict:
    """执行一步：推理 / 调工具 / 跑脚本。原 MainAgent._act。"""
    action = plan.get("action", "reason")
    detail = str(plan.get("detail", ""))

    # ── crypto 确定性攻击链优先（2026-08-21 攻坚修复）──
    # 附件分析完成后，任何 script/reason/flag 动作都先跑 CryptoToolkit 兜底
    # （含 hastad 广播爆破/phi_known/二次剩余等确定性攻击），命中 flag 直接返回——
    # LLM 现场写攻击代码成功率低（实测 ezrsa 读到 6 个大数却判 no simple attack）。
    # 必须在 execute_script 之前检查（否则 LLM 的 script 先执行，兜底永不触发）。
    if (
        getattr(ctx.question, "category", "") == "crypto"
        and ctx._attachment_analyzed
        and agent.sandbox is not None
        and action in ("reason", "flag", "script")
    ):
        script = agent._build_crypto_fallback_script(ctx)
        if script:
            result = await agent.sandbox.run(f"python: {script}")
            out_text = str(getattr(result, "stdout", ""))
            if out_text and ("flag{" in out_text.lower() or "dasctf{" in out_text.lower()):
                logger.info("[%s] crypto 确定性攻击链命中", getattr(ctx.question, "id", "?"))
                return {"kind": "script", "output": out_text,
                        "error": getattr(result, "stderr", "")}
            logger.info("[%s] crypto 攻击链未命中，继续 LLM 动作", getattr(ctx.question, "id", "?"))

    # ── reverse/pwn 确定性兜底优先（2026-08-21 攻坚修复）──
    # 附件分析完成后先跑 reverse 兜底（读全文+strings 搜 flag，覆盖硬编码 flag/
    # 字符串比较类题——省赛 reverse_2/upx 壳内 flag 实测 LLM 反复 script 空转）
    if (
        getattr(ctx.question, "category", "") in ("reverse", "pwn")
        and ctx._attachment_analyzed
        and agent.sandbox is not None
        and action in ("reason", "flag", "script")
    ):
        script = agent._build_reverse_fallback_script(ctx)
        if script:
            result = await agent.sandbox.run(f"python: {script}")
            out_text = str(getattr(result, "stdout", ""))
            if out_text and ("flag{" in out_text.lower() or "dasctf{" in out_text.lower()):
                logger.info("[%s] reverse 兜底命中", getattr(ctx.question, "id", "?"))
                return {"kind": "script", "output": out_text,
                        "error": getattr(result, "stderr", "")}

    if action == "tool" and agent.registry:
        from core.action_executor import execute_tool
        return await execute_tool(agent.registry, ctx, plan, detail)

    if action == "script" and agent.sandbox:
        from core.action_executor import execute_script
        return await execute_script(agent.sandbox, plan)

    if (
        action not in ("tool", "script")
        and getattr(ctx.question, "attachments", None)
        and not ctx._attachment_analyzed
        and agent.registry is not None
    ):
        from core.action_executor import execute_forced_file_analyze
        return await execute_forced_file_analyze(agent.registry, ctx)

    # misc 兜底
    if (
        getattr(ctx.question, "category", "") == "misc"
        and ctx._attachment_analyzed
        and agent.sandbox is not None
        and action in ("reason", "flag", "script")
    ):
        script = agent._build_misc_fallback_script(ctx)
        if script:
            result = await agent.sandbox.run(f"python: {script}")
            out_text = str(getattr(result, "stdout", ""))
            if out_text and ("flag{" in out_text.lower() or out_text.strip()):
                return {"kind": "script", "output": out_text,
                        "error": getattr(result, "stderr", "")}

    # web 兜底
    if (
        getattr(ctx.question, "category", "") == "web"
        and agent.sandbox is not None
        and action in ("reason", "flag", "script")
    ):
        script = agent._build_web_fallback_script(ctx)
        if script:
            result = await agent.sandbox.run(f"python: {script}")
            out_text = str(getattr(result, "stdout", ""))
            if out_text and ("flag{" in out_text.lower() or out_text.strip()):
                return {"kind": "script", "output": out_text,
                        "error": getattr(result, "stderr", "")}

    # 默认：纯 LLM 推理一步
    system = (
        "你是资深 CTF 选手，正在解题。请针对当前步骤给出具体分析结论。"
        '若找到 flag 输出 JSON: {"flag": "..."}；否则输出 JSON: {"finding": "..."}。'
        "不要编造未经验证的结论。"
    )
    user = agent._build_reason_prompt(ctx, detail)
    output = await agent._llm_text(system, user, attempt)
    return {"kind": "reason", "output": output}


def _truncate_preserve_tail(text: str, max_len: int) -> str:
    """截断文本但保留尾部（flag常出现在输出末尾），避免截断丢失flag。"""
    if len(text) <= max_len:
        return text
    head_len = int(max_len * 0.7)
    tail_len = max_len - head_len - 30
    return text[:head_len] + f"\n...[截断{len(text)-max_len}字符]...\n" + text[-tail_len:]


def observe_step(agent, ctx: AgentContext, plan: dict, act: dict) -> StepRecord:
    """解析执行结果，生成结构化步骤记录。原 MainAgent._observe。"""
    kind = act.get("kind", "reason")
    output = act.get("output", "") or ""
    if kind == "tool":
        # P0修复（2026-08-21）：工具失败时传递ERR_TOOL_FAILURE，让死循环/升级逻辑生效
        _err = ERR_TOOL_FAILURE if act.get("error") else None
        return StepRecord(
            stage=plan.get("stage", STAGE_EXPLOIT),
            action=f"tool:{act.get('tool')}",
            observation=_truncate_preserve_tail(str(output), 6000),
            tool_used=act.get("tool"),
            error_category=_err,
        )
    if kind == "script":
        _obs = _truncate_preserve_tail(str(output), 3000) if output else ""
        return StepRecord(
            stage=plan.get("stage", STAGE_EXPLOIT),
            action="script",
            observation=_obs,
            error_category=ERR_TOOL_FAILURE if act.get("error") else None,
        )
    if kind == "reason":
        if (agent.registry is not None or agent.sandbox is not None) and ctx.steps:
            recent_reason = [s for s in ctx.steps[-2:] if s.action == "reason"]
            if len(recent_reason) >= 2:
                return StepRecord(
                    stage=plan.get("stage", STAGE_RECON),
                    action="reason",
                    observation=str(output)[:500],
                    error_category=ERR_STUCK_LOOP,
                )
        return StepRecord(
            stage=plan.get("stage", STAGE_RECON),
            action="reason",
            observation=str(output)[:500],
            error_category=ERR_HALLUCINATION if not output else None,
        )
    return StepRecord(observation=str(output)[:500])


async def supervise_step(agent, ctx: AgentContext) -> SupervisionVerdict:
    """咨询监督反思 Agent；未注入时用确定性兜底。原 MainAgent._supervise。"""
    if agent.supervisor is not None:
        return await agent.supervisor.review(ctx)
    if ctx.stuck_count >= 2:
        return SupervisionVerdict(
            action=VERDICT_UPGRADE,
            reason="连续失败，兜底升级模型",
            suggestion="换更重模型重试",
        )
    return SupervisionVerdict(action=VERDICT_CONTINUE)


def _structured_candidate_texts(output: str) -> list:
    """从 LLM 结构化输出中收集候选 flag 文本（主输出之外的额外候选）。

    E1 结构化输出增强：支持 LLM 返回 JSON，含 candidates/flags/flag_candidates
    数组，或 ```json 代码块。仅做文本收集，校验沿用 extract_flag 既有逻辑。
    返回去重后的候选文本列表（不含主 output 本身）。
    """
    texts: list = []
    stripped = str(output).strip()
    blobs = [stripped]
    # 粗提 ```json ... ``` / ``` ... ``` 代码块
    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", str(output), re.DOTALL):
        blobs.append(m.group(1))
    # 内联 JSON 对象（无围栏，如 LLM 直接回 {...} 但前面夹了分析文字）：
    # 用平衡括号正则抓所有顶层 {...} 片段，逐个尝试解析
    for m in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", str(output), re.DOTALL):
        blobs.append(m.group(0))
    seen = set()
    for blob in blobs:
        try:
            j = json.loads(blob)
        except Exception:
            continue
        if not isinstance(j, dict):
            continue
        for key in ("candidates", "flags", "flag_candidates"):
            v = j.get(key)
            if isinstance(v, list):
                for x in v:
                    if x and str(x) not in seen:
                        seen.add(str(x))
                        texts.append(str(x))
        if isinstance(j.get("flag"), str) and j["flag"] not in seen:
            seen.add(j["flag"])
            texts.append(j["flag"])
    return texts


def _mark_hallucination(ctx) -> None:
    """2026-09-01 P1 能力突破：累计"猜 flag 被丢弃"次数，触发反幻觉强制实算。

    当 LLM 提交不在任何工具/脚本输出中的 flag（幻觉/瞎猜）被 extract_flag 丢弃时，
    累计命中并置 ctx._anti_hallucination=True，使下一 plan 步被强制改为 action=script
    真实计算（crypto 走 pycryptodome 解密/数论求解），而非继续空转或再猜。
    仅作纠偏、不影响正常解路径（真 flag 来自工具输出时不会触发本函数）。
    """
    ctx._hallucination_strike = getattr(ctx, "_hallucination_strike", 0) + 1
    ctx._anti_hallucination = True
    logger.info("[%s] 反幻觉命中 #%d：flag 不在工具产出，下一 plan 强制实算",
                getattr(ctx, "question", None) and ctx.question.id or "?",
                ctx._hallucination_strike)


def extract_flag(agent, ctx: AgentContext, act: dict) -> Optional[str]:
    """从执行结果中提取 flag（优先用 checker，其次正则）。原 MainAgent._extract_flag。

    攻克 hallucination：提取后过三态校验（REJECT=格式非法/疑似幻觉，直接丢弃）。
    """
    output = act.get("flag") or act.get("output") or ""
    primary_blocked = False
    # 模板假阳性拒绝（2026-08-21 攻坚修复）：flag 含 %d/%s 格式符 = 题面模板未替换
    # （实测 filterrandom LLM 抄题面 DASCTF{%d-%d} 当答案且通过校验）。
    # 仅标记主输出不可用，仍允许下方结构化候选兜底（E1）。
    if re.search(r"%[dsfx]", str(output)):
        logger.info("[%s] flag 含格式符模板（疑似抄题面），主输出拒绝: %s",
                    getattr(ctx, "question", None) and ctx.question.id or "?",
                    str(output)[:60])
        ctx._extract_failed = True  # 提取错埋点（2026-08-22 M1.3）
        primary_blocked = True
    if not primary_blocked and agent.checker is not None:
        flag = agent.checker.extract(str(output))
        if flag:
            from verify.flag_checker import V_REJECT
            verdict = agent.checker.check(flag)
            if verdict == V_REJECT:
                logger.info("[%s] flag 三态校验 REJECT（疑似 hallucination，丢弃）: %s",
                            getattr(ctx, "question", None) and ctx.question.id or "?",
                            flag[:40])
                ctx._extract_failed = True  # 提取错埋点（2026-08-22 M1.3）
                _mark_hallucination(ctx)    # 2026-09-01 P1：累计幻觉命中，强制下一步实算
                return None
            kind = str(act.get("kind") or "")
            act_output = str(act.get("output") or "")
            in_cur = (kind in ("tool", "script")) and flag in act_output
            _hist_steps = getattr(ctx, "steps", None) or []
            in_hist = any(
                flag in str(getattr(s, "observation", ""))
                for s in _hist_steps
                if str(getattr(s, "action", "")).startswith("tool:")
                or str(getattr(s, "action", "")) == "script"
            )
            if not (in_cur or in_hist):
                logger.info("[%s] flag 不在任何工具产出（疑似猜 flag，丢弃）: %s",
                            getattr(ctx, "question", None) and ctx.question.id or "?",
                            flag[:40])
                ctx._extract_failed = True  # 提取错埋点（2026-08-22 M1.3）
                _mark_hallucination(ctx)    # 2026-09-01 P1：累计幻觉命中，强制下一步实算
                return None
            q = getattr(ctx, "question", None)
            cat = str(getattr(q, "category", "") or "").lower()
            steps = getattr(ctx, "steps", None) or []
            _TOOL_PREFIX = "tool:"
            _TOOL_ACTIONS = ("script", "http_request", "file_analyze",
                             "search", "submit_script", "bruteforce")
            has_tool = any(
                str(getattr(s, "action", "")).startswith(_TOOL_PREFIX)
                or str(getattr(s, "action", "")) in _TOOL_ACTIONS
                for s in steps
            )
            if not has_tool and cat in ("web", "crypto", "misc", "pwn", "reverse"):
                logger.info("[%s] 强制工具前置：无工具调用证据，flag 拒绝（疑似瞎猜）: %s",
                            getattr(q, "id", "?"), flag[:40])
                ctx._extract_failed = True  # 提取错埋点（2026-08-22 M1.3）
                _mark_hallucination(ctx)    # 2026-09-01 P1：累计幻觉命中，强制下一步实算
                return None
            return flag
    pattern = getattr(ctx.question, "flag_pattern", None) or r"flag\{[^}]+\}"
    if not primary_blocked:
        m = re.search(pattern, str(output))
        if m:
            return m.group(0)
    # ── E1 结构化候选兜底：主输出无匹配时，扫 JSON 候选列表 ──
    # 仅做模板级正则校验（格式符占位/flag_pattern）；候选来自 LLM 结构化输出，
    # 但附件明文 flag 经正则提取即应接受（X8ccET：d0g3{...} 来自 read 工具落盘 output）。
    for cand in _structured_candidate_texts(output):
        if re.search(r"%[dsfx]", cand):
            continue  # 模板占位，跳过（疑似抄题面）
        mc = re.search(pattern, cand)
        if mc:
            ctx._extract_failed = False  # 找到有效候选，撤销主输出误触发的提取失败埋点
            return mc.group(0)
    return None
