"""工具执行模块（上帝模块拆分——main_agent._act 的工具执行职责独立）。

从 main_agent 提取：execute_tool / execute_script / execute_forced_file_analyze。
纯函数（不依赖 MainAgent 实例），接收 registry/sandbox/ctx——逻辑与
main_agent 原实现一致（提取不重构）。

背景（2026-08-20 锐评整改）：main_agent 按职责拆——提示词归 prompts.py、
兜底脚本归 fallbacks.py、工具执行归本模块、主循环/校验留 main_agent。
"""

from core.answer_key_filter import filter_answer_key_attachments  # ITEM4-A：隔离答案密钥附件


async def execute_tool(registry, ctx, plan: dict, detail: str) -> dict:
    """执行工具调用（tool 分支）：工具名 + 自动注入附件路径 + registry.run。

    多附件完整性（2026-08-21 攻坚修复）：file_analyze 且未显式给 path 时，
    遍历分析**全部**附件（之前只分析 attachments[0]，导致 reverse_js 只读
    coso.js 漏掉 index.html 注释里的真 flag）；已分析过的附件跳过。
    """
    tool_name = str(plan.get("tool", "")).strip()
    if not tool_name:
        return {"kind": "reason", "output": ""}
    params = {"question": ctx.question, "detail": detail}
    # ── web 题 http_request 字段透传（2026-08-23 修复：web 首步强制发包需带目标 URL）──
    # plan 里的 url/target_url/method/json/data/headers 透传给 web_request_adapter。
    if tool_name == "http_request":
        for _k in ("url", "target_url", "method", "json", "data", "headers"):
            if _k in plan and plan[_k] is not None:
                params[_k] = plan[_k]
        if "target_url" in params and "url" not in params:
            params["url"] = params.pop("target_url")
    # ── 声明式参数透传（2026-10-20 接线审计）──
    # 原实现只白名单透传 http_request 的 6 个字段，其余 plan 字段全部丢弃：
    # 于是带参数的通道（rea_probe 的 lane/selector、pcap_probe 的 flow/top_n）
    # 在主链上永远走默认值——适配器写得再全也等于不可用。
    # 现在由适配器用 `param_spec` 自己声明收哪些键，主链只转发声明过的：
    # 恢复能力，又不让 LLM 的任意 plan 字段污染适配器签名。
    # 鸭子类型守卫：registry 只要能被 run 调用就必须能用。测试里存在只实现
    # `run` 的假 registry（test_main_agent_e3_evidence 的 _FakeReg），直接
    # `registry.get(...)` 会 AttributeError 把整条执行链打断（实测踩到）。
    _getter = getattr(registry, "get", None)
    _adapter = _getter(tool_name) if callable(_getter) else None
    _spec = getattr(_adapter, "param_spec", None) or {}
    if isinstance(_spec, dict):
        for _k in _spec:
            if plan.get(_k) is not None and _k not in params:
                params[_k] = plan[_k]
    # ── 显式 path 必须直达（2026-10-20 接线审计修复）──
    # 原实现只在 plan **没有** path 时才注入 params["path"]，于是「plan 里明确
    # 指定附件」的调用反而丢参数，适配器报 `路径不存在: `（ok=false），
    # 模型只能反复收到失败、换着花样重试。
    if plan.get("path"):
        params["path"] = str(plan["path"])
        if tool_name == "file_analyze":
            ctx._attachment_analyzed = True
    # ── file_analyze 未指定 path → 遍历分析全部未读附件 ──
    if tool_name == "file_analyze" and not plan.get("path"):
        attachments = filter_answer_key_attachments(  # ITEM4-A：答案密钥不进 file_analyze
            ctx.question, list(getattr(ctx.question, "attachments", None) or []))
        unseen = [str(a) for a in attachments if str(a) not in ctx._attachments_seen]
        if unseen:
            parts = []
            errors = []
            for p in unseen:
                out = await registry.run("file_analyze",
                                         {"question": ctx.question, "path": p})
                parts.append(f"【附件 {p}】\n{out.text if hasattr(out, 'text') else out}")
                if hasattr(out, 'ok') and not out.ok:
                    errors.append(str(out.text if hasattr(out, 'text') else out))
                ctx._attachments_seen.add(p)
            if len(attachments) == len(ctx._attachments_seen):
                ctx._attachment_analyzed = True
            result = {"kind": "tool", "tool": tool_name, "output": "\n\n".join(parts)}
            # E3（2026-08-25 桶C攻坚）：累积 file_analyze 全文，供 plan prompt 强制重投
            if not hasattr(ctx, "attachment_evidence") or ctx.attachment_evidence is None:
                ctx.attachment_evidence = []
            ctx.attachment_evidence.append(result["output"])
            if errors:
                result["error"] = "; ".join(errors)[:500]
            return result
        # 全部已读：返回汇总提示（不再重复分析）
        ctx._attachment_analyzed = True
        return {"kind": "tool", "tool": tool_name,
                "output": "全部附件已分析过，请基于已有附件内容继续解题（计算/解密用 script，网络用 http_request）。"}
    # ── 其他工具 / file_analyze 显式指定 path ──
    if not plan.get("path"):
        _real_atts = filter_answer_key_attachments(  # ITEM4-A：默认分析首个真实输入附件
            ctx.question, list(getattr(ctx.question, "attachments", None) or []))
        if _real_atts:
            params["path"] = str(_real_atts[0])
        if tool_name == "file_analyze":
            ctx._attachment_analyzed = True
    out = await registry.run(tool_name, params)
    if tool_name == "file_analyze" and params.get("path"):
        ctx._attachments_seen.add(str(params["path"]))
    # P0修复（2026-08-21）：工具失败时设置error字段，让死循环检测能识别
    output_text = out.text if hasattr(out, 'text') else str(out)
    is_ok = out.ok if hasattr(out, 'ok') else True
    result = {"kind": "tool", "tool": tool_name, "output": str(output_text)}
    if not is_ok:
        result["error"] = str(output_text)[:500]
    return result


async def execute_script(sandbox, plan: dict) -> dict:
    """执行脚本（script 分支）：sandbox.run(code)。"""
    code = str(plan.get("code", "")).strip()
    if not code:
        return {"kind": "reason", "output": ""}
    result = await sandbox.run(code)
    return {"kind": "script", "output": str(getattr(result, "stdout", "")),
            "error": getattr(result, "stderr", "")}


async def execute_forced_file_analyze(registry, ctx) -> dict:
    """附件强制分析（兜底：有附件但未分析且模型未主动调工具 → 强制先读全部附件）。"""
    if registry is None or not registry.has("file_analyze"):
        return {"kind": "reason", "output": ""}
    attachments = filter_answer_key_attachments(  # ITEM4-A：答案密钥不进强制分析
        ctx.question, list(getattr(ctx.question, "attachments", None) or []))
    if not attachments:
        return {"kind": "reason", "output": ""}
    # 多附件完整性：一次读完全部未读附件（2026-08-21 攻坚修复）
    unseen = [str(a) for a in attachments if str(a) not in ctx._attachments_seen]
    parts = []
    for p in unseen:
        out = await registry.run("file_analyze",
                                 {"question": ctx.question, "path": p})
        parts.append(f"【附件 {p}】\n{out}")
        ctx._attachments_seen.add(p)
    if len(attachments) == len(ctx._attachments_seen):
        ctx._attachment_analyzed = True
    _fa_output = "\n\n".join(parts) if parts else "全部附件已分析过"
    # E3（2026-08-25 桶C攻坚）：累积 file_analyze 全文，供 plan prompt 强制重投
    if not hasattr(ctx, "attachment_evidence") or ctx.attachment_evidence is None:
        ctx.attachment_evidence = []
    ctx.attachment_evidence.append(_fa_output)
    return {"kind": "tool", "tool": "file_analyze", "output": _fa_output}
