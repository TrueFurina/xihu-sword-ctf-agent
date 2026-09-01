"""LLM 调用封装模块（上帝模块拆分——main_agent._llm_json/_llm_text 职责独立）。

从 main_agent 提取：llm_json / llm_text。
模块级函数接收 llm_client 参数（可注入 mock/真实 client），逻辑与
main_agent 原实现一致（提取不重构）。

背景（2026-08-20 锐评整改）：main_agent 按职责拆——提示词归 prompts.py、
兜底脚本归 fallbacks.py、工具执行归 action_executor.py、LLM 封装归本模块、
主循环/校验留 main_agent。
"""

from typing import Optional


async def llm_json(system: str, user: str, attempt: int, llm_client=None, recover_script: bool = False) -> Optional[dict]:
    """LLM JSON 调用：优先注入 client（dict 直返/str 解析 JSON），否则默认 ai_chat_json。

    recover_script=True 时（仅 plan 步使用）：JSON 解析失败但原文含 python 代码围栏，
    则当作 script 动作恢复，让 LLM 的"写脚本实算"尝试真正执行，而非被当作不可解析
    丢弃导致空转/放弃。supervisor/feedback 等要求严格 JSON 的调用方保持默认 False。
    """
    if llm_client is not None:
        out = await llm_client(system, user, attempt)
        if isinstance(out, dict):
            return out
        if isinstance(out, str):  # 客户端返回文本：尝试解析 JSON
            import json as _json
            import re as _re

            _raw = out.strip()
            # 剥离 markdown 围栏（```json ... ``` 或 ``` ... ```）
            _fence = _re.search(r"```(?:json)?\s*(.*?)\s*```", _raw, _re.DOTALL)
            if _fence:
                _raw = _fence.group(1).strip()
            # 提取第一个 { 到最后一个 } 之间的 JSON 块（容忍前后解释文字）
            _s, _e = _raw.find("{"), _raw.rfind("}")
            if _s != -1 and _e != -1 and _e > _s:
                _raw = _raw[_s:_e + 1]
            try:
                return _json.loads(_raw)
            except Exception:  # noqa: BLE001
                # 2026-09-01 P1：plan 步 JSON 解析失败时，若原文含 python 代码围栏，
                # 当作 script 动作恢复——让 LLM 的"写脚本实算"尝试真正执行（而非被
                # 当作不可解析丢弃导致空转/放弃）。仅 recover_script=True 时生效，
                # 不影响 supervisor/feedback 等要求严格 JSON 的调用方。
                if recover_script:
                    _cb = _re.search(r"```(?:python|py)?\s*(.*?)\s*```", out, _re.DOTALL)
                    if _cb:
                        _code = _cb.group(1).strip()
                        if _code:
                            _code = _code if _code.startswith("python:") else "python: " + _code
                            return {"action": "script", "code": _code,
                                    "stage": "exploit", "done": False,
                                    "_recovered_from_code": True}
                return None
        return None
    import os as _os
    if _os.getenv("CTF_AGENT_LLM_FAILOVER", "0") == "1":
        from llm.failover import ai_chat_json_failover_async

        return await ai_chat_json_failover_async(
            [{"role": "user", "content": user}], system=system, attempt=attempt)
    from llm.client import ai_chat_json, get_model_for_attempt

    model = get_model_for_attempt(attempt)
    return ai_chat_json([{"role": "user", "content": user}], system=system, model=model, recover_script=recover_script)


async def llm_text(system: str, user: str, attempt: int, llm_client=None) -> str:
    """LLM 文本调用：优先注入 client（str 直返/dict 提取字段），否则默认 ai_chat。"""
    if llm_client is not None:
        out = await llm_client(system, user, attempt)
        if isinstance(out, str):
            return out
        if isinstance(out, dict):  # dict 返回：提取 finding/flag/text 字段
            for key in ("finding", "flag", "text", "detail"):
                val = out.get(key)
                if isinstance(val, str) and val.strip():
                    return val
            return ""
        return ""
    import os as _os
    if _os.getenv("CTF_AGENT_LLM_FAILOVER", "0") == "1":
        from llm.failover import ai_chat_text_failover_async

        return await ai_chat_text_failover_async(
            [{"role": "user", "content": user}], system=system, attempt=attempt)
    from llm.client import ai_chat, get_model_for_attempt

    model = get_model_for_attempt(attempt)
    return ai_chat([{"role": "user", "content": user}], system=system, model=model) or ""
