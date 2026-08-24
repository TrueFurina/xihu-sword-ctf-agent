"""CTF 场景 Mock LLM（开发期零依赖跑通链路）。

原 Security-Agent 的 llm/mock.py 是安全研判场景（summarize 事件），
与 CTF 解题契约不匹配，此处重写为 CTF 场景：
- 输出遵循统一 JSON 契约 {flag, confidence, evidence, error, ...}
- 预置答案表：本地题库中已知的题目返回对应 flag
- 未命中预置答案时返回"解不出"（confidence=0 + 错误说明），
  用于测试失败路径与校验-反馈循环
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# 预置答案表：{题目 id: flag}。由 eval/cases.py 在加载题库时注入，
# 也可通过 mock_answers() 显式设置。开发期用于验证链路正确性。
_PRESET_ANSWERS: dict[str, str] = {}


def set_preset_answers(answers: dict[str, str]) -> None:
    """注入预置答案表（题目 id → flag）。"""
    _PRESET_ANSWERS.clear()
    _PRESET_ANSWERS.update(answers)


def clear_preset_answers() -> None:
    _PRESET_ANSWERS.clear()


def mock_solve(
    question_id: str,
    question_text: str = "",
    question_type: str = "",
) -> dict:
    """模拟主 Agent 解题，返回统一 JSON 契约。

    Args:
        question_id: 题目唯一 id（预置答案表主键）
        question_text: 题目描述（用于启发式推断，预留）
        question_type: web/crypto/misc 等题型

    Returns:
        AgentOutput 契约 dict：
        {flag, confidence, evidence, error{category,detail}, duration_ms, provider}
    """
    flag = _PRESET_ANSWERS.get(question_id)
    if flag:
        return {
            "task_id": question_id,
            "question_type": question_type,
            "stage": "flag_extract",
            "flag": flag,
            "confidence": 0.95,
            "evidence": [f"[mock] 预置答案命中题目 {question_id}"],
            "error": None,
            "supervision": "continue",
            "duration_ms": 12,
            "provider": "mock",
            "retries": 0,
        }

    # 未命中：返回失败（用于测试校验-反馈循环的失败路径）
    return {
        "task_id": question_id,
        "question_type": question_type,
        "stage": "exploit",
        "flag": None,
        "confidence": 0.0,
        "evidence": [],
        "error": {
            "category": "unsolved_mock",
            "detail": f"[mock] 未命中预置答案 {question_id}，模拟解不出",
        },
        "supervision": "give_up",
        "duration_ms": 8,
        "provider": "mock",
        "retries": 0,
    }


def mock_chat(messages: list[dict], system: Optional[str] = None, **kwargs) -> Optional[str]:
    """模拟 ai_chat 的文本回复（用于 llm/client.py fail-open 链路测试）。

    从最后一条 user 消息中尝试提取 flag{...}，否则返回一段固定文本。
    """
    text = ""
    for msg in reversed(messages or []):
        content = msg.get("content", "")
        if isinstance(content, str) and content.strip():
            text = content
            break
    if "flag{" in text:
        import re

        m = re.search(r"flag\{[^}]+\}", text)
        if m:
            return f"检测到 flag: {m.group(0)}"
    return "（mock）未识别到 flag 特征，建议继续信息收集。"
