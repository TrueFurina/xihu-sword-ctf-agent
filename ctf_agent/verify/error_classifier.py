"""错误分类器：把失败原因归类为可行动的修正方向（v2.0 核心）。

对齐专家意见：「判断当前阶段、解析工具输出的关键信息、识别僵局、分类错误类型，
再给模型明确的修正方向，而不是把整段日志丢回去让它自己悟」。

分类（与 core/main_agent 的 ERR_* 常量一致）：
- stuck_loop      死循环：连续 N 步同一动作/输出
- wrong_direction 方向错：偏离题目目标（分析错文件/错端口/错工具）
- hallucination   幻觉：模型编造结果（未执行工具就断言 flag）
- tool_failure    工具失败：命令不存在/超时/语法错
- env_failure     环境问题：依赖缺失/网络不通
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

from core.main_agent import (
    ERR_ENV_FAILURE,
    ERR_HALLUCINATION,
    ERR_STUCK_LOOP,
    ERR_TOOL_FAILURE,
    ERR_WRONG_DIRECTION,
    StepRecord,
)


class ErrorClassifier:
    """错误分类器：输入步骤历史，输出错误类别 + 修正建议。"""

    def __init__(self) -> None:
        self.CATEGORIES = {
            ERR_STUCK_LOOP: "连续 N 步同一动作/输出，死循环",
            ERR_WRONG_DIRECTION: "偏离题目目标（分析错文件/错端口/错思路）",
            ERR_HALLUCINATION: "编造输出（flag 未经验证/工具未执行就断言）",
            ERR_TOOL_FAILURE: "工具执行失败（命令不存在/超时/语法错）",
            ERR_ENV_FAILURE: "环境问题（依赖缺失/网络不通）",
        }

    def classify(self, step_history: list) -> tuple[str, str]:
        """对步骤历史分类，返回 (error_category, 修正建议)。

        Args:
            step_history: list[StepRecord] 或含 error_category 的对象列表

        Returns:
            (category, suggestion)；无法判定时返回 (None, "")
        """
        if not step_history:
            return (None, "")

        # 规则 1：连续 3 步同一 action → 死循环
        if len(step_history) >= 3:
            recent_actions = [getattr(s, "action", "") for s in step_history[-3:]]
            if len(set(recent_actions)) == 1 and recent_actions[0]:
                return (
                    ERR_STUCK_LOOP,
                    "检测到死循环：连续执行相同动作。请换一个完全不同的思路（换工具/换方向/换目标文件）。",
                )

        # 规则 2：最近步骤中工具失败 ≥2 次 → 工具失败
        tool_failures = sum(
            1 for s in step_history[-4:] if getattr(s, "error_category", None) == ERR_TOOL_FAILURE
        )
        if tool_failures >= 2:
            return (
                ERR_TOOL_FAILURE,
                "工具连续执行失败。建议：检查命令参数/改用替代工具/或改用手写 Python 脚本绕过。",
            )

        # 规则 3：有幻觉标记（模型未执行工具就报结果）
        for s in step_history[-3:]:
            if getattr(s, "error_category", None) == ERR_HALLUCINATION:
                return (
                    ERR_HALLUCINATION,
                    "检测到模型幻觉：结果未经工具执行验证。请先实际执行命令/脚本，确认输出后再断言。",
                )

        # 规则 4：最近步骤含 env 特征
        for s in step_history[-3:]:
            if getattr(s, "error_category", None) == ERR_ENV_FAILURE:
                return (
                    ERR_ENV_FAILURE,
                    "环境问题：检查依赖是否安装、网络是否可达、路径是否存在。",
                )

        return (None, "")

    def describe(self) -> dict:
        return {"categories": self.CATEGORIES}
