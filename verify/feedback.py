"""校验-反馈循环：错误分类 + 结构化修正指令生成（v2.0 核心）。

对齐专家意见：「真正能提升解出率的，是步骤级校验——判断当前阶段、
解析工具输出的关键信息、识别僵局、分类错误类型，再给模型明确的修正方向，
而不是把整段日志丢回去让它自己悟」。

流程：
1. FlagChecker 验证 flag
2. 失败 → ErrorClassifier 分类错误 → 监督 Agent 裁决
3. 生成结构化修正指令（错误类别 + 修正方向 + 监督建议）回传主 Agent
4. ≤ max_retries 次迭代
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

from verify.error_classifier import ErrorClassifier
from verify.flag_checker import FlagChecker
from verify.step_checker import StepChecker


class FeedbackLoop:
    """校验-反馈循环：失败时分类错误并生成定向修正。

    两层校验（对齐真实比赛逻辑）：
    1. 格式校验：FlagChecker.validate（flag 格式是否正确）
    2. 正确性校验：is_correct 回调（真实比赛=平台 submit 返回 accepted=true；
       本地评测=与官方 flag 比对）。未提供时仅做格式校验。

    错误归因（v2.0）：失败时用 StepChecker 解析最近步骤的工具输出，
    提取关键信息（key_info），与错误分类+修正方向一起组成结构化修正指令，
    而不是把整段报错日志丢回模型。
    """

    def __init__(
        self,
        checker: Optional[FlagChecker] = None,
        classifier: Optional[ErrorClassifier] = None,
        step_checker: Optional[StepChecker] = None,
        max_retries: int = 3,
        is_correct: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.checker = checker or FlagChecker()
        self.classifier = classifier or ErrorClassifier()
        self.step_checker = step_checker or StepChecker()
        self.max_retries = max_retries
        self.is_correct = is_correct

    def _flag_ok(self, flag: str, pattern: Optional[str]) -> bool:
        """格式通过 + 正确性通过（若配置了 is_correct）。"""
        if not self.checker.validate(flag, pattern):
            return False
        if self.is_correct is not None:
            try:
                return bool(self.is_correct(flag))
            except Exception:  # noqa: BLE001 - 正确性判定异常视为不通过
                return False
        return True

    # ── 错误归因（v2.0 核心）────────────────────────────

    def _build_correction(self, last_output: dict, attempt: int) -> dict:
        """生成结构化修正指令：错误分类 + 关键信息 + 修正方向。"""
        steps = last_output.get("_steps", [])
        category, suggestion = self.classifier.classify(steps)

        # 用 StepChecker 解析最近步骤的工具输出，提取关键信息（报错/flag 特征）
        key_info = ""
        if steps:
            last_step = steps[-1]
            obs = getattr(last_step, "observation", "") or ""
            parsed = self.step_checker.parse_tool_output(obs)
            if parsed.has_error_marker:
                key_info = parsed.error_hint[:200]
            elif parsed.key_lines:
                key_info = parsed.key_lines[0][:200]
            else:
                key_info = obs[:200]

        if category:
            logger.info(
                "[%s] 第 %d 次迭代失败，错误分类: %s（关键信息: %s）",
                getattr(last_output.get("_question"), "id", "?"),
                attempt + 1,
                category,
                key_info[:80] or "(无)",
            )

        return {
            "attempt": attempt + 1,
            "error_category": category,
            "key_info": key_info,
            "suggestion": suggestion or "换一个思路重试",
            "previous_flag": last_output.get("flag"),
            "validated": False,
        }

    async def run(
        self,
        question,
        solver: Callable,
        max_retries: Optional[int] = None,
    ) -> dict:
        """执行求解 + 校验 + 反馈循环。

        Args:
            question: Question 对象
            solver: callable(question, attempt, correction) -> AgentOutput dict
                    correction 为结构化修正指令（dict 或 None），供主 Agent 使用

        Returns:
            最终 AgentOutput（成功或最后一次失败结果）
        """
        retries = max_retries or self.max_retries
        correction: Optional[dict] = None
        last_output: Optional[dict] = None

        for attempt in range(retries):
            last_output = await solver(question, attempt, correction)

            # 1. flag 校验（格式 + 正确性双层）
            flag = last_output.get("flag")
            pattern = getattr(question, "flag_pattern", None)
            if flag and self._flag_ok(flag, pattern):
                last_output["retries"] = attempt
                last_output["validated"] = True
                return last_output

            # 2. 失败 → 生成结构化修正指令（错误归因）
            last_output["_question"] = question
            correction = self._build_correction(last_output, attempt)

        if last_output is not None:
            last_output["retries"] = retries - 1
            last_output["validated"] = False
        return last_output or {}
