"""异步任务池：多题并行执行（v2.0：做到「多题不阻塞」即及格）。

- asyncio.Semaphore 控制最大并发（默认 8）
- 不做花哨优先级队列（排名看解出率，不看谁快几秒）
- 每题的耗时由主循环/校验层记录
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

from config import AppConfig


class TaskPool:
    """异步任务池：并行执行多个求解任务。"""

    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config or AppConfig.from_env()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)

    @property
    def max_concurrency(self) -> int:
        return self.config.max_concurrency

    async def submit(self, question, solver: Callable[[object, int], Awaitable[dict]]) -> dict:
        """提交一道题并发执行（信号量限流）。

        Args:
            question: Question 对象
            solver: callable(question, attempt) -> AgentOutput dict

        Returns:
            AgentOutput dict（含 duration_ms 由本层填充）
        """
        async with self._semaphore:
            start = time.perf_counter()
            try:
                output = await solver(question, 0)
            except Exception as exc:  # noqa: BLE001 - 单题异常不拖垮整体
                logger.warning("[%s] 求解异常: %s", getattr(question, "id", "?"), exc)
                output = {"task_id": getattr(question, "id", ""), "flag": None,
                          "error": {"category": "env_failure", "detail": str(exc)}}
            finally:
                duration_ms = int((time.perf_counter() - start) * 1000)
            if isinstance(output, dict):
                output["duration_ms"] = output.get("duration_ms") or duration_ms
            return output

    async def run_all(
        self,
        questions: list,
        solver: Callable[[object, int], Awaitable[dict]],
    ) -> list[dict]:
        """并发执行全部题目，返回结果列表（顺序与输入一致）。"""
        tasks = [self.submit(q, solver) for q in questions]
        return await asyncio.gather(*tasks)

    def describe(self) -> dict:
        return {"max_concurrency": self.config.max_concurrency}
