"""统一执行器接口（Docker / 子进程双实现）。

v2.0：本机 Docker daemon 不可用（WSLService 故障），MVP 用子进程实现；
Docker 版决赛前修复 WSL 后补充（sandbox/docker_executor.py）。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ExecResult:
    """执行结果（统一结构）。"""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def combined(self) -> str:
        parts = [self.stdout]
        if self.stderr:
            parts.append(f"[stderr] {self.stderr}")
        return "\n".join(parts)


class Executor(ABC):
    """执行器抽象：隔离运行 AI 生成的代码/EXP。"""

    @abstractmethod
    async def run(self, code: str, timeout: int = 30) -> ExecResult:
        """执行代码/命令，返回 stdout/stderr/exit_code。"""
        raise NotImplementedError
