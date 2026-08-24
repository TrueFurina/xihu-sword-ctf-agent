"""平台 API 抽象层：完整题目生命周期（v2.0 做厚，不假设性硬编码）。

覆盖全生命周期：拉题 → 详情 → 创建实例 → 获取访问 → 下载附件 → 提交 flag
→ 重置环境 → 销毁实例。所有字段带默认值，测试赛拿到 openapi.json 后
仅实现 platform/dasctf.py 的 DasCTFPlatform，不动上层调度。

对齐通用 CTF API 模式（参考 aiagentsec-benchmarks agent-operator.md，
非西湖论剑官方，仅作交互模式参考）。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ChallengeInfo:
    """题目元数据（字段预留，未知字段用 None/默认值）。"""

    id: str = ""
    title: str = ""
    category: str = "misc"          # web/crypto/misc/reverse/pwn
    description: str = ""
    flag_format: str = "flag{[^}]+}"  # 如 flag{...} / DASCTF{...}
    score: int = 0                  # 分值（优先级参考）
    has_instance: bool = False      # 是否需要启动实例
    has_attachment: bool = False    # 是否有附件
    extra: dict = field(default_factory=dict)  # 预留字段（平台特有）


@dataclass
class InstanceInfo:
    """实例信息（启动容器/环境后返回）。"""

    instance_id: str = ""
    status: str = ""                # starting/running/error
    extra: dict = field(default_factory=dict)


@dataclass
class AccessInfo:
    """访问信息（IP/端口/账号）。"""

    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""
    url: str = ""                   # 若平台给的是 URL
    entrypoints: list = field(default_factory=list)  # 多端口/多服务
    extra: dict = field(default_factory=dict)


@dataclass
class SubmitResult:
    """提交 flag 的结果（对齐平台返回语义）。"""

    accepted: bool = False          # 是否接受（决定是否完成此题）
    correct: bool = False           # 是否正确
    detail: str = ""                # 平台返回详情
    remaining_attempts: Optional[int] = None  # 剩余提交次数（如有）
    request_failed: bool = False              # 提交请求层是否失败（网络/HTTP/鉴权）
                                                # 与 correct=False（flag 错误）区分：
                                                # 请求故障时 flag 可能是对的，poller 熔断
                                                # 不应据此丢弃正确 flag（复盘第⑥层修复）
    extra: dict = field(default_factory=dict)


class PlatformAPI(ABC):
    """官方答题平台抽象接口——测试赛当天仅需实现这一个类。"""

    @abstractmethod
    async def list_challenges(self) -> list[ChallengeInfo]:
        """拉取题目列表。"""
        raise NotImplementedError

    @abstractmethod
    async def get_challenge(self, challenge_id: str) -> ChallengeInfo:
        """获取单题完整定义。"""
        raise NotImplementedError

    @abstractmethod
    async def create_instance(self, challenge_id: str) -> InstanceInfo:
        """启动题目环境/容器。"""
        raise NotImplementedError

    @abstractmethod
    async def get_access(self, instance_id: str) -> AccessInfo:
        """获取实例访问信息（地址/端口/账号）。"""
        raise NotImplementedError

    @abstractmethod
    async def download_attachment(self, challenge_id: str) -> list[str]:
        """下载题目附件，返回本地路径列表。"""
        raise NotImplementedError

    @abstractmethod
    async def get_hint(self, challenge_id: str) -> str:
        """获取结构化提示（可选）。"""
        raise NotImplementedError

    @abstractmethod
    async def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        """提交 flag。"""
        raise NotImplementedError

    @abstractmethod
    async def reset_instance(self, instance_id: str) -> None:
        """重置实例环境。"""
        raise NotImplementedError

    @abstractmethod
    async def destroy_instance(self, instance_id: str) -> None:
        """销毁实例（释放资源，成功后必须调用）。"""
        raise NotImplementedError
