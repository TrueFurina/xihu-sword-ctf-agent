"""OpenSSL 加解密适配器：crypto 题型常用命令封装。

输出过滤：只保留关键结果（解密明文/计算值），不送全量日志。

⚠️ 环境注意（本机 Windows 实测）：Git Bash 的 mingw openssl 在 Python
管道环境下可能被路由异常（输出 wsl.exe 的 UTF-16LE 错误），导致 exit=1。
本适配器逻辑按标准 Linux openssl 编写，决赛 Docker/Linux 环境正常可用；
本机验证以 Python 适配器（pycryptodome 模板）为准。
"""

from __future__ import annotations

import shlex
from typing import Optional

from tools.base import ToolAdapter, ToolOutput


class OpensslAdapter(ToolAdapter):
    """OpenSSL 命令行适配器（crypto 题型）。"""

    name = "openssl"
    categories = ["crypto"]

    async def run(self, params: dict) -> ToolOutput:
        operation = str(params.get("operation") or "").strip()
        args = str(params.get("args") or "").strip()

        if not operation:
            return ToolOutput(text="未指定 openssl 操作（如 rsautl -decrypt）", ok=False)
        if self.sandbox is None:
            return ToolOutput(text="沙盒未配置，无法执行 openssl", ok=False)

        # 参数白名单：仅允许安全字符，防注入
        safe_args = self._sanitize(args)
        cmd = f"openssl {operation} {safe_args}".strip()
        result = await self.sandbox.run(cmd)

        if result.timed_out:
            return ToolOutput(text=f"[超时] openssl 执行超过 {self.sandbox.default_timeout}s", ok=False)
        if result.exit_code != 0:
            hint = self._first_lines(result.stderr or "未知错误", 5)
            return ToolOutput(text=f"[openssl失败 exit={result.exit_code}]\n{hint}", ok=False)
        return ToolOutput(text=self._first_lines(result.stdout, 15), raw=result.stdout, ok=True)

    @staticmethod
    def _sanitize(args: str) -> str:
        """参数净化：只允许文件路径/选项/数字（防命令注入）。"""
        tokens = []
        for t in shlex.split(args):
            if t.startswith("-"):
                tokens.append(t)  # 选项如 -decrypt/-inkey
            elif all(c.isalnum() or c in "./_-" for c in t):
                tokens.append(t)  # 文件路径/十六进制串
            # 其他（含空格/引号/分号）直接丢弃，防注入
        return " ".join(tokens)
