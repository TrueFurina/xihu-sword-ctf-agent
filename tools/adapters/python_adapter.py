"""Python 代码执行适配器：沙盒运行 AI 生成的解题脚本。

适用于所有题型（crypto 计算/misc 编码/web 脚本化请求等）。
输出过滤：保留 stdout 前 N 行 + 错误摘要。
"""

from __future__ import annotations

from typing import Optional

from tools.base import ToolAdapter, ToolOutput


class PythonAdapter(ToolAdapter):
    """Python 脚本执行适配器。"""

    name = "python"
    categories = ["crypto", "misc", "web", "reverse", "pwn"]  # 通用

    async def run(self, params: dict) -> ToolOutput:
        code = str(params.get("code") or params.get("payload") or "").strip()
        if not code:
            return ToolOutput(text="未提供 Python 代码", ok=False)

        if self.sandbox is None:
            return ToolOutput(text="沙盒未配置，无法执行 Python", ok=False)

        result = await self.sandbox.run(f"python: {code}")
        if result.timed_out:
            return ToolOutput(text=f"[超时] 脚本执行超过 {self.sandbox.default_timeout}s", ok=False)
        if result.exit_code != 0:
            hint = self._first_lines(result.stderr or "未知错误", 5)
            return ToolOutput(text=f"[执行失败 exit={result.exit_code}]\n{hint}", ok=False)
        return ToolOutput(text=self._first_lines(result.stdout, 20), raw=result.stdout, ok=True)
