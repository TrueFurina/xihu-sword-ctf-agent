"""G4 — MCP 标准工具协议适配层（¥0 抽象，不依赖 mcp 包）。

把本仓现有的 `ToolAdapter`（`tools/tools/base.py`）适配到
Model Context Protocol (MCP) 的 server 形态，便于：
  1. 本仓工具被外部 MCP client 调用（复用社区生态）；
  2. 后续接入社区 MCP 工具（CAI 用 MCP 接外部工具的同类能力）。

设计要点（防自欺 / 防注水）：
- 纯数据结构 + 包装函数，**不启动 socket server**（那需 mcp 包 / 轨道 B）。
- handler 以可调用对象形式存在；async adapter 用 asyncio.run 桥接。
- 确定性优先：`tools/call` 只转发 adapter 过滤后的 `.text`，**绝不伪造**任何输出。
- 绝不读 KPI/账本、不碰 presolve 治理闸门；只在 presolve miss 后的工具层复用。
- 本模块是「适配层」，不替代现有 `ToolRegistry`，也不重写任何 adapter 实现。
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Callable, Optional


class MCPTool:
    """一个 MCP 工具（server 侧描述 + 执行入口）。"""

    # MCP 协议常量（2024-11-05 是主流稳定版）
    PROTOCOL_VERSION = "2024-11-05"

    def __init__(
        self,
        name: str,
        description: str,
        input_schema: dict,
        handler: Callable[[dict], Any],
    ) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.handler = handler  # arguments dict -> ToolOutput-like / str

    def to_list_entry(self) -> dict:
        """生成 MCP `tools/list` 中单个 Tool 对象（标准 schema）。"""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


def _default_input_schema() -> dict:
    """现有 `adapter.run(params: dict)` 的通用 MCP input schema。

    本仓 adapter 的 run 收一个 params dict，故统一以 JSON 字符串透传，
    避免为每个 adapter 手写 JSON Schema（那属于轨道 B 接活环境时再细化）。
    """
    return {
        "type": "object",
        "properties": {
            "params": {
                "type": "string",
                "description": "JSON-encoded params dict passed to adapter.run()",
            }
        },
        "required": ["params"],
    }


def tool_adapter_to_mcp(adapter: Any, description: Optional[str] = None) -> MCPTool:
    """把 `ToolAdapter` 实例（或 duck-typed 对象）包装成 MCPTool。

    要求 adapter 提供：
      - `.name: str`
      - `.description: str`（或传入 description 覆盖）
      - `.run(params: dict) -> ToolOutput`（sync 或 async 均可）
    """
    name = getattr(adapter, "name", "") or ""
    desc = description or getattr(adapter, "description", "") or name
    is_async = asyncio.iscoroutinefunction(getattr(adapter, "run", None))

    def _handler(arguments: dict) -> Any:
        raw = arguments.get("params", "{}")
        try:
            params = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            # 退化：原样透传，不静默丢参
            params = {"_raw": raw}
        if is_async:
            result = asyncio.run(adapter.run(params))
        else:
            result = adapter.run(params)
        # 兼容 ToolOutput（.text/.ok）与裸字符串/字典
        return result

    return MCPTool(
        name=name,
        description=desc,
        input_schema=_default_input_schema(),
        handler=_handler,
    )


class MCPRegistry:
    """MCP server 侧工具注册表：生成 `tools/list`、分发 `tools/call`。"""

    def __init__(self, server_name: str = "xihu-mcp", version: str = "0.1.0") -> None:
        self.server_name = server_name
        self.version = version
        self._tools: dict[str, MCPTool] = {}

    def register(self, tool: MCPTool) -> None:
        """注册一个 MCPTool。"""
        self._tools[tool.name] = tool

    def register_adapter(self, adapter: Any, description: Optional[str] = None) -> None:
        """把一个现有 adapter 包装并注册。"""
        self.register(tool_adapter_to_mcp(adapter, description))

    def list_tools(self) -> dict:
        """MCP `tools/list` 标准响应。"""
        return {"tools": [t.to_list_entry() for t in self._tools.values()]}

    def call_tool(self, name: str, arguments: dict) -> dict:
        """MCP `tools/call` 分发，返回标准响应（content + isError）。"""
        tool = self._tools.get(name)
        if tool is None:
            return {
                "content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True,
            }
        try:
            result = tool.handler(arguments)
            text = result.text if hasattr(result, "text") else str(result)
            is_error = not getattr(result, "ok", True)
            return {
                "content": [{"type": "text", "text": text}],
                "isError": bool(is_error),
            }
        except Exception as exc:  # noqa: BLE001 — 转成 MCP 错误响应，不崩 server
            return {
                "content": [{"type": "text", "text": f"tool error: {exc}"}],
                "isError": True,
            }

    def initialize_response(self) -> dict:
        """MCP `initialize` 响应骨架（server 侧）。"""
        return {
            "protocolVersion": MCPTool.PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": self.server_name, "version": self.version},
        }
