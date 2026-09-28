"""G4 — MCP 适配层单测（¥0、零 token、纯逻辑）。

验证：现有 adapter 能包装成 MCPTool、tools/list 结构正确、
tools/call 分发正确（sync/async 均覆盖）、未知工具返回 isError、
initialize 响应骨架结构正确、坏 JSON 参数安全退化。
"""

from __future__ import annotations

from core.mcp_adapter import (
    MCPRegistry,
    MCPTool,
    _default_input_schema,
    tool_adapter_to_mcp,
)


# ── 最小 duck-typed mock adapter（sync）──
class FakeSyncAdapter:
    name = "echo_tool"
    description = "echo params back"

    def run(self, params):
        class _Out:
            text = "got:" + str(params.get("x", ""))
            ok = True

        return _Out()


# ── 最小 async mock adapter ──
class FakeAsyncAdapter:
    name = "async_tool"
    description = "async echo"

    async def run(self, params):
        class _Out:
            text = "async:" + str(params.get("y", ""))
            ok = True

        return _Out()


def test_mcp_tool_to_list_entry():
    t = MCPTool("t", "desc", _default_input_schema(), lambda a: "ok")
    entry = t.to_list_entry()
    assert entry["name"] == "t"
    assert entry["description"] == "desc"
    assert entry["inputSchema"]["type"] == "object"
    assert "params" in entry["inputSchema"]["properties"]


def test_adapter_to_mcp_sync_handler():
    m = tool_adapter_to_mcp(FakeSyncAdapter())
    assert m.name == "echo_tool"
    out = m.handler({"params": '{"x": "hi"}'})
    assert out.text == "got:hi"
    assert out.ok is True


def test_adapter_to_mcp_async_handler():
    m = tool_adapter_to_mcp(FakeAsyncAdapter())
    assert m.name == "async_tool"
    out = m.handler({"params": '{"y": "7"}'})
    assert out.text == "async:7"


def test_registry_list_and_call_sync():
    reg = MCPRegistry()
    reg.register_adapter(FakeSyncAdapter())
    listing = reg.list_tools()
    assert len(listing["tools"]) == 1
    assert listing["tools"][0]["name"] == "echo_tool"
    resp = reg.call_tool("echo_tool", {"params": '{"x": "z"}'})
    assert resp["isError"] is False
    assert resp["content"][0]["text"] == "got:z"


def test_registry_call_async_adapter():
    reg = MCPRegistry()
    reg.register_adapter(FakeAsyncAdapter())
    resp = reg.call_tool("async_tool", {"params": '{"y": "9"}'})
    assert resp["isError"] is False
    assert resp["content"][0]["text"] == "async:9"


def test_call_unknown_tool_returns_error():
    reg = MCPRegistry()
    resp = reg.call_tool("nope", {})
    assert resp["isError"] is True
    assert "unknown tool" in resp["content"][0]["text"]


def test_tool_execution_exception_becomes_error():
    def boom(_a):
        raise RuntimeError("kaboom")

    reg = MCPRegistry()
    reg.register(MCPTool("bad", "bad", _default_input_schema(), boom))
    resp = reg.call_tool("bad", {"params": "{}"})
    assert resp["isError"] is True
    assert "tool error" in resp["content"][0]["text"]


def test_initialize_response_shape():
    reg = MCPRegistry("svc", "1.2.3")
    init = reg.initialize_response()
    assert init["serverInfo"]["name"] == "svc"
    assert init["serverInfo"]["version"] == "1.2.3"
    assert init["capabilities"]["tools"] == {}
    assert "protocolVersion" in init


def test_bad_json_params_safe_fallback():
    m = tool_adapter_to_mcp(FakeSyncAdapter())
    out = m.handler({"params": "not-json"})
    # 退化成 {"_raw": "not-json"}，run 取不到 x → "got:"
    assert out.text == "got:"
