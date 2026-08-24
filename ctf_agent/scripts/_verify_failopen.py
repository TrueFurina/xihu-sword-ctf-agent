"""fail-open 验证脚本：无 Key 时 client 返回 None 且不抛异常。

注意：本脚本不读取、不打印任何凭据值，仅验证行为。
"""

import os
import sys

# 项目根目录加入 sys.path（scripts/ 下直接运行时需要）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# 移除 Key 环境变量（进程内生效，不影响全局环境）
for var in ("DEEPSEEK_API_KEY", "CTF_AGENT_LLM_API_KEY"):
    os.environ.pop(var, None)

from llm.client import ai_chat, ai_chat_json  # noqa: E402

r1 = ai_chat([{"role": "user", "content": "test"}])
r2 = ai_chat_json([{"role": "user", "content": "test"}])
print("ai_chat 无Key返回:", repr(r1))
print("ai_chat_json 无Key返回:", repr(r2))
assert r1 is None, f"fail-open 失败: ai_chat 应返回 None, 实际 {r1!r}"
assert r2 is None, f"fail-open 失败: ai_chat_json 应返回 None, 实际 {r2!r}"
print("FAIL_OPEN_OK")
