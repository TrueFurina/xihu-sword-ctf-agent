"""fail-open 验证：无 Key 时 client **返回 None 且不抛异常**。

注意：本脚本不读取、不打印任何凭据值，仅验证行为。

2026-11-01 审计修正
-------------------
原实现只断言了返回值：

    r1 = ai_chat(...)
    assert r1 is None

问题：**它没有真的验证「不抛异常」这一半。** 若 `ai_chat` 抛异常，脚本会在
`r1 = ai_chat(...)` 那一行直接崩溃，输出的是 traceback 而不是
「fail-open 失败：ai_chat 应返回 None」——诊断信息丢失，而且退出码虽非 0，
却和「返回了非 None」这个真正的语义错误无法区分。

现在两件事分开断言，并且**先捕获异常再判返回值**，失败信息明确指到是哪种错。
"""

import os
import sys
import traceback

# 项目根目录加入 sys.path（scripts/ 下直接运行时需要）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# 移除 Key 环境变量（进程内生效，不影响全局环境）
for var in ("DEEPSEEK_API_KEY", "CTF_AGENT_LLM_API_KEY"):
    os.environ.pop(var, None)

from llm.client import ai_chat, ai_chat_json  # noqa: E402


def _probe(name, fn):
    """调用 fn，返回 (是否抛异常, 异常描述, 返回值)。"""
    try:
        return False, None, fn([{"role": "user", "content": "test"}])
    except BaseException as exc:  # noqa: BLE001 - 这里就要抓全部
        return True, "%s: %s" % (type(exc).__name__, exc), None


def main() -> int:
    failures = []
    for name, fn in (("ai_chat", ai_chat), ("ai_chat_json", ai_chat_json)):
        raised, why, value = _probe(name, fn)
        if raised:
            # 这是 fail-open 的反面：没 Key 就不该炸，调用方无从降级。
            failures.append("%s 抛了异常（fail-open 要求返回 None）: %s" % (name, why))
            print("%-14s 抛异常: %s" % (name, why))
            continue
        print("%-14s 返回: %r" % (name, value))
        if value is not None:
            failures.append("%s 应返回 None，实际 %r" % (name, value))

    if failures:
        print("\n=== FAIL_OPEN FAILED ===")
        for f in failures:
            print("  [FAIL] %s" % f)
        return 1
    print("FAIL_OPEN_OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # 连 main 都炸了，也要给出可读结论
        traceback.print_exc()
        print("FAIL_OPEN_FAILED (脚本自身异常)")
        sys.exit(1)
