"""反幻觉 provenance 闸（2026-09-22 攻坚）。

项目铁律：LLM 提交的候选 flag 必须「可证实来自工具/脚本真实产出」或「与 sha256
真值匹配」，否则一律判幻觉拒绝。本模块是 extract_flag 的证据门单一真值源，替代
旧的内联 in_cur/in_hist/has_tool 逻辑，并堵两处旧闸泄漏：

  泄漏① 打印泄漏（print-leak）：LLM 写 `script` 动作 `print("flag{猜的}")`，flag 进入
    act_output → 旧 in_cur=True 被放行。本闸检查「产出该 flag 的那一步脚本源码是否原样
    含此 flag 字面量」——若含，说明是 echo/print 硬编码而非算出来的，拒绝。

  泄漏② 无关工具调用放行：旧 has_tool 只要「历史有任何工具调用」就接受 reason 提交的
    flag，即使 flag 根本不在任何工具产出里。本闸要求 flag 字面量必须出现在某 tool/script
    步的 observation 中（当前步或历史步），否则拒绝。

判定顺序（调用方在调用本函数前已做 sha256 仲裁；sha256 匹配=确定性采信，不匹配=
确定性幻觉，都不进本函数）：
  - 当前步 kind∈{tool,script} 且 flag 在 output 中，且 flag 不在该步脚本源码 → 采信
  - flag 在某历史 tool/script 步的 observation 中，且不在该步脚本源码 → 采信
  - flag 在当前步 output 中但也在该步脚本源码 → 打印泄漏，拒绝
  - flag 不在任何工具产出 → 无工具证据，拒绝
"""
from __future__ import annotations

# 工具/脚本类动作（其 observation 是可信产出来源）
_TOOL_ACTIONS = ("script", "http_request", "file_analyze",
                 "search", "submit_script", "bruteforce")
_TOOL_PREFIX = "tool:"


def _tool_steps(ctx) -> list:
    """返回所有 tool/script 类步骤（含 action）。"""
    out = []
    for s in (getattr(ctx, "steps", None) or []):
        act_name = str(getattr(s, "action", ""))
        if act_name.startswith(_TOOL_PREFIX) or act_name in _TOOL_ACTIONS:
            out.append(s)
    return out


def provenance_allows(flag: str, ctx, act: dict) -> tuple[bool, str]:
    """判定候选 flag 是否来自真实工具/脚本产出。

    返回 (ok, reason)。reason 用于日志与埋点归因。
      ok=True  → 采信（工具证据充分）
      ok=False → 拒绝（reason 说明泄漏/无证据类型）
    """
    if not flag:
        return False, "empty-flag"
    kind = str(act.get("kind") or "")
    output = str(act.get("output") or "")
    # 产出该 flag 的脚本源码：仅当 LLM 写脚本（execute_script）时由 act_step 注入；
    # tool/reason 步无源码 → "" → hardcoded=False。
    source = str(act.get("source") or "")

    in_cur_output = (kind in ("tool", "script")) and (flag in output)
    hardcoded_in_source = flag in source

    # 历史工具/脚本 observation 中出现
    in_hist = any(flag in str(getattr(s, "observation", "")) for s in _tool_steps(ctx))

    if in_cur_output and not hardcoded_in_source:
        return True, "tool-output-current"
    if in_hist and not hardcoded_in_source:
        return True, "tool-output-history"
    if in_cur_output and hardcoded_in_source:
        return False, "print-leak(script-hardcoded-flag)"
    if not (in_cur_output or in_hist):
        return False, "no-tool-evidence"
    return False, "unknown-provenance"


def is_print_leak(flag: str, act: dict) -> bool:
    """快速判定：当前步是否为「脚本硬编码打印 flag」的泄漏。

    供 extract_flag 在拒绝路径上做精确归因（与 no-tool-evidence 区分）。
    """
    kind = str(act.get("kind") or "")
    output = str(act.get("output") or "")
    source = str(act.get("source") or "")
    if kind not in ("tool", "script"):
        return False
    return (flag in output) and (flag in source)
