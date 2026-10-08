#!/usr/bin/env python
"""归因指纹守卫：识别 benchmark 报告中不可信的「LLM 解出」归因。

背景（两次真实事故）：
- 雷 0（2026-09-29）：real_crypto_dnui_keyboard 被标 main_agent_llm，
  复核实为 presolve（78ms、tokens=0），导致真值源输出被推翻的旧结论。
- 2026-10-08：L2_pure_llm_20261006 等三份报告表面「纯 LLM 8/19=42.1%」，
  逐题取证全部为 presolve/截断产物（解出 11ms~3.9s、tokens 全 None、
  失败题墙钟整齐卡 ~12s），假数字一度差点进入权威文档。

判定口径（指纹，非猜测）：
- LLM 全链路经验下限 LLM_FLOOR_MS=5000：真实 LLM 至少一次 API 往返
  （M2/NYU 实测 8.3s 起；亚 5s 解出与 LLM 决策链路不符）。
- 解出但无 token 计费（tokens/total_tokens 缺失）= 无任何 LLM 调用证据。
- 归因字段优先级：item.solved_by / item.method > 报告级 mode。
- 未解出条目永不判疑（0/N 结论不依赖归因，天然安全）。

用法：
    python _attribution_fingerprint.py <benchmark_report.json> [...]

退出码：0=干净；1=存在可疑归因（fail-closed，供 CI 门禁）；2=输入错误。
只读审计：本脚本不修改任何被检文件。
"""

from __future__ import annotations

import json
import sys
from typing import Any

LLM_FLOOR_MS = 5000
_LLM_HINTS = ("llm", "main_agent")


def _attributed_to_llm(item: dict[str, Any], report_mode: str) -> bool:
    """该解出条目是否被归因给 LLM（显式条目级字段优先，回退报告级 mode）。"""
    by = str(item.get("solved_by") or item.get("method") or report_mode or "").lower()
    return any(h in by for h in _LLM_HINTS)


def _tokens_recorded(item: dict[str, Any]) -> bool:
    """是否有任何 token 计费证据。"""
    return item.get("tokens") is not None or item.get("total_tokens") is not None


def audit_report(report: dict[str, Any], llm_floor_ms: int = LLM_FLOOR_MS) -> list[dict[str, Any]]:
    """返回可疑归因列表；空列表 = 干净。

    每个可疑项：{id, duration_ms, tokens_recorded, attributed_via, reason}。
    """
    mode = str(report.get("mode", ""))
    suspects: list[dict[str, Any]] = []
    for item in report.get("results", []) or []:
        if not item.get("solved"):
            continue
        if not _attributed_to_llm(item, mode):
            continue
        dur = item.get("duration_ms")
        reasons: list[str] = []
        if not isinstance(dur, (int, float)):
            reasons.append("无解出时长证据")
        elif dur < llm_floor_ms:
            reasons.append(f"解出时长 {dur}ms < LLM 全链路经验下限 {llm_floor_ms}ms")
        if not _tokens_recorded(item):
            reasons.append("无 token 计费证据（无 LLM 调用凭证）")
        if reasons:
            suspects.append(
                {
                    "id": item.get("id") or item.get("question_id") or "<unknown>",
                    "duration_ms": dur,
                    "tokens_recorded": _tokens_recorded(item),
                    "attributed_via": str(item.get("solved_by") or item.get("method") or mode),
                    "reason": "；".join(reasons),
                }
            )
    return suspects


def _load(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv: list[str]) -> int:
    paths = [a for a in argv[1:] if a != "--json"]
    if not paths:
        print("用法: _attribution_fingerprint.py <benchmark_report.json> [...]", file=sys.stderr)
        return 2
    total = 0
    for p in paths:
        try:
            report = _load(p)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[input-error] {p}: {e}", file=sys.stderr)
            return 2
        suspects = audit_report(report)
        total += len(suspects)
        if suspects:
            print(f"❌ {p}: {len(suspects)} 条可疑 LLM 归因（fail-closed）")
            for s in suspects:
                print(f"   - {s['id']}: dur={s['duration_ms']}ms tokens={s['tokens_recorded']}"
                      f" via={s['attributed_via']} | {s['reason']}")
        else:
            print(f"✅ {p}: 干净（无可疑归因）")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
