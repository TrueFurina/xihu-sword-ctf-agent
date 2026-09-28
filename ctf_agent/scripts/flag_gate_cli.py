"""解出闸门 CLI —— 任何跑批/校验都必须过的最后一道硬卡。

铁律（2026-09-28 真机真题批次1 实锤后确立）::

    正则命中 = 候选        sha256 比对 = 解出

没有答案基准（flag_sha256）时一律判「不可核验」，**绝不**记为解出（fail-closed）。

用法::

    python scripts/flag_gate_cli.py --sha256 <hex> --candidates-file hits.json
    python scripts/flag_gate_cli.py --sha256 <hex> --text "noise flag{...} flag{REAL}"
    python scripts/flag_gate_cli.py --candidates-file hits.json   # 无基准 → 必 FAIL

退出码（供 CI/脚本判定，不要用 stdout 判断成败）::

    0 = 通过校验（可记为解出）
    1 = 未通过 / 不可核验（不得记为解出）
    2 = 用法错误
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.flag_verify import FlagGate, extract_candidates  # noqa: E402


def _load_candidates(path: str) -> list[str]:
    if not os.path.exists(path):
        raise SystemExit(f"[用法错误] 候选文件不存在: {path}")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):  # 兼容 {"candidates": [...]} / {"matched": "..."} 
        if "candidates" in data:
            data = data["candidates"]
        elif "matched" in data:
            data = [data["matched"]] if data["matched"] else []
    if not isinstance(data, list):
        raise SystemExit("[用法错误] 候选必须是 JSON 数组或含 candidates 的对象")
    return [str(x) for x in data if x]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="flag 解出闸门（sha256 硬校验，fail-closed）")
    ap.add_argument("--sha256", default="", help="题目元数据里的 flag_sha256（留空=不可核验，必 FAIL）")
    ap.add_argument("--pattern", default=r"flag\{.*?\}", help="flag 正则（配合 --text 使用）")
    ap.add_argument("--candidates-file", default="", help="候选 JSON 文件（数组或 {candidates:[...]}）")
    ap.add_argument("--text", default="", help="直接给文本，用 --pattern 抽取候选")
    ap.add_argument("--json", action="store_true", help="输出 JSON（便于机器消费）")
    args = ap.parse_args(argv)

    if args.candidates_file:
        cands = _load_candidates(args.candidates_file)
    elif args.text:
        cands = extract_candidates(args.text, args.pattern)
    else:
        ap.error("必须提供 --candidates-file 或 --text")

    res = FlagGate(expected_sha256=args.sha256, flag_pattern=args.pattern).judge(cands)

    if args.json:
        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
    else:
        mark = "PASS" if res.verified else "FAIL"
        print(f"[{mark}] verified={res.verified} candidates={res.candidates} reason={res.reason}")
        if res.flag:
            print(f"        flag={res.flag}")
    return 0 if res.verified else 1


if __name__ == "__main__":
    sys.exit(main())
