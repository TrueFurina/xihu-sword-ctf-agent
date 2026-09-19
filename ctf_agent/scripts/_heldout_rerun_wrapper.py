#!/usr/bin/env python3
"""held-out 重跑隔离 wrapper（2026-09-19）。

红线背景（并发写入事故 2026-09-17）：benchmark_heldout.py 的 RUN_DIR/OUT_DIR/MANIFEST
硬编码在共享目录，直接跑会 rmtree 共享 heldout_run/、覆盖共享 heldout/benchmark_report.json
（1/10 真值报告）。本 wrapper 把三个可写路径全部重定向到带 tag 的唯一目录，
源题库 QUESTIONS_REAL 与黑板冷启动备份逻辑保持不变（诚实口径不动）。

用法：
  python scripts/_heldout_rerun_wrapper.py --tag v20260919a -- --run --provider deepseek --wallclock 300 --limit 2
  （--tag 后的参数原样透传给 benchmark_heldout.main()）
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark_heldout as bh  # noqa: E402


def main() -> int:
    args = sys.argv[1:]
    tag = "rerun"
    if "--tag" in args:
        i = args.index("--tag")
        tag = args[i + 1]
        del args[i:i + 2]
    if "--" in args:
        i = args.index("--")
        args = args[i + 1:]
    if "--tag" in args or not args:
        print(__doc__)
        return 2

    # 模块级常量在 main() 调用前覆盖（函数运行时读全局，覆盖生效）
    bh.MANIFEST = bh.RESULTS / f"heldout_candidates_{tag}.json"
    bh.RUN_DIR = bh.RESULTS / f"heldout_run_{tag}"
    bh.OUT_DIR = bh.RESULTS / f"heldout_{tag}"
    # BLACKBOARD 保持真值路径：冷启动（备份→清空→恢复）是诚实口径的一部分，
    # 防跨会话 flag 缓存命中污染 unseen 成绩。跑前已确认无并发 python 进程。

    print(f"[wrapper] 隔离重定向 tag={tag}")
    print(f"[wrapper]   MANIFEST -> {bh.MANIFEST.name}")
    print(f"[wrapper]   RUN_DIR  -> {bh.RUN_DIR.name}")
    print(f"[wrapper]   OUT_DIR  -> {bh.OUT_DIR.name}（共享 heldout/ 真值报告不受影响）")

    sys.argv = [sys.argv[0]] + args
    return bh.main()


if __name__ == "__main__":
    raise SystemExit(main())
