#!/usr/bin/env python
"""静态检查门禁：ruff 分级零容忍（2026-10-21）。

**为什么需要**（不是整理癖，是一次真实事故）
--------------------------------------------
2026-10-21 全仓首扫 `ruff check --select F821,F811`，抓出 6 个真 bug：

  ① `agents/math_engine.py:_engine_caesar` —— 先 `re.search(...)` 后 `import re as _re_m`。
     凯撒引擎**每次执行必抛 NameError**，被外层 try/except 吞成 `return None`。
     症状不是报错，是"凯撒引擎永远解不出题"——**静默功能死亡**。
  ② 同文件 pkcs1 分支 `[(int(x), ...) for m in re.finditer(...)]`，`x` 从未定义。
  ③~⑥ 三个测试文件的 `__main__` 块调用改名后已不存在的函数（pytest 不收集
     `__main__`，所以测试全绿也发现不了；只有人肉 `python tests/xxx.py` 才崩）。

这些 bug 在此之前**全部躲过了 1963 条测试**：一个被异常吞噬，一个所在分支无覆盖，
三个在 pytest 眼里根本不存在。可见"测试通过"完全不能替代静态名字检查。

**分级口径**（分级而非一刀切，因为噪音量差两个数量级）
------------------------------------------------------
- 全仓零容忍：F821 未定义名 / F811 重定义 —— 跑不起来或静默失效。
- 核心目录零容忍：F401 / F841 —— core/ agents/ tools/ llm/ eval/ scheduler/
  ctfplatform/ skills/ 与根级 run.py、config.py。这些是生产路径，死导入与死变量
  会掩盖真实逻辑缺口（例：`supervisor_agent` 导入了三个错误码却从未消费，
  说明 hallucination/wrong_direction 两类错误没进差异化监督——这是缺口不是噪音）。
  F401/F841 的 per-file 豁免（tests/ scripts/ __init__.py）由 pyproject.toml 统一声明，
  本脚本不重复维护白名单，避免"两处真源漂移"。
- `tools/tools/`：历史遗留重复副本，整目录排除（理由见 pyproject.toml）。

**fail-closed**
---------------
ruff 未安装 / 执行异常 / 超时 → 返回 2（无法判定 ≠ 通过）。
退出码：0 通过 / 1 有发现 / 2 无法执行。
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 核心生产目录：F401/F841 零容忍
CORE_PATHS = [
    "core", "agents", "tools", "llm", "eval", "scheduler", "ctfplatform",
    "skills", "run.py", "config.py",
]

# 全仓：只拦"跑不起来"的名字级硬错
HARD_CODES = ["F821", "F811"]
# 核心目录：额外拦死导入/死变量
CORE_CODES = ["F401", "F841"]


def _ruff_exe() -> list[str] | None:
    """优先用 `python -m ruff`（与 venv 绑定），退化为 PATH 上的 ruff。"""
    try:
        probe = subprocess.run(
            [sys.executable, "-m", "ruff", "--version"],
            capture_output=True, text=True, timeout=30,
        )
        if probe.returncode == 0:
            return [sys.executable, "-m", "ruff"]
    except (OSError, subprocess.SubprocessError):
        pass
    exe = shutil.which("ruff")
    return [exe] if exe else None


def _run_ruff(ruff: list[str], targets: list[str], codes: list[str]) -> dict:
    """跑一次 ruff，返回 {ok, rc, findings, raw_tail}。"""
    cmd = [*ruff, "check", *targets, "--select", ",".join(codes),
           "--output-format", "concise", "--no-cache"]
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "rc": 2, "findings": [],
                "raw_tail": [f"ruff 无法执行: {exc}"], "crashed": True}
    findings = [
        ln for ln in (p.stdout or "").splitlines()
        if ln.strip() and not ln.startswith("warning") and ": " in ln
    ]
    # ruff: 0=干净 1=有发现；其它码视为无法判定（fail-closed）
    crashed = p.returncode not in (0, 1)
    return {
        "ok": p.returncode == 0 and not crashed,
        "rc": p.returncode,
        "findings": findings,
        "raw_tail": ((p.stdout or "") + (p.stderr or "")).strip().splitlines()[-4:],
        "crashed": crashed,
    }


def run(verbose: bool = False) -> dict:
    ruff = _ruff_exe()
    if ruff is None:
        return {
            "passed": False, "rc": 2,
            "reason": "ruff 未安装或不可执行（fail-closed：无法判定不等于通过）",
            "checks": [],
        }

    checks = []
    # 检查一：全仓名字级硬错
    hard = _run_ruff(ruff, ["."], HARD_CODES)
    checks.append({
        "key": "hard_names", "title": f"全仓 {'/'.join(HARD_CODES)}（跑不起来的名字错）",
        **hard,
    })
    # 检查二：核心目录死导入/死变量
    core = _run_ruff(ruff, CORE_PATHS, CORE_CODES)
    checks.append({
        "key": "core_deadcode", "title": f"核心目录 {'/'.join(CORE_CODES)}（死导入/死变量）",
        **core,
    })

    passed = all(c["ok"] for c in checks)
    return {
        "passed": passed,
        "rc": 0 if passed else (2 if any(c.get("crashed") for c in checks) else 1),
        "checks": checks,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="ruff 分级静态门禁（F821/F811 全仓，F401/F841 核心目录）")
    ap.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    ap.add_argument("-v", "--verbose", action="store_true", help="通过时也打印明细")
    args = ap.parse_args()

    res = run(verbose=args.verbose)

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        for c in res.get("checks", []):
            mark = "✅" if c.get("ok") else "❌"
            print(f"{mark} {c['title']}  (rc={c.get('rc')})")
            if not c.get("ok") or args.verbose:
                for ln in c.get("findings", [])[:20] or c.get("raw_tail", []):
                    print(f"    {ln}")
        if res.get("reason"):
            print(f"⚠️  {res['reason']}")
        print("静态门禁：" + ("通过" if res["passed"] else "未通过"))
    return res["rc"]


if __name__ == "__main__":
    sys.exit(main())
