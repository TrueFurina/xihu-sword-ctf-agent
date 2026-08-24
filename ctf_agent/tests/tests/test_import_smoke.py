"""入口 import 冒烟测试（P0 修复：防 run.py SyntaxError 复现——2026-08-21）。

今早 run.py:226 SyntaxError（并行会话 votes 代码插坏 dict）本可被 1 行测试拦住——
46 个测试里零个测入口 import。本测试锁定：
1. run.py 主入口可 import（build_solver/build_race_solver 正常）
2. 主循环入口（_race_start.py）可 import
3. 核心模块（main_agent/llm client/poller）可 import

用法：pytest tests/test_import_smoke.py（或全量 pytest 自动收集）
"""

import importlib


def test_run_import() -> None:
    """run.py 主入口可 import（SyntaxError 防线——今早 226 语法错误本可拦住）。"""
    import run

    assert hasattr(run, "build_solver"), "build_solver 缺失"
    assert hasattr(run, "build_race_solver"), "build_race_solver 缺失"


def test_race_start_import() -> None:
    """主循环入口 _race_start.py 可 import（赛时 --compete 链路）。"""
    mod = importlib.import_module("scripts._race_start")
    assert mod is not None


def test_core_modules_import() -> None:
    """核心模块可 import（main_agent/llm client/poller——主链路）。"""
    for name in ("core.main_agent", "llm.client", "ctfplatform.poller",
                 "agents.crypto_toolkit", "tools.skill_manager"):
        importlib.import_module(name)  # 抛异常即测试失败
