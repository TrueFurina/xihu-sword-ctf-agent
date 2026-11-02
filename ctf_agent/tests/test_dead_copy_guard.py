# -*- coding: utf-8 -*-
"""死副本不得复活（2026-11-01 审计补）。

`tools/tools/` 是 `tools/` 的旧副本（21 个 .py / 150 KB）：
  · 全仓无人 import（只有一处 docstring 提到）；
  · **已经落后**：`flag_scan_adapter.py` 少 16 行，缺 `HTB{}` 通用前缀、
    body 排除 NUL 等 4 项修复；`flag_extract_guard.py` 反过来多一行
    `low = text.lower()`（死变量，真身已清理）；
  · `base.py` 少 8 行。

`pyproject.toml` 与 `_gate_static.py` 都写了"历史遗留重复副本，整目录排除，
待人工确认后清理"。这句话负责，但"待确认"没有承接人，所以它一直在。

真正的风险不是 150 KB：
**有人搜 `flag_scan_adapter` 会找到两份，改错那份也能跑通，但改的是过期代码。**
过期代码比没有代码更危险——它看起来是存在的。

本文件锁住：
  · 任何代码不得 import 死副本（一旦启用立刻红）
  · 死副本与真身的差异必须可枚举（防止它被"修好"从而以假乱真）
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import importlib.util
import pathlib

import pytest

_SCRIPT = pathlib.Path(_ROOT) / "scripts" / "_check_dead_copy.py"


@pytest.fixture(scope="module")
def dc():
    spec = importlib.util.spec_from_file_location("_deadcopy", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_code_imports_dead_copy(dc):
    """全仓不得 import 死副本。

    这是最重要的一条：一旦有人开始用 `tools.tools.*`，
    他改的、跑的都是过期代码，而系统看起来完全正常。
    """
    bad = dc.check_imports("tools/tools")
    assert bad == [], f"有代码 import 了死副本：{bad}"


def test_dead_copy_still_exists_and_is_registered(dc):
    """副本还在时，必须仍被登记（防止它悄悄消失后守卫失去意义）。"""
    if not os.path.isdir(os.path.join(_ROOT, "tools", "tools")):
        pytest.skip("死副本已被清理——若已确认，请从 DEAD_COPIES 移除本条")
    assert any(d == "tools/tools" for d, _, _ in dc.DEAD_COPIES)


def test_divergence_is_enumerable(dc):
    """与真身的差异必须能被枚举出来（不判红，但必须可见）。

    `pyproject.toml` 说"待人工确认后清理"——可确认的前提是**知道差在哪**。
    这条保证差异清单随时可算出，而不是靠人肉 diff。
    """
    if not os.path.isdir(os.path.join(_ROOT, "tools", "tools")):
        pytest.skip("死副本已被清理")
    div = dc.check_divergence("tools/tools", "tools")
    assert div, "死副本与真身完全没有差异？请复核是否已同步（同步后应直接清理）"
    # 至少 flag_scan_adapter 应当仍落后于真身
    joined = "\n".join(div)
    assert "flag_scan_adapter" in joined, "预期 flag_scan_adapter 与真身不同"


def test_report_exit_zero_when_no_imports(dc):
    """端到端：无 import 时 report() 返回 0（不误判成失败）。"""
    if not os.path.isdir(os.path.join(_ROOT, "tools", "tools")):
        pytest.skip("死副本已被清理")
    assert dc.report() == 0
