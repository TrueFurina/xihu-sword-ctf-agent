# -*- coding: utf-8 -*-
"""分级墙钟映射回归单测（2026-08-21 P0-2 difficulty/升级映射修复）。

针对 core/main_agent.MainAgent._wallclock_for 的难度→墙钟映射：
- EASY/VERY_EASY → 120s（简单题快速止损，抢一血窗口）
- HARD/VERY_HARD → 480s（难题深推理窗口；P1-2 由 600s 下调，≤ specialcurve2 487s 灾难值）
- 未知/空 difficulty → 默认 per_question_wallclock（300s，防守性兜底）
- difficulty 大小写不敏感（内部 .upper() 归一）

防死代码复发：任一分支被误删/改错（例如全部落回 300s 默认），本测试立即失败。

⚠️ 注意：main_agent.py 存在 .bak_p0（Archi 修改中）。本测试锁定的是「难度→墙钟
映射表契约」而非具体读取字段：run.py O1 联动（2026-08-21）同时写入
question.difficulty 与 question.extra["difficulty"]，故用例双字段同置，
对两种实现路径均稳健。若 Archi 后续改动破坏映射表，本测试应仍能捕获。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace
from core.main_agent import MainAgent


def _make_question(difficulty=""):
    """构造带 difficulty 的假 Question（与 run.py O1 联动契约一致：双字段同置）。"""
    return SimpleNamespace(
        id="t1",
        category="crypto",
        title="test",
        description="",
        flag_pattern=r"flag\{[^}]+\}",
        attachments=None,
        difficulty=difficulty,
        extra={"difficulty": difficulty},
    )


def _make_agent(wallclock=300, hard_wallclock=480):
    return MainAgent(per_question_wallclock=wallclock, hard_wallclock=hard_wallclock)


def test_hard_wallclock_480s():
    """difficulty='hard' → 墙钟 480s（难题深推理窗口，P1-2 由 600s 下调）。"""
    agent = _make_agent()
    assert agent._wallclock_for(_make_question("hard")) == 480.0
    print("✓ test_hard_wallclock_480s")


def test_easy_wallclock_120s():
    """difficulty='easy' → 墙钟 120s（简单题快速止损，抢一血窗口）。"""
    agent = _make_agent()
    assert agent._wallclock_for(_make_question("easy")) == 120.0
    print("✓ test_easy_wallclock_120s")


def test_empty_difficulty_default_300s():
    """difficulty=''（空/未知）→ 墙钟 300s（防守性默认，不误伤普通题）。"""
    agent = _make_agent()
    assert agent._wallclock_for(_make_question("")) == 300.0
    print("✓ test_empty_difficulty_default_300s")


def test_missing_difficulty_default_300s():
    """difficulty 完全缺失（无字段无 extra）→ 仍 300s（getattr/空字典兜底）。"""
    agent = _make_agent()
    q = SimpleNamespace(id="t", difficulty="", extra={})
    assert agent._wallclock_for(q) == 300.0
    print("✓ test_missing_difficulty_default_300s")


def test_very_easy_and_very_hard_aliases():
    """VERY_EASY→120s、VERY_HARD→480s（映射表别名分支不回归）。"""
    agent = _make_agent()
    assert agent._wallclock_for(_make_question("very_easy")) == 120.0
    assert agent._wallclock_for(_make_question("very_hard")) == 480.0
    print("✓ test_very_easy_and_very_hard_aliases")


def test_medium_default_300s():
    """difficulty='medium' → 300s（未显式列出，落默认分支）。"""
    agent = _make_agent()
    assert agent._wallclock_for(_make_question("medium")) == 300.0
    print("✓ test_medium_default_300s")


def test_difficulty_case_insensitive():
    """大小写不敏感：'HARD'/'Hard'、'EASY' 与全小写结果一致（.upper() 归一）。"""
    agent = _make_agent()
    assert agent._wallclock_for(_make_question("HARD")) == 480.0
    assert agent._wallclock_for(_make_question("Hard")) == 480.0
    assert agent._wallclock_for(_make_question("EASY")) == 120.0
    print("✓ test_difficulty_case_insensitive")


def test_injected_wallclock_overrides_unknown_default():
    """per_question_wallclock 注入值优先于默认 300s；HARD 分支读 hard_wallclock 独立档。"""
    agent = _make_agent(wallclock=600)
    assert agent._wallclock_for(_make_question("")) == 600.0  # 未知 → 注入值
    assert agent._wallclock_for(_make_question("hard")) == 480.0  # HARD → hard_wallclock 默认 480
    assert agent._wallclock_for(_make_question("easy")) == 120.0  # 映射表 120，不受注入影响
    print("✓ test_injected_wallclock_overrides_unknown_default")


def test_hard_wallclock_injectable():
    """HARD 墙钟可通过 hard_wallclock 参数注入覆盖（480 默认，可覆盖为 600）。"""
    agent = _make_agent(hard_wallclock=600)
    assert agent._wallclock_for(_make_question("hard")) == 600.0
    print("✓ test_hard_wallclock_injectable")


if __name__ == "__main__":
    test_hard_wallclock_480s()
    test_easy_wallclock_120s()
    test_empty_difficulty_default_300s()
    test_missing_difficulty_default_300s()
    test_very_easy_and_very_hard_aliases()
    test_medium_default_300s()
    test_difficulty_case_insensitive()
    test_injected_wallclock_overrides_unknown_default()
    test_hard_wallclock_injectable()
    print("=== 分级墙钟映射回归单测全部通过 ===")
