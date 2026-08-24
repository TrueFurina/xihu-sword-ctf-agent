# -*- coding: utf-8 -*-
"""B-20 回归测试：重型模型升级判定（决赛备战 2026-08-21）。

验证：EASY/MEDIUM crypto 首步不烧重型模型；仅 HARD/VERY_HARD 首步重型；
crypto/pwn/reverse 的简单题卡壳重试(attempt>=1)才升级；已升级/高 attempt 不再升级。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.main_agent import _should_upgrade_heavy


def test_easy_crypto_first_attempt_light():
    """EASY crypto 首步（attempt=0）不升级重型——简单题走轻量。"""
    assert _should_upgrade_heavy("EASY", "crypto", 0) is False


def test_medium_crypto_first_attempt_light():
    """MEDIUM crypto 首步不升级（B-20 核心：避免正式赛简单 crypto 浪费 reasoner）。"""
    assert _should_upgrade_heavy("MEDIUM", "crypto", 0) is False


def test_hard_crypto_first_attempt_heavy():
    """HARD crypto 首步升级重型（深推理从头介入）。"""
    assert _should_upgrade_heavy("HARD", "crypto", 0) is True


def test_very_hard_any_cat_heavy():
    """VERY_HARD 任意题型首步重型。"""
    assert _should_upgrade_heavy("VERY_HARD", "misc", 0) is True


def test_medium_crypto_retry_upgrades():
    """crypto 简单题卡壳重试（attempt=1）才升级重型。"""
    assert _should_upgrade_heavy("MEDIUM", "crypto", 1) is True


def test_medium_crypto_attempt2_no_upgrade():
    """attempt>=2 不再升级（已重型）。"""
    assert _should_upgrade_heavy("MEDIUM", "crypto", 2) is False


def test_already_upgraded_no_double():
    """已升级过（upgrades!=0）不重复升级。"""
    assert _should_upgrade_heavy("HARD", "crypto", 0, upgrades=1) is False


def test_easy_web_retry_still_light():
    """非 hard 类目（web）简单题即使重试也不重型。"""
    assert _should_upgrade_heavy("EASY", "web", 1) is False


def test_unknown_difficulty_crypto_first_light():
    """难度未知（空串）crypto 首步走轻量（保守不烧重型）。"""
    assert _should_upgrade_heavy("", "crypto", 0) is False
