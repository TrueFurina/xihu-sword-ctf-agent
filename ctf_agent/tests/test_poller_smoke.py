# -*- coding: utf-8 -*-
"""轮询层最小回归测试（P1 补强 · P0 数据链路修复回归，2026-08-21）。

背景：poller.py 此前零测试；产品官 2026-08-21 新增 429 阶梯退避 /
fast_interval 钳制 / 列表失败倍增 / [数据可达] 观测 / no-data 止损。
本文件用鸭子类型 FakePlatform 覆盖：

1. run_forever 间隔决策：
   - fast_interval <5s 钳制到 5s（防 429 风暴）
   - backoff_suggestion>0 覆盖间隔（连续 429 阶梯）
   - 列表请求失败 → 间隔倍增（上限 300s）
2. _handle_challenge no-data 止损：题面空+无附件+无靶机 → skipped_no_data，
   且日志含 "[数据可达]" 锚点（数据可达率统计用）
3. _validate_flag 幻觉防护：空白/超长/非可打印字符拦截，合法 flag 放行
4. _timeout_for 分级硬超时：EASY 600s / MEDIUM 1200s / HARD 1800s / 未知默认

设计：全部同步测试 + asyncio.run，FakePlatform 不继承抽象类（鸭子类型），
不真正联网/起子进程。
"""

import asyncio
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfplatform import poller  # noqa: E402
from ctfplatform.base import ChallengeInfo, InstanceInfo, SubmitResult  # noqa: E402


class FakePlatform:
    """最小鸭子类型平台替身（仅暴露 poller 用到的成员）。"""

    def __init__(self, challenges=None, backoff=0.0, list_ok=True):
        self._challenges = list(challenges or [])
        self._backoff = float(backoff)
        self._list_ok = list_ok
        self.submits = []

    async def list_challenges(self):
        return list(self._challenges)

    def backoff_suggestion(self, base: float) -> float:
        return self._backoff

    def last_list_ok(self) -> bool:
        return self._list_ok

    async def get_challenge(self, challenge_id: str):
        return None

    async def create_instance(self, challenge_id: str):
        return InstanceInfo(instance_id="")

    async def destroy_instance(self, challenge_id: str) -> None:
        pass

    async def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        self.submits.append((challenge_id, flag))
        return SubmitResult(accepted=True, detail="ok")


def _run(coro):
    return asyncio.run(coro)


def _make_poller(platform=None, **kw):
    kw.setdefault("use_shared_progress", False)
    return poller.PlatformPoller(platform=platform or FakePlatform(), **kw)


def _patch_sleep(monkeypatch):
    """截断 asyncio.sleep，记录间隔（不真正等待）。"""
    sleeps = []

    async def _sleep(sec):
        sleeps.append(sec)

    monkeypatch.setattr(poller.asyncio, "sleep", _sleep)
    return sleeps


# ── 1. run_forever 间隔决策 ──────────────────────────────


def test_run_forever_clamps_fast_interval(monkeypatch):
    """fast_interval=3s 被钳制到 30s（防高频 429 风暴 + 403 WAF 封禁）。

    2026-08-21 初赛教训：3s 高频轮询触发平台「疑似攻击行为」403 封禁，
    下限从 5s 提升到 30s 双保险。
    """
    sleeps = _patch_sleep(monkeypatch)
    p = _make_poller()
    _run(p.run_forever(interval=30.0, max_rounds=1,
                       fast_interval=3.0, fast_duration=999))
    assert sleeps == [30.0]


def test_run_forever_backoff_overrides_interval(monkeypatch):
    """连续 429 阶梯 60s > 轮询 30s → 覆盖为 60s。"""
    sleeps = _patch_sleep(monkeypatch)
    p = _make_poller(FakePlatform(backoff=60.0))
    _run(p.run_forever(interval=30.0, max_rounds=1))
    assert sleeps == [60.0]


def test_run_forever_list_fail_doubles_interval(monkeypatch):
    """列表请求失败 → 间隔 30*2=60s 退避。"""
    sleeps = _patch_sleep(monkeypatch)
    p = _make_poller(FakePlatform(backoff=0.0, list_ok=False))
    _run(p.run_forever(interval=30.0, max_rounds=1))
    assert sleeps == [60.0]


def test_run_forever_backoff_zero_keeps_interval(monkeypatch):
    """无 429（backoff=0）→ 不干预间隔（保持 30s）。"""
    sleeps = _patch_sleep(monkeypatch)
    p = _make_poller(FakePlatform(backoff=0.0, list_ok=True))
    _run(p.run_forever(interval=30.0, max_rounds=1))
    assert sleeps == [30.0]


# ── 2. no-data 止损 + [数据可达] 锚点 ────────────────────


def test_handle_challenge_no_data_skip(caplog):
    """题面空+无附件+无靶机 → skipped_no_data（P0-4 止损，禁空转）。"""
    p = _make_poller()
    ch = ChallengeInfo(id="x1", title="t", category="misc",
                       description="", extra={})
    with caplog.at_level(logging.INFO, logger="ctfplatform.poller"):
        rec = _run(p._handle_challenge(ch))
    assert rec.error == "skipped_no_data"
    assert "[数据可达]" in caplog.text  # 数据可达率统计锚点


def test_handle_challenge_solves_and_submits(monkeypatch):
    """有题面数据 → 走 solver 解题 + 自动提交。"""
    async def _solver(ch):
        return {"flag": "flag{ok}", "validated": True}

    plat = FakePlatform()
    p = _make_poller(plat, solver=_solver)
    ch = ChallengeInfo(id="x2", title="solve me", category="crypto",
                       description="real desc", extra={"endpoints": [{"x": 1}]})
    rec = _run(p._handle_challenge(ch))
    assert rec.flag == "flag{ok}"
    assert rec.accepted is True
    assert ("x2", "flag{ok}") in plat.submits


# ── 3. _validate_flag 幻觉防护 ───────────────────────────


def test_validate_flag_accepts_valid():
    p = _make_poller()
    ch = ChallengeInfo(id="1")
    assert p._validate_flag(ch, "flag{abc_123}") == "flag{abc_123}"


def test_validate_flag_rejects_blank_and_whitespace():
    p = _make_poller()
    ch = ChallengeInfo(id="1")
    assert p._validate_flag(ch, "   ") == ""
    assert p._validate_flag(ch, "flag{a b}") == ""  # 含空格，疑似幻觉拼接


def test_validate_flag_rejects_non_printable():
    p = _make_poller()
    ch = ChallengeInfo(id="1")
    assert p._validate_flag(ch, "flag{\x91\xe6\xff}") == ""  # 乱码


# ── 4. _timeout_for 分级硬超时 ───────────────────────────


def _ch_with_difficulty(diff: str) -> ChallengeInfo:
    return ChallengeInfo(id="1", extra={"difficulty": diff})


def test_timeout_for_difficulty():
    p = _make_poller()
    assert p._timeout_for(_ch_with_difficulty("EASY")) == 600.0
    assert p._timeout_for(_ch_with_difficulty("VERY_EASY")) == 600.0
    assert p._timeout_for(_ch_with_difficulty("MEDIUM")) == 1200.0
    assert p._timeout_for(_ch_with_difficulty("HARD")) == 1800.0
    assert p._timeout_for(_ch_with_difficulty("VERY_HARD")) == 1800.0
    assert p._timeout_for(_ch_with_difficulty("")) == 900.0  # 未知难度默认
