# -*- coding: utf-8 -*-
"""presolve 主入口 sha256 仲裁的回归锁（2026-10-09 primes 假命中遮蔽修复）。

病灶：`presolve()` 主循环 `asyncio.as_completed` 先到先得——更快路径的诱饵候选
遮蔽慢路径的真解。实测 ext_gctf2023_primes：chal.sage 内置诱饵
`CTF{YkDOLIS…}` 0.4s 抢跑 24.6s Coppersmith 真解（10-08 / 10-09 两次基线
sweep 同象，`logs/presolve_resweep_20261009.md`）。

修法（题面声明 sha256 真值时）：
  * 候选经 `_matches_expected_sha256` 验真 → 立即返回（权威，压过先到者）；
  * 未验真合格候选 → 暂存并继续等；扫完无真解才回退暂存者；
  * 无真值声明 → 行为完全不变（先到先得，零回退）。

变异验证：删掉验真直出分支 → case 1 红；删掉暂存回退 → case 3 红。
㉚ 自检：合成任务对直接打在 `presolve()` 生产入口上（monkeypatch 全部 _try_*）。
"""

from __future__ import annotations

import asyncio
import hashlib

import pytest

import core.presolve as P
from eval.cases import Question

TRUE_FLAG = "CTF{the_real_flag_value_here}"
DECOY_FLAG = "CTF{YkDOLIStjpjP5Am1SXDt5d2r9es3b5KZP47v8rXF}"
TRUE_SHA = hashlib.sha256(TRUE_FLAG.encode("utf-8")).hexdigest()


def _make_q(expected_sha: str | None) -> Question:
    data = {
        "id": "t_sha_arb",
        "category": "crypto",
        "title": "arbitration fixture",
        "description": "base64 challenge fixture",
        "flag_pattern": r"CTF\{[^}]+\}",
    }
    if expected_sha:
        data["flag_sha256"] = expected_sha
    return Question.from_dict(data)


def _patch_tasks(monkeypatch, fast, slow):
    """把全部 _try_* 打成 no-op，再注入一快一慢两个合成任务（㉚：打在生产入口上）。"""
    async def _noop(q, *a, **k):
        return None
    for name in [n for n in dir(P) if n.startswith("_try_") and callable(getattr(P, n))]:
        monkeypatch.setattr(P, name, _noop, raising=False)
    async def _fast(q, *a, **k):
        await asyncio.sleep(0)
        return fast
    async def _slow(q, *a, **k):
        await asyncio.sleep(0.05)
        return slow
    monkeypatch.setattr(P, "_try_flag_scan", _fast, raising=False)
    monkeypatch.setattr(P, "_try_math_engine", _slow, raising=False)


def test_sha_verified_candidate_beats_faster_decoy(tmp_path, monkeypatch):
    """真解（慢）必须压过更快到达的诱饵（快）——primes 遮蔽的回归锁。"""
    _patch_tasks(monkeypatch, fast=DECOY_FLAG, slow=TRUE_FLAG)
    q = _make_q(TRUE_SHA)
    got = asyncio.run(P.presolve(q, registry=None, force=True))
    assert got == TRUE_FLAG, "sha256 可验真的真解必须压过先到的未验真候选"


def test_no_truth_keeps_first_wins_behavior(tmp_path, monkeypatch):
    """无 sha256 真值声明 → 行为完全不变：先到先得（零行为回退）。"""
    _patch_tasks(monkeypatch, fast=DECOY_FLAG, slow=TRUE_FLAG)
    q = _make_q(None)
    got = asyncio.run(P.presolve(q, registry=None, force=True))
    assert got == DECOY_FLAG


def test_truth_declared_but_never_verified_falls_back(tmp_path, monkeypatch):
    """有真值声明但扫完无验真候选 → 回退暂存的先到合格候选（不比旧行为更差）。"""
    _patch_tasks(monkeypatch, fast=DECOY_FLAG, slow=None)
    q = _make_q(TRUE_SHA)
    got = asyncio.run(P.presolve(q, registry=None, force=True))
    assert got == DECOY_FLAG


def test_sha_arbitration_writes_blackboard_once(tmp_path, monkeypatch):
    """验真直出走黑板缓存入口（_cache_presolve_hit），且只写一次。"""
    _patch_tasks(monkeypatch, fast=DECOY_FLAG, slow=TRUE_FLAG)
    q = _make_q(TRUE_SHA)
    calls = []
    monkeypatch.setattr(P, "_cache_presolve_hit",
                        lambda question, flag: calls.append(flag), raising=False)
    got = asyncio.run(P.presolve(q, registry=None, force=True))
    assert got == TRUE_FLAG
    assert calls == [TRUE_FLAG]
