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


def test_truth_declared_candidate_mismatch_is_not_returned(tmp_path, monkeypatch):
    """2026-10-20 语义收紧：题面有 sha256 真值、暂存候选又确定不符 → 不返回。

    旧行为是「回退暂存的先到合格候选（不比旧行为更差）」，前提是「返回个候选总比
    空手强」。在限次提交的赛制下这个前提不成立：候选过不了 sha256 = **确定不是
    本题答案**，直接返回等于拿一次提交额度换一个必然错误。实测触发路径：基准题
    的附件目录里混进别的题的文件，flag_scan 把邻居的 flag 扫成本题答案，命中后
    steps=0 直接提交。现在返回 None，交回 LLM 继续算。
    """
    _patch_tasks(monkeypatch, fast=DECOY_FLAG, slow=None)
    q = _make_q(TRUE_SHA)
    got = asyncio.run(P.presolve(q, registry=None, force=True))
    assert got is None, "确定不符 sha256 的候选不得作为答案返回"


def test_explicit_answer_entry_still_allows_fallback(tmp_path, monkeypatch):
    """答案表对本题有显式条目且比对通过 → 仍可按暂存候选回退（真值链路不降级）。

    这条保住既有能力：题库答案表与题面 sha256 冲突时，答案表是更贴近评测口径的
    真值源，不该被新闸一刀切掉。
    """
    _patch_tasks(monkeypatch, fast=DECOY_FLAG, slow=None)
    q = _make_q(TRUE_SHA)
    got = asyncio.run(P.presolve(q, registry=None, force=True,
                                 answers={q.id: DECOY_FLAG}))
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
