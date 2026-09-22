"""P0-3 回归：benchmark 重试循环遇「终态失败」必须短路跳过重试。

背景（2026-09-22 held-out 17 池）：benchmark 层 `for attempt in range(3)` 无条件重试、
跨轮零记忆 → 同一道 budget_exceeded 题被烧 3 遍预算。修复后：
  - 终态失败（budget_exceeded / wallclock_timeout / race_abandon /
    solver_exception / not_attempted）立即 break，只跑 1 次 attempt。
  - 非终态失败（无 flag、无 error）仍走满 max_retries（保留原校验-反馈循环行为）。

控制组（test_non_terminal_still_retries）证明短路不是把重试整段删掉——它只拦终态，
瞬时外部故障 / 正常判负仍重试。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.benchmark import run_benchmark, NON_RETRYABLE_CATEGORIES


class _Q:
    def __init__(self, qid):
        self.id = qid
        self.category = "crypto"
        self.provenance = "real_past_ctf"
        self.attachments = []


def _run(solver, max_retries=3):
    return run_benchmark([_Q("t")], solver, max_retries=max_retries, use_mock=True)


def test_terminal_budget_exceeded_short_circuits():
    calls = {"n": 0}

    def solver(q, attempt):
        calls["n"] += 1
        return {"error": {"category": "budget_exceeded"}, "flag": None}

    results = _run(solver)
    assert len(results) == 1
    # 终态失败只跑 1 次 attempt，不重烧预算
    assert results[0].retries == 1, f"期望重试 1 次，实际 {results[0].retries}"
    assert calls["n"] == 1


def test_terminal_wallclock_timeout_short_circuits():
    calls = {"n": 0}

    def solver(q, attempt):
        calls["n"] += 1
        return {"error": {"category": "wallclock_timeout"}, "flag": None}

    results = _run(solver)
    assert results[0].retries == 1
    assert calls["n"] == 1


def test_terminal_race_abandon_short_circuits():
    calls = {"n": 0}

    def solver(q, attempt):
        calls["n"] += 1
        return {"error": {"category": "race_abandon"}, "flag": None}

    results = _run(solver)
    assert results[0].retries == 1
    assert calls["n"] == 1


def test_non_terminal_still_retries():
    calls = {"n": 0}

    def solver(q, attempt):
        calls["n"] += 1
        return {"flag": None}  # 无 error 键 → 非终态，正常判负

    results = _run(solver, max_retries=3)
    # 保留原校验-反馈循环：非终态仍走满 3 次
    assert results[0].retries == 3
    assert calls["n"] == 3


def test_solved_no_retry():
    def solver(q, attempt):
        return {"flag": "flag{ok}"}

    results = _run(solver)
    assert results[0].solved is True
    assert results[0].retries == 1


def test_non_retryable_set_is_defined():
    # 变更护栏：若有人误改 NON_RETRYABLE_CATEGORIES，至少 budget_exceeded 必须仍在内，
    # 否则 2026-09-22 的「一题烧 3 遍预算」会复发。
    assert "budget_exceeded" in NON_RETRYABLE_CATEGORIES
    assert "wallclock_timeout" in NON_RETRYABLE_CATEGORIES
    assert "race_abandon" in NON_RETRYABLE_CATEGORIES
