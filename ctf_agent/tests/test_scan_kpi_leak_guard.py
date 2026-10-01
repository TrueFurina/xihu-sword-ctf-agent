# -*- coding: utf-8 -*-
"""KPI 候选扫描的「反注水闸门」回归测试（2026-10-01）。

背景是**实测出来的真实缺陷**，不是假想：
  `scripts/_scan_kpi_candidates.py` 旧版只跳过 `answer_disclosed=True`，而
  `data/questions_real` 全池 92 题该字段**恒为 False** —— 门是死的。实测后果：
    · att_leak 题 `real_crypto_anxun2020_aes`：presolve 的附件扫描 0.2 秒内"命中"；
    · desc_leak 题 `real_crypto_dnui_keyboard`：题面直接写「解出 CLCKOUTHK」。
  旧写法把它们当 MATCH 候选输出（实测 58 条候选）。据此晋升 KPI = 把「读题目
  材料里的答案」记成「能力」。

本测试锁三件事：
  1. 来源判定（att_leak / desc_leak）必须挡在扫描之外；
  2. 判定失败必须 fail-closed（宁可漏报，不可误报）；
  3. 二段 oracle 判定必须在场（裸 token 的题面泄漏，无 oracle 判不出来）。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts._scan_kpi_candidates import (  # noqa: E402
    LEAK_PROVENANCE, _classify_provenance, split_by_leak,
)

_LEAK_JSON = _ROOT / "heldout_evidence" / "leak_provenance_real92_v3_20261001.json"
_POOL = _ROOT / "data" / "questions_real"
_ATT_ANXUN = (_POOL / "_attachments" / "crypto" / "real_crypto_anxun2020_aes")
_SKIP_POOL = "data/questions_real 未落地（.gitignore 排除，公开仓不含）"


def _have_pool() -> bool:
    return _POOL.is_dir() and any(_POOL.rglob("*.json"))


class _Q:
    """最小题目替身：split_by_leak 只依赖 id（判定器由测试注入）。"""

    def __init__(self, qid: str) -> None:
        self.id = qid


def _load_real(qid: str):
    from eval.cases import load_questions
    return {q.id: q for q in load_questions(str(_POOL), include_disclosed=True)}[qid]


# ── 1. 纯函数分区语义 ─────────────────────────────────────────────────────
def test_none_provenance_goes_to_scannable():
    q = _Q("plain")
    scannable, leaked, unknown = split_by_leak([q], lambda _q: {"provenance": "none"})
    assert [x.id for x in scannable] == ["plain"]
    assert leaked == [] and unknown == []


def test_att_and_desc_leak_are_excluded():
    qs = [_Q("ok"), _Q("att"), _Q("desc")]
    prov = {"ok": "none", "att": "att_leak", "desc": "desc_leak"}
    scannable, leaked, unknown = split_by_leak(qs, lambda q: {"provenance": prov[q.id]})
    assert [x.id for x in scannable] == ["ok"]
    assert sorted(x.id for x, _ in leaked) == ["att", "desc"]
    assert unknown == []


def test_classifier_failure_is_fail_closed():
    def boom(_q):
        raise RuntimeError("附件缺失/判定异常")

    scannable, leaked, unknown = split_by_leak([_Q("boom")], boom)
    assert scannable == [], "判定失败必须排除：候选会用于 KPI 晋升，误报=注水记成能力"
    assert [x.id for x, _ in unknown] == ["boom"]
    assert leaked == []


def test_unexpected_provenance_is_excluded():
    scannable, _leaked, unknown = split_by_leak(
        [_Q("odd")], lambda _q: {"provenance": "computed"})
    assert scannable == []
    assert [x.id for x, why in unknown] == ["odd"]


def test_mutation_widening_leak_set_is_consulted(monkeypatch):
    """【变异】把泄漏档位集合改成 ("none",) 后，普通题必须被挡住 ——
    证明 LEAK_PROVENANCE 真被 split_by_leak 读取，而不是摆设。"""
    import scripts._scan_kpi_candidates as mod

    monkeypatch.setattr(mod, "LEAK_PROVENANCE", ("none",))
    scannable, leaked, _ = split_by_leak([_Q("plain")], lambda _q: {"provenance": "none"})
    assert scannable == [], "集合被扩到含 none 后仍未挡住 → 闸门没真正读该集合"
    assert [p for _, p in leaked] == ["none"]
    assert LEAK_PROVENANCE == ("att_leak", "desc_leak"), "真实档位集合不得被改小"


def test_gate_is_two_layered_when_leak_set_is_emptied(monkeypatch):
    """【变异·第二层】即使档位集合被误改空，att_leak 也只是掉进 unknown（仍被排除）。

    这是有意为之的双层防护：leaked 认档位、unknown 兜底未知档位（fail-closed）。
    单层设计下"集合被改空"= 闸门失效；双层设计下最坏情况是保守漏报。
    """
    import scripts._scan_kpi_candidates as mod

    monkeypatch.setattr(mod, "LEAK_PROVENANCE", ())
    scannable, leaked, unknown = split_by_leak([_Q("leaky")], lambda _q: {"provenance": "att_leak"})
    assert scannable == [], "集合被改空后注水题仍不得进入扫描"
    assert leaked == []
    assert [x.id for x, _ in unknown] == ["leaky"]


# ── 2. 真实题库（缺失则跳过）───────────────────────────────────────────────
@pytest.mark.skipif(not _have_pool(), reason=_SKIP_POOL)
def test_real_att_leak_question_is_excluded():
    q = _load_real("real_crypto_anxun2020_aes")
    scannable, leaked, _ = split_by_leak([q], _classify_provenance)
    assert scannable == [], "附件里明文躺着真值的题不得进入候选扫描"
    assert [p for _, p in leaked] == ["att_leak"]


@pytest.mark.skipif(not _have_pool(), reason=_SKIP_POOL)
def test_real_desc_leak_needs_oracle_pass():
    """裸 token 题面泄漏：无 oracle 判不出、有 oracle 才判得出。

    这正是扫描器必须做「二段判定」的原因 —— 断言无 oracle 时可扫，
    是为了把"为什么需要二段"钉死；若将来单段就能判出，本断言会红，属信号不是噪声。
    """
    q = _load_real("real_crypto_dnui_keyboard")
    first, _, _ = split_by_leak([q], _classify_provenance)
    assert [x.id for x in first] == [q.id], "无 oracle 时该题落在可扫集（故必须二段）"

    second, leaked, _ = split_by_leak(
        [q], lambda x: _classify_provenance(x, {q.id: "flag{CLCKOUTHK}"}))
    assert second == [], "题面写出答案的题不得进入候选扫描"
    assert [p for _, p in leaked] == ["desc_leak"]


@pytest.mark.skipif(not (_have_pool() and _LEAK_JSON.is_file()), reason="题库或审计证据缺失")
def test_guard_blocks_evidence_att_leak_sample():
    """抽样核对：审计判为 att_leak 的题，抽样必须全部被闸门挡住（含裸 token 通道）。"""
    import json

    rows = json.loads(_LEAK_JSON.read_text(encoding="utf-8"))["rows"]
    att_ids = [r["id"] for r in rows if r["provenance"] == "att_leak"][:6]
    assert att_ids, "审计证据里应有 att_leak 样本"
    from eval.cases import load_questions
    pool = {q.id: q for q in load_questions(str(_POOL), include_disclosed=True)}
    scannable, leaked, _ = split_by_leak(
        [pool[i] for i in att_ids if i in pool], _classify_provenance)
    assert scannable == [], f"以下证据判定的注水题漏进了扫描：{[x.id for x in scannable]}"
    assert len(leaked) == len(att_ids)


@pytest.mark.skipif(
    not (_have_pool() and _ATT_ANXUN.is_dir()), reason="真实附件缺失（.gitignore 排除）")
def test_presolve_hits_att_leak_from_attachment_causally():
    """因果证据：该题确实被 presolve 在附件里命中 —— 所以只能按来源判定挡掉。"""
    import asyncio

    from core.presolve import presolve
    import scripts._scan_kpi_candidates as mod

    q = _load_real("real_crypto_anxun2020_aes")
    missing = [a for a in q.attachments
               if not (Path(str(a)) if Path(str(a)).is_absolute() else _ROOT / str(a)).exists()]
    if missing:
        pytest.skip(f"附件未落地: {missing[:2]}")
    got = asyncio.run(presolve(q, registry=mod.build_registry(), force=True))
    assert got and q.flag_matches(str(got)), "该题本就能被附件扫描命中；这正是闸门存在的原因"
