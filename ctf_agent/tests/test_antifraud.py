# -*- coding: utf-8 -*-
"""反注水法令（写死）单测：各法条 must fail-closed，干净态 must 通过。

覆盖：
  WATERMARK_DRIFT    KPI 计数溢出地板+晋升（无对应证据化晋升）→ 阻断
  WATERMARK_REGRESSION KPI 计数跌破不可下破地板 → 阻断
  PROMOTION_WITHOUT_EVIDENCE 白名单含超额题块却无证据 → 阻断
  UNAUTHORIZED_SOLVE 未授权题块计入严格 KPI（走私） → 阻断
  KPI_REGRESSION     授权题块被擅自降级 → 阻断
  BASELINE_TAMPER    基线锚文件被篡改 → 阻断
  LEAKED_DEMO        仓库含硬编码真 flag / 预植答案 → 阻断
  STAGED_LEAK        暂存区含泄露 → 阻断
  LEAKED_FAKE_LLM    commit message 以 LLM 突破包装泄露式假验证 → 阻断
  LEAKED_FLAG_IN_MSG commit message 含硬编码真 flag → 阻断
  违规账              每一次注水企图都落账（永久、可审计）
"""
import os
import sys
import json

_CTFA = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _CTFA)
sys.path.insert(0, os.path.join(_CTFA, "scripts"))

import pytest

import _antifraud as af

# 让 session_id 走环境变量，避免测试中调用 git
os.environ.setdefault("CT_AGENT_SESSION", "test-antifraud")


@pytest.fixture
def tmp_violation_log(tmp_path, monkeypatch):
    """把违规账重定向到临时文件，避免污染真实 governance/anti_fraud/violations.jsonl。"""
    p = tmp_path / "violations.jsonl"
    monkeypatch.setattr(af, "GOV_DIR", str(tmp_path))
    monkeypatch.setattr(af, "VIOLATION_LOG", str(p))
    return p


def _read_log(p):
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


# ── 干净态：真实仓库执法应通过 ──
def test_clean_enforce_passes():
    ok, v = af.enforce("full")
    assert ok is True, f"干净态不应检出注水：{v}"
    assert v == []


def test_kpi_watermark_floor_is_nine():
    # 写死真值锚，不得依赖任何外部文件；水位 = 地板9 + 证据化晋升数
    # 2026-09-03 正式提升：ezrsa + simplelegendre + exciting_inverse 三道经
    # PROMOTION_EVIDENCE 带证据晋级（地板 9 + 晋升 3 = 水位 12）
    assert af.BASE_WATERMARK == 9
    assert af.KPI_WATERMARK == 12
    assert len(af.AUTHORIZED_KPI_SOLVES) == 12
    assert "real_crypto_ezrsa" in af.AUTHORIZED_KPI_SOLVES
    assert "real_crypto_simplelegendre" in af.AUTHORIZED_KPI_SOLVES
    assert "real_crypto_exciting_inverse" in af.AUTHORIZED_KPI_SOLVES
    # 晋升必须带可审计证据（PROMOTION_WITHOUT_EVIDENCE 反之阻断）
    assert af.PROMOTION_EVIDENCE["real_crypto_ezrsa"].startswith("sha256:93be5f3a")
    assert "REGRESS_PASS" in af.PROMOTION_EVIDENCE["real_crypto_ezrsa"]
    assert af.PROMOTION_EVIDENCE["real_crypto_simplelegendre"].startswith("sha256:75e6aa4d")
    assert "REGRESS_PASS" in af.PROMOTION_EVIDENCE["real_crypto_simplelegendre"]
    assert af.PROMOTION_EVIDENCE["real_crypto_exciting_inverse"].startswith("sha256:4b84616c")
    assert "REGRESS_PASS" in af.PROMOTION_EVIDENCE["real_crypto_exciting_inverse"]


# ── 治理修复防御性测试（防止 KPI 注水回归） ──
def test_10732_governance_fix_not_in_kpi_watermark():
    """2026-09-03 10732 治理修复：可机器复现（REGRESSION_CHECKS 含 10732）+ 不进严格 KPI
    （KPI_WATERMARK 仍 12 / AUTHORIZED 不含 10732）双状态成立。
    防御：禁止任何人擅自把 10732 加入 BASE_AUTHORIZED_KPI_SOLVES 或 PROMOTION_EVIDENCE
    （会触发自我授权注水，违反诚信红线）。"""
    # KPI_WATERMARK 应保持 12（vnctf/10732 治理都不动水位）
    assert af.KPI_WATERMARK == 12, (
        f"KPI_WATERMARK 应保持 12，{af.KPI_WATERMARK} 表示被擅自篡改"
    )
    assert len(af.AUTHORIZED_KPI_SOLVES) == 12
    # 10732 不应在 AUTHORIZED_KPI_SOLVES（会触发 WATERMARK_DRIFT 因台账已可机器复现）
    assert "10732" not in af.AUTHORIZED_KPI_SOLVES, (
        "10732 不应在 AUTHORIZED_KPI_SOLVES，否则与台账题块"
        "「✅ 可机器复现 + ⛔ 不进严格 KPI」双标状态冲突——会触发 WATERMARK_DRIFT"
    )
    # 10732 不应在 PROMOTION_EVIDENCE（无外部 sha256 真值闭环，自我授权红线）
    assert "10732" not in af.PROMOTION_EVIDENCE, (
        "10732 不应在 PROMOTION_EVIDENCE——其 sha256 来源是 verifier+vision LLM "
        "自我闭环（无外部真值校验），写入 PROMOTION_EVIDENCE 等于自我授权"
    )
    # REGRESSION_CHECKS 应含 10732（可机器复现闭环）
    from scripts._merge_gate import REGRESSION_CHECKS, KNOWN_GAP
    ids = [r["id"] for r in REGRESSION_CHECKS]
    assert "10732" in ids, f"REGRESSION_CHECKS 应含 10732，当前：{ids}"
    # KNOWN_GAP 应不含 10732（已治理移除）
    gap_ids = [g["id"] for g in KNOWN_GAP]
    assert "10732" not in gap_ids, f"KNOWN_GAP 应不含 10732（已治理移除），当前：{gap_ids}"


def test_vnctf_flag_governance_fix_in_base_authorized():
    # 2026-09-03 治理修复：vnctf_flag 题面 flag_pattern 写错（flag{...} 而真值格式
    # vnctf{...}）致 presolve 二次校验误判诱饵丢弃；修题面+修 venv certifi/httpx 后
    # REGRESS_PASS(5159ms) 命中。本题本就含于 9 地板（KPI 水位不变仍 12），但必须
    # 验证它真在 AUTHORIZED_KPI_SOLVES 中（防后续误移出）。
    assert "real_misc_vnctf_flag" in af.BASE_AUTHORIZED_KPI_SOLVES
    assert "real_misc_vnctf_flag" in af.AUTHORIZED_KPI_SOLVES
    # 治理修复不新增 PROMOTION_EVIDENCE 项（水位锚写死 9+晋升数=12 不变）
    assert len(af.PROMOTION_EVIDENCE) == 3
    assert len(af.AUTHORIZED_KPI_SOLVES) == 12
    assert af.KPI_WATERMARK == 12


# ── WATERMARK_DRIFT / WATERMARK_REGRESSION ──
def test_watermark_drift_blocked(tmp_violation_log, monkeypatch):
    # 计数溢出地板+晋升（无对应晋升记录）→ 阻断
    monkeypatch.setattr(af, "count_offline_verified", lambda: 13)
    v = af.check_kpi_watermark()
    assert any(r["rule"] == "WATERMARK_DRIFT" for r in v)
    assert any(r["rule"] == "WATERMARK_DRIFT" for r in _read_log(tmp_violation_log))


def test_watermark_above_floor_blocked(tmp_violation_log, monkeypatch):
    # 13 > 地板9+晋升3=水位12 但无对应晋升记录 → 仍判 WATERMARK_DRIFT（溢出无证据）
    monkeypatch.setattr(af, "count_offline_verified", lambda: 13)
    v = af.check_kpi_watermark()
    assert any(r["rule"] == "WATERMARK_DRIFT" for r in v)


def test_watermark_regression_blocked(tmp_violation_log, monkeypatch):
    # 跌破不可下破地板 → WATERMARK_REGRESSION
    monkeypatch.setattr(af, "count_offline_verified", lambda: 8)
    v = af.check_kpi_watermark()
    assert any(r["rule"] == "WATERMARK_REGRESSION" for r in v)


def test_ledger_missing_blocked(tmp_violation_log, monkeypatch):
    monkeypatch.setattr(af, "count_offline_verified", lambda: -1)
    v = af.check_kpi_watermark()
    assert any(r["rule"] == "LEDGER_MISSING" for r in v)


# ── PROMOTION_WITHOUT_EVIDENCE ──
def test_promotion_without_evidence_blocked(tmp_violation_log, monkeypatch):
    # 白名单含超额题块却无证据 → 阻断
    monkeypatch.setattr(af, "AUTHORIZED_KPI_SOLVES", frozenset(["real_crypto_new"]))
    monkeypatch.setattr(af, "BASE_AUTHORIZED_KPI_SOLVES", frozenset())
    monkeypatch.setattr(af, "PROMOTION_EVIDENCE", {})
    v = af.check_promotion_evidence()
    assert any(r["rule"] == "PROMOTION_WITHOUT_EVIDENCE" for r in v)
    assert any(r["rule"] == "PROMOTION_WITHOUT_EVIDENCE" for r in _read_log(tmp_violation_log))


def test_promotion_with_evidence_ok(tmp_violation_log, monkeypatch):
    # 超额题块带证据 → 通过
    monkeypatch.setattr(af, "AUTHORIZED_KPI_SOLVES", frozenset(["real_crypto_new"]))
    monkeypatch.setattr(af, "BASE_AUTHORIZED_KPI_SOLVES", frozenset())
    monkeypatch.setattr(af, "PROMOTION_EVIDENCE",
                        {"real_crypto_new": "sha256:abcd|verify:scripts/_regress_one.py real_crypto_new"})
    assert af.check_promotion_evidence() == []


# ── UNAUTHORIZED_SOLVE / KPI_REGRESSION ──
def test_unauthorized_solve_blocked(tmp_violation_log, monkeypatch):
    monkeypatch.setattr(af, "_ledger_counted_ids",
                        lambda: (set(af.AUTHORIZED_KPI_SOLVES), {"### X. fake_crypto_xyz 【A类】"}))
    v = af.check_authorized_set()
    assert any(r["rule"] == "UNAUTHORIZED_SOLVE" for r in v)
    assert any(r["rule"] == "UNAUTHORIZED_SOLVE" for r in _read_log(tmp_violation_log))


def test_kpi_regression_blocked(tmp_violation_log, monkeypatch):
    known = set(af.AUTHORIZED_KPI_SOLVES)
    known.discard("10733")
    monkeypatch.setattr(af, "_ledger_counted_ids", lambda: (known, set()))
    v = af.check_authorized_set()
    assert any(r["rule"] == "KPI_REGRESSION" for r in v)


def test_authorized_set_clean(tmp_violation_log, monkeypatch):
    monkeypatch.setattr(af, "_ledger_counted_ids",
                        lambda: (set(af.AUTHORIZED_KPI_SOLVES), set()))
    assert af.check_authorized_set() == []


# ── BASELINE_TAMPER ──
def test_baseline_tamper_blocked(tmp_violation_log, monkeypatch, tmp_path):
    bp = tmp_path / "KPI_BASELINE.json"
    bp.write_text(json.dumps({"offline_verified": 99}), encoding="utf-8")
    monkeypatch.setattr(af, "BASELINE", str(bp))
    v = af.check_baseline_consistency()
    assert any(r["rule"] == "BASELINE_TAMPER" for r in v)
    assert any(r["rule"] == "BASELINE_TAMPER" for r in _read_log(tmp_violation_log))


def test_baseline_consistent_ok(tmp_violation_log, monkeypatch, tmp_path):
    bp = tmp_path / "KPI_BASELINE.json"
    bp.write_text(json.dumps({"offline_verified": af.KPI_WATERMARK}), encoding="utf-8")
    monkeypatch.setattr(af, "BASELINE", str(bp))
    assert af.check_baseline_consistency() == []


# ── LEAKED_DEMO ──
def test_leaked_demo_blocked(tmp_violation_log, monkeypatch):
    monkeypatch.setattr(af, "scan_leaked_demo", lambda: False)
    v = af.check_leaked_demo()
    assert any(r["rule"] == "LEAKED_DEMO" for r in v)
    assert any(r["rule"] == "LEAKED_DEMO" for r in _read_log(tmp_violation_log))


# ── STAGED_LEAK ──
def test_staged_leak_blocked_precommit(tmp_violation_log, monkeypatch):
    monkeypatch.setattr(af, "count_offline_verified", lambda: 9)
    monkeypatch.setattr(af, "scan_leaked_demo", lambda: True)
    monkeypatch.setattr(af, "_ledger_counted_ids",
                        lambda: (set(af.AUTHORIZED_KPI_SOLVES), set()))
    monkeypatch.setattr(af, "BASELINE", os.devnull)
    monkeypatch.setattr(af, "scan_staged_leaked", lambda: False)
    ok, v = af.enforce("pre_commit")
    assert ok is False
    assert any(r["rule"] == "STAGED_LEAK" for r in v)


# ── LEAKED_FAKE_LLM (commit message) ──
def test_llm_claim_with_leak_blocked(tmp_violation_log, monkeypatch):
    monkeypatch.setattr(af, "scan_staged_leaked", lambda: False)
    v = af.check_commit_message("feat: LLM 推理贡献从 0 突破")
    assert any(r["rule"] == "LEAKED_FAKE_LLM" for r in v)
    assert any(r["rule"] == "LEAKED_FAKE_LLM" for r in _read_log(tmp_violation_log))


def test_llm_claim_clean_ok(tmp_violation_log, monkeypatch):
    monkeypatch.setattr(af, "scan_staged_leaked", lambda: True)
    assert af.check_commit_message("feat: LLM 推理贡献从 0 突破") == []


def test_plain_message_ok(tmp_violation_log, monkeypatch):
    monkeypatch.setattr(af, "scan_staged_leaked", lambda: True)
    assert af.check_commit_message("chore: 重构工具链") == []


# ── LEAKED_FLAG_IN_MSG ──
def test_leaked_flag_in_msg_blocked(tmp_violation_log):
    msg = f"feat: 解出 {af.LEAKED_REAL_FLAG}"
    v = af.check_commit_message(msg)
    assert any(r["rule"] == "LEAKED_FLAG_IN_MSG" for r in v)
    assert any(r["rule"] == "LEAKED_FLAG_IN_MSG" for r in _read_log(tmp_violation_log))
