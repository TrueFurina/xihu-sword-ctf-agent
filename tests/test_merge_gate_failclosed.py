# -*- coding: utf-8 -*-
"""merge_gate fail-closed 端到端验收测试（2026-08-25 红牌一复核补钉）。

背景：第九轮锐评红牌一指控"删掉 KPI_BASELINE.json 棘轮归零重来"（fail-open）。
实测 _merge_gate.py:184-189 已是 fail-closed（基线缺失 → sys.exit(1)）。
本测试把"删基线 = 硬失败"钉死成机器可查的事实，防回归。

三个场景（对应红牌一的三段验收）：
  1. 基线存在且台账 >= 基线 → kpi_check 返回 True（正常放行）
  2. 基线文件缺失 → kpi_check 抛 SystemExit(1)（删基线 = 硬失败）
  3. 台账 offline_verified 计数 < 基线 → kpi_check 返回 False（删台账行 = 硬失败）
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import scripts._merge_gate as mg


def _fake_ledger(tmp_path, n_verified: int):
    """构造含 n 条 offline_verified 状态行的临时台账。"""
    lines = ["# 测试台账\n", "\n", "## 二、离线核验解出\n"]
    for i in range(n_verified):
        lines.append(f"### 题{i}\n")
        lines.append(f"- **状态**：✅ offline_verified\n")
    p = tmp_path / "REAL_SOLVES_LEDGER.md"
    p.write_text("".join(lines), encoding="utf-8")
    return str(p)


def _fake_regression_ok(monkeypatch):
    """回归集真跑直接放行（本测试只验 KPI 计数通道，不验回归）。"""
    monkeypatch.setattr(mg, "regression_check", lambda: True)


def test_baseline_exists_and_ok(monkeypatch, tmp_path):
    """场景1：基线存在且台账 >= 基线 → 放行。"""
    ledger = _fake_ledger(tmp_path, 5)
    monkeypatch.setattr(mg, "LEDGER", ledger)
    baseline = tmp_path / "KPI_BASELINE.json"
    baseline.write_text(json.dumps({"offline_verified": 5}), encoding="utf-8")
    monkeypatch.setattr(mg, "BASELINE", str(baseline))
    _fake_regression_ok(monkeypatch)
    assert mg.kpi_check() is True, "基线存在且台账>=基线应放行"


def test_baseline_missing_fails_closed(monkeypatch, tmp_path):
    """场景2：基线文件缺失 → SystemExit(1)（删基线 = 硬失败，不重建放行）。"""
    ledger = _fake_ledger(tmp_path, 5)
    monkeypatch.setattr(mg, "LEDGER", ledger)
    missing = tmp_path / "KPI_BASELINE.json"  # 不创建 → 缺失
    monkeypatch.setattr(mg, "BASELINE", str(missing))
    _fake_regression_ok(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        mg.kpi_check()
    assert exc.value.code == 1, "基线缺失必须 exit 1（fail-closed），不得重建放行"


def test_ledger_below_baseline_fails(monkeypatch, tmp_path):
    """场景3：台账计数 < 基线 → 返回 False（删台账行 = 硬失败）。"""
    ledger = _fake_ledger(tmp_path, 3)  # 台账 3 < 基线 5
    monkeypatch.setattr(mg, "LEDGER", ledger)
    baseline = tmp_path / "KPI_BASELINE.json"
    baseline.write_text(json.dumps({"offline_verified": 5}), encoding="utf-8")
    monkeypatch.setattr(mg, "BASELINE", str(baseline))
    _fake_regression_ok(monkeypatch)
    assert mg.kpi_check() is False, "台账 3 < 基线 5 应拒绝（防删台账行重置棘轮）"
