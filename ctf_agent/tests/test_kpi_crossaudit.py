"""KPI 锚点 × 答案来源交叉审计（_kpi_leak_crossaudit）的判定测试。

背景：2026-10-01 干净口径复盘发现内部 92 道语料里 68 道真值 flag 物理上躺在附件/题面里。
这威胁项目唯一对外数字 `offline_verified`（README 引用的绝对计数）——本题锁住
「KPI 计入题里到底有没有泄漏」这条判据，防止 headline 数字被静默注水。

变异验证（故意改错必须 FAIL）：
  ① 关掉 A/B 类分类闸 → 计入题必须归零（证明分类闸真的在过滤）；
  ② 把唯一泄漏题的 provenance 改成 computed → 污染判决必须翻转（证明判决真的由泄漏数据驱动）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "scripts"))
import _kpi_leak_crossaudit as ka  # noqa: E402

LEDGER_SAMPLE = """# 台账

### 1. real_crypto_alpha 【A类·完整攻击链】（某赛）
- **状态**：✅ offline_verified（2026-01-01）

### 2. real_crypto_beta 【B类·presolve 确定性密码学变换】
- **状态**：✅ offline_verified（2026-01-01）

### 3. real_misc_gamma
- **状态**：✅ offline_verified（未标类别 → C 类，不计入）

### 4. real_pwn_delta 【A类·完整攻击链】
- **状态**：❌ 未核验

### 5. 99887（外部真题）
- **状态**：✅ offline_verified
"""


def _rows(**prov):
    return [{"id": k, "provenance": v} for k, v in prov.items()]


# ---------------------------------------------------------------- 台账解析

def test_parse_only_ab_class_verified():
    got = ka.parse_ledger(LEDGER_SAMPLE)
    assert [r["id"] for r in got] == ["real_crypto_alpha", "real_crypto_beta"]


def test_parse_extracts_numeric_id_and_skips_unverified():
    ids = {r["id"] for r in ka.parse_ledger(LEDGER_SAMPLE)}
    assert "real_pwn_delta" not in ids       # A 类但状态 ❌
    assert "real_misc_gamma" not in ids      # 未标类别 = C 类
    assert "99887" not in ids                # 外部真题 = E 类


# ---------------------------------------------------------------- 交叉判定

def test_attachment_leak_flags_contamination():
    r = ka.cross_audit(LEDGER_SAMPLE, _rows(real_crypto_alpha="att_leak",
                                            real_crypto_beta="computed"))
    assert r["counted"] == 2
    assert r["leak"] == 1 and r["contaminated"] is True
    assert r["leak_ids"] == ["real_crypto_alpha"]
    assert r["computed"] == 1


def test_desc_leak_also_contaminates():
    r = ka.cross_audit(LEDGER_SAMPLE, _rows(real_crypto_alpha="desc_leak",
                                            real_crypto_beta="computed"))
    assert r["contaminated"] is True and r["leak"] == 1


def test_unsolved_is_not_treated_as_leak():
    """unsolved（presolve 未命中）≠ 泄漏；不得判污染，也不得判 computed。"""
    r = ka.cross_audit(LEDGER_SAMPLE, _rows(real_crypto_alpha="unsolved",
                                            real_crypto_beta="computed"))
    assert r["contaminated"] is False
    assert r["unsolved"] == 1 and r["unsolved_ids"] == ["real_crypto_alpha"]


def test_missing_corpus_is_flagged_separately():
    """台账有记、语料无对应文件 → 单独一档，既不判泄漏也不判干净。"""
    r = ka.cross_audit(LEDGER_SAMPLE, _rows(real_crypto_alpha="computed"))
    assert r["missing_corpus"] == 1
    assert r["missing_corpus_ids"] == ["real_crypto_beta"]
    assert r["contaminated"] is False


# ---------------------------------------------------------------- 变异验证

def test_mutation_class_gate_is_load_bearing(monkeypatch):
    """变异①：把分类闸打桩成恒 C 类 → 计入题必须归零（否则分类闸形同虚设）。"""
    monkeypatch.setattr(ka, "_classify_entry", lambda _t: "C")
    assert ka.parse_ledger(LEDGER_SAMPLE) == [], \
        "变异失败：关掉 A/B 分类闸后仍有题被计入，说明分类闸没生效"


def test_mutation_leak_verdict_is_data_driven():
    """变异②：把唯一泄漏题改成 computed → 污染判决必须翻转（证明判决由数据驱动）。"""
    leaky = ka.cross_audit(LEDGER_SAMPLE, _rows(real_crypto_alpha="att_leak",
                                                real_crypto_beta="computed"))
    assert leaky["contaminated"] is True
    mutated = ka.cross_audit(LEDGER_SAMPLE, _rows(real_crypto_alpha="computed",
                                                  real_crypto_beta="computed"))
    assert mutated["contaminated"] is False, \
        "变异失败：泄漏源被改成 computed 后仍判污染，说明判决是硬编码的"


# ---------------------------------------------------------------- 真实仓库回归锁

def test_real_repo_kpi_counted_matches_canonical_and_is_leak_free():
    """真实台账 × 真实泄漏审计：计入数与权威口径一致，且**零 att/desc 泄漏**。"""
    from scripts._merge_gate import count_offline_verified
    ledger = (_ROOT / "REAL_SOLVES_LEDGER.md").read_text(encoding="utf-8")
    leak = json.loads((_ROOT / "heldout_evidence" /
                       "leak_provenance_real92_20261001.json").read_text(encoding="utf-8"))
    r = ka.cross_audit(ledger, leak["rows"])
    assert r["counted"] == count_offline_verified(), \
        "交叉审计的计入口径与 count_offline_verified() 分叉"
    assert r["contaminated"] is False, \
        f"KPI 计入题里出现了答案泄漏：{r['leak_ids']}"
