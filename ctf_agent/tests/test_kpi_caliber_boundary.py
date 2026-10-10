#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KPI 台账「LLM 自主解出 = 0」的口径边界护栏（2026-10-10）。

**为什么需要这条测试**
----------------------
KPI 机器真值源（`scripts/_kpi_canonical.py`）长期写着「当前可验证的大模型自主解出数为 0」。
这句话本身有实证支撑（`real_crypto_dnui_keyboard` 在两次独立实测中均为
`solved_by=presolve`，78ms、tokens≈0），但它**没有写出适用口径**。

而 2026-10-06 的外部真题盲测给出了一个必须记下的反例：**同一道题在
`CTF_AGENT_INTERNAL_PRESOLVE=off`（关掉题首确定性预扫）口径下，由模型自身解出，
602 token**，且两套独立判分（本项目 sha256 仲裁 + 对方 `judge_external_westlake.py`）
结论一致。

于是「自主解出 = 0」这句话有两种读法：
- ✅ 在**默认配置 + 该 2 题池**口径下成立（它本来的意思）
- ❌ 被简化成「模型完全解不出 held-out 题」——把**口径问题说成能力问题**

本护栏把口径边界钉进测试：台账文案必须同时包含
①「默认配置 + 2 题池」的限定、②纯 LLM 口径的反例、③两条都不能说满的声明。
任何人日后想把它简化回无边界的「= 0」，这里必须 FAIL。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts._kpi_canonical import heldout_status, heldout_budget_ablation,     _heldout_clause  # noqa: E402


def _status_text() -> str:
    """取 heldout 台账文案（走 canonical_kpi 用的同一函数，避免两处口径漂移）。

    实现注记：初版误取 `heldout_status()`——那个函数只返回**结构化数据**
    （report/pool_total/solved_by_* …），不含任何文案，于是 6 条断言全红。
    文案真源是 `_heldout_clause(hs, abl)`。
    """
    hs = heldout_status()
    abl = heldout_budget_ablation()
    return _heldout_clause(hs, abl)


class TestHeldoutCaliberBoundary:
    """🔴 核心护栏：口径边界必须写在台账文案里，且不能被简化掉。"""

    def test_caliber_qualifier_present(self):
        text = _status_text()
        assert "口径边界" in text, (
            "KPI 台账的 heldout 文案缺少口径边界声明——"
            "「自主解出=0」必须限定在「默认配置 + 该 2 题池」口径内"
        )

    def test_default_config_qualifier_present(self):
        text = _status_text()
        assert "默认配置" in text, "必须写明该结论成立于默认配置（题首预扫开启）"
        assert "2 题池" in text or "本 2 题池" in text, "必须写明该结论的分母是 2 题池"

    def test_pure_llm_counter_example_recorded(self):
        """纯 LLM 口径的反例必须记在案：同一题在关预扫下由模型解出（602 token）。"""
        text = _status_text()
        assert "INTERNAL_PRESOLVE" in text, (
            "台账必须记录 `CTF_AGENT_INTERNAL_PRESOLVE=off` 口径下的反例，"
            "否则读者会把口径问题误读成能力问题"
        )
        assert "602" in text, "反例的具体 token 数（602）必须可核对，不写'很少 token'之类模糊说法"

    def test_both_overclaims_explicitly_forbidden(self):
        """两条都不能说满，必须明文禁止。"""
        text = _status_text()
        assert "把口径问题说成能力问题" in text, (
            "必须明文禁止「模型完全解不出 held-out 题」这类过度断言"
        )
        assert "n=1" in text, (
            "必须写明外部未见题池仅 1 道（n=1 无统计意义），"
            "禁止据此宣称「已能解」"
        )

    def test_presolve_evidence_still_present(self):
        """边界声明不得推翻原有实证：两次独立实测的 presolve 归属仍要在案。"""
        text = _status_text()
        assert "presolve" in text
        assert "78ms" in text, "原始实测证据（78ms、tokens≈0）必须保留，不能只剩结论"


class TestNoBoundarylessZeroClaim:
    """反向检查：不允许出现无边界的「自主解出数 = 0」。"""

    def test_no_unqualified_zero_claim(self):
        text = _status_text()
        # 出现"自主解出数为 0"必须紧邻口径限定词，否则视为无边界的简化断言
        idx = text.find("自主解出数为 0")
        if idx >= 0:
            window = text[max(0, idx - 200): idx + 400]
            assert ("口径边界" in window or "默认配置" in window), (
                "发现无口径限定的「自主解出数为 0」——"
                "该结论只在默认配置 + 2 题池口径下成立，必须带上限定"
            )
        else:
            # 已改写为带限定的表述，同样可接受
            assert "口径边界" in text


if __name__ == "__main__":
    sys.exit(__import__("pytest").main([__file__, "-v"]))