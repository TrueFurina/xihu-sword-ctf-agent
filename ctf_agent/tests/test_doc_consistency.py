# -*- coding: utf-8 -*-
"""文档↔实现一致性校验器（scripts/_doc_consistency.py）单测。

覆盖：
- 状态断言漂移检测 + 三个避免误报的边界（引号提及 / 否定表述 / 批判文档豁免）
- KPI 数字漂移（2026-09-12 新增）：声明位数字 ≠ 机器计数即报红，含 README / 台账 /
  基线 / KPI_WATERMARK 四个位，以及「锚点缺失不误报」「取不到真值不误报」
  「历史演进叙述（12→13）不误报」三条边界
- KPI 闸门盲区加固（2026-09-19 新增，P0-3）：
  D1 公开声明文件（README.md / README.zh.md）必须保留声明行，整行删掉即红；
  D2 正文习语 `offline_verified=<n>` 全文扫，≠ 机器计数即红（箭头式历史叙述不误报）；
  D3 含 contribution/自主推理贡献 的行，`0/<分母>` 分母白名单 = {count, heldout}
  （heldout 取自 _kpi_canonical，禁硬编码）
- 真实仓库回归守卫 test_live_repo_*：只改一处文档即红
  （已做变异验证：台账汇总行 13→12 / README 正文 =13 / ZH 删声明行 / 0/13 → FAIL）
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _doc_consistency as dc  # noqa: E402


def test_stale_assertion_hits():
    """裸的过时断言命中（真的声称"单写者全局租约"）。"""
    hits = dc.check_stale_assertions("x.md", "当前执法层实现为单写者全局租约")
    assert any("单写者全局租约" in h for h in hits)


def test_quoted_mention_exempt():
    """引号包裹的「提及」不命中（治理记录引用违规词说明已去掉）。"""
    assert dc.check_stale_assertions("x.md", "原协议声称「单写者全局租约」，已修订") == []


def test_negation_exempt():
    """否定表述不命中（"不再是单写者全局租约锁"）。"""
    assert dc.check_stale_assertions("x.md", "不再是一次仅一个会话可写的单写者全局租约锁") == []


def test_review_doc_exempt():
    """批判/审查类文档豁免（锐评引用过时断言是在批评它）。"""
    hits = dc.check_stale_assertions("CTDE协同协议-锐评-20260823.md", "协议声称单写者全局租约，实测已落地")
    assert hits == []


def test_missing_file_detected(monkeypatch, tmp_path):
    """关键文件缺失时检测出来（TASK_BOARD.md 不存在）。"""
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "DOC_ROOT", str(tmp_path / "deliverables"))
    monkeypatch.setattr(dc, "_REQUIRED_FILES", ("TASK_BOARD.md",))
    hits = dc.check_missing_files()
    assert any("TASK_BOARD.md" in h for h in hits)


# ── KPI 数字漂移（2026-09-12 新增）───────────────────────────────────────
# 触发本闸门的真实事故：specialcurve2 晋级 12→13 后，README 与台账第二节都改了 13，
# 台账第五节汇总行仍写 12 —— 而当时 26 个一致性/反注水测试全绿（旧校验只查措辞）。

_LEDGER_PAT = dict(dc._KPI_DECL_PATTERNS)["REAL_SOLVES_LEDGER.md"]
_README_PAT = dict(dc._KPI_DECL_PATTERNS)[os.path.join(os.path.pardir, "README.md")]


def test_kpi_ledger_declaration_drift_detected(monkeypatch, tmp_path):
    """台账第五节汇总行数字 ≠ 机器计数 → 必须报漂移。"""
    (tmp_path / "L.md").write_text(
        "| **严格真题 offline_verified（唯一 KPI，merge_gate 机器真值）** | **12** |\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", (("L.md", _LEDGER_PAT),))
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 13, 13))
    hits = dc.check_kpi_number_consistency()
    assert any("12" in h and "13" in h for h in hits), hits


def test_kpi_readme_declaration_drift_detected(monkeypatch, tmp_path):
    """README 指标表数字 ≠ 机器计数 → 必须报漂移。"""
    (tmp_path / "R.md").write_text(
        "| **offline_verified** (strict real-problem KPI) | **9** |\n", encoding="utf-8",
    )
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", (("R.md", _README_PAT),))
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 13, 13))
    hits = dc.check_kpi_number_consistency()
    assert any("9" in h and "13" in h for h in hits), hits


def test_kpi_baseline_and_watermark_drift_detected(monkeypatch, tmp_path):
    """基线棘轮锚 / KPI_WATERMARK 派生不变式被破坏 → 各自报出。"""
    (tmp_path / "KPI_BASELINE.json").write_text('{"offline_verified": 12}', encoding="utf-8")
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", ())
    monkeypatch.setattr(dc, "_KPI_BASELINE_REL", "KPI_BASELINE.json")
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 11, 12))
    hits = dc.check_kpi_number_consistency()
    assert any("基线" in h for h in hits), hits
    assert any("KPI_WATERMARK" in h for h in hits), hits


def test_kpi_no_anchor_no_false_positive(monkeypatch, tmp_path):
    """文档改版/删表导致锚点消失 → 不误报（宁漏勿误）。"""
    (tmp_path / "L.md").write_text("# 文档\n本文件没有 KPI 汇总表\n", encoding="utf-8")
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", (("L.md", _LEDGER_PAT),))
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 13, 13))
    assert dc.check_kpi_number_consistency() == []


def test_kpi_truth_unavailable_no_false_positive(monkeypatch):
    """取不到机器真值 → 不误报（绝不因取数失败阻断门禁）。"""
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (None, None, None))
    assert dc.check_kpi_number_consistency() == []


def test_kpi_historical_mentions_not_flagged(monkeypatch, tmp_path):
    """历史叙述里的「12→13」「回退 12→9」是合法演进记录，不得误报。"""
    hist = (
        "- **晋级**：水位 12→13（地板 9 + 晋升 4，全证据态）。\n"
        "- 2026-08-28 诚实回退 12→9；2026-09-03 三道带证据重新晋级。\n"
        "- 此 12 / 13 为全证据态，与回退前口径不同。\n"
    )
    # ① 过时断言检查不命中
    assert dc.check_stale_assertions("x.md", hist) == []
    # ② 声明位正则不命中演进叙述行
    (tmp_path / "L.md").write_text(hist, encoding="utf-8")
    monkeypatch.setattr(dc, "ROOT", str(tmp_path))
    monkeypatch.setattr(dc, "_KPI_DECL_PATTERNS", (("L.md", _LEDGER_PAT),))
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (13, 13, 13))
    assert dc.check_kpi_number_consistency() == []


def test_kpi_machine_truth_self_consistent():
    """机器真值自洽：计数 = 水位 = 基线（本仓真实状态，非 mock）。"""
    count, watermark, baseline = dc.machine_kpi_truth()
    assert isinstance(count, int) and count > 0, (count, watermark, baseline)
    assert count == watermark == baseline, (count, watermark, baseline)


def test_live_repo_kpi_declarations_consistent():
    """真实仓库回归：README / 台账 / 基线 三处手写数字必须与机器计数一致。

    这条是「口径单一真值」的常驻守卫——若有人只改一处文档，CI 立刻红。
    """
    assert dc.check_kpi_number_consistency() == []


# ── KPI 闸门盲区加固（2026-09-19 新增，P0-3）─────────────────────────────
# 事故：README.md 正文写 `offline_verified=13`（表格是 14）却全绿通过；README.zh.md
# 全文 0 次出现唯一机器强制 KPI，中文版与英文版对外讲两个不同的能力水位。
# 根因：闸门只锚定精确表格行，正文与整文件都在网外；且 README 不在 DOC_ROOT 遍历范围。

def _mk_repo(monkeypatch, tmp_path, readme=None, zh_readme=None):
    """构造一个「仓库根 + ctf_agent 子目录」的最小结构，ROOT 指向 ctf_agent。

    README 声明锚点与正文扫描均以仓库根（ROOT 上一级）为基准，故文件写在 tmp_path。
    """
    root = tmp_path / "ctf_agent"
    root.mkdir()
    monkeypatch.setattr(dc, "ROOT", str(root))
    if readme is not None:
        (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    if zh_readme is not None:
        (tmp_path / "README.zh.md").write_text(zh_readme, encoding="utf-8")
    return root


# ── D1：公开声明文件必须保留声明行 ──────────────────────────────────────

def test_kpi_zh_declaration_missing_detected(monkeypatch, tmp_path):
    """D1 变异：README.zh.md 声明行整行删掉 → 必须红（防「删声明行」绕过）。"""
    _mk_repo(
        monkeypatch, tmp_path,
        readme="| **offline_verified** (strict real-problem KPI) | **14** |\n",
        zh_readme="## 诚实 KPI\n本表格没有 offline_verified 声明行\n",
    )
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    hits = dc.check_kpi_number_consistency()
    assert any("README.zh.md" in h and "声明缺失" in h for h in hits), hits


def test_kpi_zh_declaration_present_green(monkeypatch, tmp_path):
    """D1 恢复：README.zh.md 保留声明行且数字正确 → 绿。"""
    _mk_repo(
        monkeypatch, tmp_path,
        readme="| **offline_verified** (strict real-problem KPI) | **14** |\n",
        zh_readme="| **offline_verified**（严格真题 KPI，机器棘轮只升不降） | **14** |\n",
    )
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    assert dc.check_kpi_number_consistency() == []


def test_kpi_zh_declaration_drift_detected(monkeypatch, tmp_path):
    """D1 补齐的 ZH 锚点：ZH 声明数字 ≠ 机器计数 → 报漂移。"""
    _mk_repo(
        monkeypatch, tmp_path,
        readme="| **offline_verified** (strict real-problem KPI) | **14** |\n",
        zh_readme="| **offline_verified**（严格真题 KPI） | **9** |\n",
    )
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    hits = dc.check_kpi_number_consistency()
    assert any("README.zh.md" in h and "9" in h and "14" in h for h in hits), hits


# ── D2：正文习语 `offline_verified=<n>` 全文扫 ───────────────────────────

def test_kpi_inline_idiom_drift_detected(monkeypatch, tmp_path):
    """D2 变异（今天溜过去的那类）：表格 14 正确，只把正文改成 =13 → 必须红。"""
    _mk_repo(
        monkeypatch, tmp_path,
        readme="| **offline_verified** (strict real-problem KPI) | **14** |\n"
               "> ⚠️ **What `offline_verified=13` does and does NOT mean.**\n",
    )
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    hits = dc.check_kpi_inline_idiom_drift()
    assert any("README.md" in h and "13" in h for h in hits), hits


def test_kpi_inline_idiom_correct_green(monkeypatch, tmp_path):
    """D2 恢复：正文 =14 与机器计数一致 → 绿。"""
    _mk_repo(
        monkeypatch, tmp_path,
        readme="> ⚠️ **What `offline_verified=14` does and does NOT mean.**\n",
    )
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    assert dc.check_kpi_inline_idiom_drift() == []


def test_kpi_inline_historical_arrows_not_flagged(monkeypatch, tmp_path):
    """D2 零误报边界：箭头式历史叙述（12→13 / 回退 12→9 / nominal 12 to 9）不报。"""
    _mk_repo(
        monkeypatch, tmp_path,
        readme="水位 12→13；2026-08-28 诚实回退 12→9；nominal 12 to 9；"
               "specialcurve2 带证据晋级 12→13。\n",
    )
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    assert dc.check_kpi_inline_idiom_drift() == []


# ── D3：LLM 贡献分母白名单 ──────────────────────────────────────────────

def test_kpi_contribution_denominator_13_detected(monkeypatch, tmp_path):
    """D3 变异：contribution 行 `0/13` → 分母非法 → 必须红。"""
    _mk_repo(
        monkeypatch, tmp_path,
        readme="LLM autonomous-reasoning contribution is **0/13**.\n",
    )
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    hits = dc.check_kpi_inline_idiom_drift()
    assert any("分母非法" in h and "13" in h for h in hits), hits


def test_kpi_contribution_zh_denominator_1_detected(monkeypatch, tmp_path):
    """D3 变异：ZH `自主推理贡献` 行 `0 / 1`（无来源分母）→ 必须红。"""
    _mk_repo(
        monkeypatch, tmp_path,
        zh_readme="| LLM 自主推理贡献 | **0 / 1**（唯一未解题为数据集缺陷） |\n",
    )
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    hits = dc.check_kpi_inline_idiom_drift()
    assert any("分母非法" in h and "1" in h for h in hits), hits


def test_kpi_contribution_valid_denominators_green(monkeypatch, tmp_path):
    """D3 正例：分母 14（KPI 集）合法；held-out 池分母取自 _kpi_canonical 后亦合法。"""
    _mk_repo(
        monkeypatch, tmp_path,
        readme="LLM autonomous-reasoning contribution is **0/14**.\n",
        zh_readme="| LLM 自主推理贡献 | **0 / 14** |\n",
    )
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    assert dc.check_kpi_inline_idiom_drift() == []


def test_kpi_allowed_denominators_from_canonical():
    """D3 铁律：held-out 分母必须来自 _kpi_canonical（禁硬编码），且 ∈ 白名单。"""
    dens = dc._kpi_allowed_denominators(14)
    assert 14 in dens
    kc = dc._load_gov_module("_kpi_canonical")
    assert kc is not None
    assert int(kc.count_heldout_candidates()) in dens


def test_live_repo_inline_idiom_consistent():
    """真实仓库回归：两个公开 README 的正文习语 / LLM 贡献分母必须自洽。"""
    assert dc.check_kpi_inline_idiom_drift() == []


# ── C① break-ice 分母口径限定语（2026-09-19 新增）───────────────────────
# 事故遗留：README.md break-ice 段落的 `11/15` / `8/15` 用的是**该实验自身题集**
# 的分母，与已作废的「presolve 覆盖度 15 题子集（15/15、86.7%）」口径无关，
# 但两者都写 `15`，读者极易混读。它不是 `0/N` 形式的贡献比，闸门按设计不查它，
# 故用本节的 present 测试兜底（并显式记录「不靠闸门守」这一事实）。

_BREAKICE_QUALIFIER_MARK = "Denominator caveat (do not conflate)"


def _breakice_section(text):
    """截取 README 的 break-ice 实验段落（从实验标题到诚实 caveat 标题之间）。"""
    lines = text.split("\n")
    start = next(i for i, l in enumerate(lines) if "LLM reasoning break-ice experiment" in l)
    end = next(i for i, l in enumerate(lines) if "Honesty caveat on the 4 unsolved" in l)
    assert start < end, "break-ice 段落标题顺序异常"
    return "\n".join(lines[start:end])


def test_live_repo_breakice_denominator_qualifier_present():
    """break-ice 段落必须带「15 是实验自身题集、与作废口径无关」的口径限定语。

    防回归锚（C①）：清掉上文的 `15 / 15` 后，若旁边的 `11/15`/`8/15` 不限定语，
    读者仍会把两个 15 当成同一个分母——等于白清。该限定语**只由本测试守**。
    """
    text = dc._read_text(os.path.join(dc._repo_root(), "README.md"))
    assert text is not None, "仓库根缺少 README.md"
    section = _breakice_section(text)
    assert _BREAKICE_QUALIFIER_MARK in section, "break-ice 段落缺少分母口径限定语"
    # 要点 1：明说与该作废口径无关
    assert "unrelated" in section
    # 要点 2：明说不计入 KPI（与既有 'not counted in KPI'/'superseded' 并存）
    assert "not counted in the KPI" in section and "superseded" in section
    # 要点 3：数字可溯源（不得发明新数字）
    assert "llm_breaking_ice_20260901-050201.json" in section
    assert "llm_breaking_ice_20260828-022534.json" in section


def test_breakice_qualifier_not_gate_enforced(monkeypatch, tmp_path):
    """记录设计取舍：删掉该限定语后闸门（D1/D2/D3）仍全绿——它只靠测试守，不靠闸门守。

    限定语是散文性说明，既不是 `offline_verified=<n>` 习语，也不在含 contribution
    的行上，故闸门按设计不查它；防回归由 test_live_repo_..._qualifier_present 负责。
    """
    real = dc._read_text(os.path.join(dc._repo_root(), "README.md"))
    assert real is not None
    qualifier = ("**Denominator caveat (do not conflate):** the `15` in `11/15` "
                 "and `8/15` ")
    assert qualifier in real
    stripped = real.replace(qualifier, "**Denominator note removed:** ", 1)
    assert _BREAKICE_QUALIFIER_MARK not in stripped

    root = tmp_path / "ctf_agent"
    root.mkdir()
    monkeypatch.setattr(dc, "ROOT", str(root))
    (tmp_path / "README.md").write_text(stripped, encoding="utf-8")
    (tmp_path / "README.zh.md").write_text(
        "| **offline_verified**（严格真题 KPI） | **14** |\n", encoding="utf-8")
    monkeypatch.setattr(dc, "machine_kpi_truth", lambda: (14, 14, 14))
    # 闸门不报 → 证明限定语不靠闸门守，只靠上面那条 present 测试守
    assert dc.check_kpi_number_consistency() == []
    assert dc.check_kpi_inline_idiom_drift() == []
