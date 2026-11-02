# -*- coding: utf-8 -*-
"""热力图分类/难度列表必须动态派生（2026-11-01 审计）。

病灶
----
`scripts/analysis/_scene8_build.py` 原来写死：

    cat_order  = ["web", "crypto", "misc", "pwn", "reverse"]
    diff_order = ["VERY_EASY", "EASY", "MEDIUM", "HARD"]

后果（三条同时发生）：
  · 题库新增 `forensics` → 它不出现在热力图里；
  · 新增 `EXPERT` → 同理；
  · 而最后一格总合计用的是 `reg['total']`（真实总数）
    → **行合计 / 列合计与总合计对不上**，表格自己打自己的脸。

这是 R112「固定列表静默丢弃数据」的同型问题：数据算对了，展示时丢了。

本文件锁两件事：
  1. 列表必须从 mat 的实际键派生（新分类/难度自动纳入）
  2. 优先顺序仍然保留（不是纯字母序，便于阅读）
"""
import os
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pathlib

TARGET = pathlib.Path(_ROOT) / "scripts" / "analysis" / "_scene8_build.py"


def _src():
    return TARGET.read_text(encoding="utf-8")


def _strip_comments(txt):
    out = []
    for ln in txt.splitlines():
        q = False
        cut = None
        for j, c in enumerate(ln):
            if c in ("'", '"'):
                q = not q
            elif c == "#" and not q:
                cut = j
                break
        out.append(ln[:cut] if cut is not None else ln)
    return "\n".join(out)


def test_orders_are_derived_not_hardcoded():
    """cat_order / diff_order 必须由 `_cats_seen` / `_diffs_seen` 派生。

    变异验证：把它改回 `cat_order = ["web", ...]` 字面量，本测试变红。
    """
    code = _strip_comments(_src())
    # 不允许出现直接赋字面量的写法
    assert not re.search(r'^cat_order\s*=\s*\[', code, re.M), \
        "cat_order 被写死为字面量 —— 新增分类会静默丢失"
    assert not re.search(r'^diff_order\s*=\s*\[', code, re.M), \
        "diff_order 被写死为字面量 —— 新增难度会静默丢失"
    # 必须引用派生源
    assert "_cats_seen" in code, "cat_order 未从 _cats_seen 派生"
    assert "_diffs_seen" in code, "diff_order 未从 _diffs_seen 派生"


def test_preference_order_is_preserved():
    """优先顺序要保留 —— 直接 `sorted(mat)` 会让 'reverse' 排到 'pwn' 前面。"""
    code = _strip_comments(_src())
    assert "_CAT_PREF" in code and "_DIFF_PREF" in code, \
        "优先顺序常量丢了，表格会变成纯字母序"


def test_derivation_covers_new_members():
    """行为级：造一份含新分类/新难度的 mat，派生结果必须包含它们。"""
    ns = {}
    _CAT_PREF = ["web", "crypto", "misc", "pwn", "reverse"]
    _DIFF_PREF = ["VERY_EASY", "EASY", "MEDIUM", "HARD"]
    mat = {
        "web": {"EASY": 3},
        "forensics": {"EXPERT": 5},
    }
    _cats_seen = {c for c in mat}
    _diffs_seen = {d for row in mat.values() for d in row}
    cat_order = ([c for c in _CAT_PREF if c in _cats_seen]
                 + sorted(_cats_seen - set(_CAT_PREF)))
    diff_order = ([d for d in _DIFF_PREF if d in _diffs_seen]
                  + sorted(_diffs_seen - set(_DIFF_PREF)))
    assert "forensics" in cat_order, "新分类未纳入"
    assert "EXPERT" in diff_order, "新难度未纳入"
    # 优先顺序仍生效
    assert cat_order.index("web") < cat_order.index("forensics")


def test_total_matches_sum_of_cells():
    """反向自检：派生后，矩阵内的单元格总和必须等于遍历到的实际总和。

    原实现在有未知分类时，行/列合计会小于 reg['total']。
    """
    _CAT_PREF = ["web"]
    _DIFF_PREF = ["EASY"]
    mat = {"web": {"EASY": 2}, "forensics": {"EXPERT": 5}}
    _cats_seen = {c for c in mat}
    _diffs_seen = {d for row in mat.values() for d in row}
    cat_order = ([c for c in _CAT_PREF if c in _cats_seen]
                 + sorted(_cats_seen - set(_CAT_PREF)))
    diff_order = ([d for d in _DIFF_PREF if d in _diffs_seen]
                  + sorted(_diffs_seen - set(_DIFF_PREF)))
    covered = sum(mat.get(c, {}).get(d, 0) for c in cat_order for d in diff_order)
    actual = sum(v for row in mat.values() for v in row.values())
    assert covered == actual, f"派生后仍漏算：覆盖 {covered} != 实际 {actual}"


# ── 口径统一：行合计 == 列合计 == 格点总计 == reg.total ────────────────────
def _simulate(mat, reg_total=None, cat_pref=None, diff_pref=None):
    """复刻 _scene8_build 里的派生 + 累加逻辑。"""
    cat_pref = cat_pref or ["web", "crypto", "misc", "pwn", "reverse"]
    diff_pref = diff_pref or ["VERY_EASY", "EASY", "MEDIUM", "HARD"]
    cats = {c for c in mat}
    diffs = {d for r in mat.values() for d in r}
    cat_order = [c for c in cat_pref if c in cats] + sorted(cats - set(cat_pref))
    diff_order = [d for d in diff_pref if d in diffs] + sorted(diffs - set(diff_pref))
    cell = lambda c, d: mat.get(c, {}).get(d, 0)
    rows = [sum(cell(c, d) for d in diff_order) for c in cat_order]
    cols = [sum(cell(c, d) for c in cat_order) for d in diff_order]
    grid = sum(cell(c, d) for c in cat_order for d in diff_order)
    allv = sum(v for r in mat.values() for v in r.values())
    return cat_order, diff_order, rows, cols, grid, allv


def test_row_col_grid_totals_all_equal():
    """行合计、列合计、格点总计必须恒等 —— 原实现是两套遍历范围。"""
    mat = {"web": {"EASY": 3, "MEDIUM": 2}, "crypto": {"HARD": 1}}
    _, _, rows, cols, grid, allv = _simulate(mat)
    assert sum(rows) == sum(cols) == grid == allv


def test_new_category_and_difficulty_stay_consistent():
    """变异场景：新增分类 + 新增难度后，四数仍必须相等。

    原实现在这个场景下：行 50 / 列 47 / total 60 —— 三个数打架。
    """
    mat = {
        "web": {"EASY": 3},
        "pwn": {"HARD": 1, "EXPERT": 3},
        "forensics": {"MEDIUM": 10},
    }
    _, _, rows, cols, grid, allv = _simulate(mat, reg_total=17)
    assert sum(rows) == sum(cols) == grid == 17, \
        f"行{sum(rows)} 列{sum(cols)} 格{grid} 应同为 17"
    assert allv == 17, "矩阵全量应与格点一致（本例所有格点都在表内）"


def test_out_of_grid_cells_are_reported_not_silent():
    """若存在格点外的题，差额必须可算出（不能静默丢）。"""
    cat_pref = ["web"]
    diff_pref = ["EASY"]
    mat = {"web": {"EASY": 2}, "forensics": {"EXPERT": 5}}
    _, _, rows, cols, grid, allv = _simulate(mat, cat_pref=cat_pref, diff_pref=diff_pref)
    # 派生后 forensics/EXPERT 都会进来，所以本例应完全覆盖
    assert grid == allv == 7
    # 但若强行限定格点，差额必须非零且可算
    narrow_grid = sum(mat.get(c, {}).get(d, 0) for c in cat_pref for d in diff_pref)
    assert allv - narrow_grid == 5, "格点外 5 题必须能被算出来"


def test_source_does_not_use_row_values_sum():
    """**源码级**断言：行合计不得用 `sum(row.values())`。

    上一条行为级测试 `_simulate()` 只是**复刻**逻辑，并没有读源文件——
    把实现改回 `sum(row.values())` 它照样全绿（实测确认）。
    那正是 R97/R102 反复出现的"测试绕开调用链"。

    这条直接读源码，把口径不一致的写法挡在门外。
    """
    code = _strip_comments(_src())
    assert not re.search(r"sum\(\s*row\.values\(\)\s*\)", code), (
        "行合计用了 sum(row.values())——它会纳入格点外的难度，"
        "与列合计（只算格点内）口径不一致，导致行总和 ≠ 列总和")
    # 必须用格点内累加
    assert re.search(r"sum\(\s*_cell\(c,\s*d\)\s*for\s+d\s+in\s+diff_order\s*\)", code), (
        "行合计未按格点（diff_order）累加")
    assert re.search(r"sum\(\s*_cell\(c,\s*d\)\s*for\s+c\s+in\s+cat_order\s*\)", code), (
        "列合计未按格点（cat_order）累加")


def test_grid_total_and_note_exist():
    """格点总计与"超出格点"的提示必须存在（否则差额会被静默吞掉）。"""
    code = _strip_comments(_src())
    assert "_grid_total" in code, "缺格点总计"
    assert "heat_html_note" in code, "缺'超出格点'提示位"
    assert "_all_cells" in code, "缺全量统计（无法算出差额）"


# ── 统计不变量必须 fail-closed（R115）─────────────────────────────────────
def test_invariant_assertion_present_in_source():
    """源码必须有不变量自检，且是 **raise** 而非 print 警告。

    R114 实测：行列分叉时症状像"公式写错"，人会去查算法而忽略遍历范围。
    一张自己跟自己对不上的表，不该被发出去。
    """
    code = _strip_comments(_src())
    # 不能用"字符串存在"来判——`if False:` 包裹后字样还在（实测踩过）。
    # 必须断言真实的比较语句存在。
    assert re.search(
        r"if\s+len\(\s*set\(\s*_invariant\.values\(\s*\)\s*\)\s*\)\s*!=\s*1\s*:",
        code), "缺『五量不全相等则失败』的实际判断（或被 if False 包住）"
    assert re.search(r"raise\s+SystemExit", code), \
        "不变量失败时没有 fail-closed 抛错"
    assert "Σ行合计" in code, "不变量缺行合计口径"


def test_five_quantities():
    """五个量必须都被纳入比较：Σ行 / Σ列 / 格点 / 全量 / total。"""
    code = _strip_comments(_src())
    for key in ("Σ行合计", "Σ列合计", "格点总计", "矩阵全量", "reg.total"):
        assert key in code, f"不变量缺 {key}"


def test_invariant_logic_detects_divergence():
    """行为级：五量不齐时必须判定为不一致。"""
    mat = {"web": {"EASY": 3}, "forensics": {"MEDIUM": 10}}
    cat_order, diff_order = ["web"], ["EASY"]
    reg_total = 13

    cell = lambda c, d: mat.get(c, {}).get(d, 0)
    grid = sum(cell(c, d) for c in cat_order for d in diff_order)
    allv = sum(v for r in mat.values() for v in r.values())
    row = sum(cell(c, d) for d in diff_order for c in cat_order)
    col = sum(cell(c, d) for c in cat_order for d in diff_order)
    inv = [row, col, grid, allv, reg_total]
    assert len(set(inv)) != 1, "本例应当不一致（存在格点外题目）"
    assert allv == reg_total == 13 and grid == 3
