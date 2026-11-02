# -*- coding: utf-8 -*-
"""`_verify_presolve_truth.classify()` 的守卫（2026-11-01 审计补）。

为什么需要它
------------
这个脚本是 R59 审计「14 个 offline_verified vs 93 题真实可复现 2 题」落差的
主要证据来源之一。它的**判读逻辑**决定了那个数字，但原来埋在 `main()` 的
for 循环里，只能靠肉眼读代码确认。

最大的风险点：**`NO_GROUND`（提取到但题库没真值）不能算作「解出」。**
两者合并计数，会把「题库没真值所以无法反驳」算成「解出来了」——
那正是这个仓库被诟病的数字虚高形态。

本文件锁住四类边界，并加了变异验证（把 NO_GROUND 并进 MATCH 必须让测试变红）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib.util

_SPEC = importlib.util.spec_from_file_location(
    "_vpt", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "scripts", "_verify_presolve_truth.py"))
# 该脚本顶层会 build_registry 等重依赖，这里只抽 classify 函数体执行
_SRC = open(_SPEC.origin, encoding="utf-8").read()


def _load_classify():
    import ast
    tree = ast.parse(_SRC)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "classify":
            ns = {}
            exec(compile(ast.Module([node], []), "<c>", "exec"), ns)
            return ns["classify"]
    raise AssertionError("找不到 classify()——脚本结构变了，请同步本测试")


classify = _load_classify()


# ── 四类语义 ────────────────────────────────────────────────────────────────
def test_match_only_when_extracted_and_ground_truth_agrees():
    assert classify(True, True, True) == "MATCH"


def test_extract_but_disagree_is_its_own_bucket():
    """提取到但与真值不符 —— 必须单独成类，不能算 MISS 也不能算 MATCH。

    这是最危险的一类：管线给出了**错答案**。若并入 MISS，就看不出
    "它不是解不出，而是解错了"。
    """
    assert classify(True, False, True) == "EXTRACT_BAD"


def test_no_ground_truth_is_not_a_solve():
    """提取到但题库无真值 —— **必须**是 NO_GROUND，绝不能是 MATCH。

    变异验证：把这里改成返回 "MATCH"，本测试必红。
    """
    assert classify(True, False, False) == "NO_GROUND"


def test_not_extracted_is_miss_regardless_of_ground_truth():
    assert classify(False, False, True) == "MISS"
    assert classify(False, False, False) == "MISS"


# ── 反向自检 ────────────────────────────────────────────────────────────────
def test_four_buckets_are_distinct():
    """四类必须互不相同，否则前面的断言可能因"全返回同一值"而虚假通过。"""
    got = {classify(True, True, True), classify(True, False, True),
           classify(True, False, False), classify(False, False, True)}
    assert len(got) == 4, f"分类值发生塌缩: {got}"


def test_no_ground_and_match_never_conflate():
    """最核心的一条：NO_GROUND 与 MATCH 必须可区分。

    历史口径问题的根源就是这两者被合并成"解出数"。
    """
    a = classify(True, True, True)
    b = classify(True, False, False)
    assert a != b, "『提取到且对』与『提取到但无真值』被合并了 —— 口径会虚高"
