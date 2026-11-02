# -*- coding: utf-8 -*-
"""两个"解出数"判定脚本的口径一致性守卫（2026-11-01 审计补）。

背景
----
本仓有两处会产出"解出数"这个 KPI：
  · `_verify_presolve_truth.py`  → `classify()` 产出 MATCH / NO_GROUND / ...
  · `_verify_numeric_dispatch.py` → `run_one()` 返回 True/False

原先两者对**同一件事**（提取到 flag 但题库无真值）给出**相反结论**：
  · presolve_truth：归为 NO_GROUND，明确"不能算解出"
  · numeric_dispatch：`return True`，算通过

同一个仓库对同一现象两种口径，会让 KPI 随"用哪个脚本统计"而漂移。
这正是 R59 审计发现"14 vs 2 落差"的同型问题（NO_GROUND 被并入 MATCH）。

本文件锁住：**两边都必须把"无真值"判为不计入通过。**
"""
import os
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _src(name):
    with open(os.path.join(_ROOT, "scripts", name), encoding="utf-8") as f:
        return f.read()


def _strip_comments(txt):
    """剥掉注释与 docstring，只看代码 —— 否则注释里的'原实现 return True'
    会让下面的断言永远失败（R103 踩过同样的坑）。
    """
    import ast
    lines = txt.splitlines()
    try:
        tree = ast.parse(txt)
    except SyntaxError:
        return txt
    blanks = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                d = body[0]
                for ln in range(d.lineno, (d.end_lineno or d.lineno) + 1):
                    blanks.add(ln)
    out = []
    for i, ln in enumerate(lines, 1):
        if i in blanks:
            out.append("")
            continue
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


def test_presolve_truth_has_no_ground_bucket():
    """presolve_truth 必须保留 NO_GROUND 这一独立类别。"""
    code = _strip_comments(_src("_verify_presolve_truth.py"))
    assert 'return "NO_GROUND"' in code, "NO_GROUND 被合并或删除了"


def test_numeric_dispatch_does_not_pass_without_truth():
    """numeric_dispatch 在题库无真值时**不得** return True。

    修复前那一行的上下文是：
        print("     (题库无 flag_sha256，仅证明 flag 非空)")
        return True
    这种"没真值也算过"的形态会让解出数虚高。
    """
    code = _strip_comments(_src("_verify_numeric_dispatch.py"))
    # 找到「题库无真值」那个分支的代码段
    idx = code.find("flag_sha256")
    assert idx != -1, "找不到 flag_sha256 相关分支"
    tail = code[idx: idx + 600]
    # 该分支里不得出现裸 return True
    assert not re.search(r"无法校验.{0,120}?return\s+True", tail, re.S), \
        "无真值分支仍然 return True —— 与 presolve_truth 的 NO_GROUND 口径相反"


def test_both_scripts_agree_on_no_truth_semantics():
    """口径一致性总断言：两边都不得把"无真值"当成功。"""
    pt = _strip_comments(_src("_verify_presolve_truth.py"))
    nd = _strip_comments(_src("_verify_numeric_dispatch.py"))
    assert 'return "NO_GROUND"' in pt
    assert "不计为通过" in nd or "return False" in nd
