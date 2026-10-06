# -*- coding: utf-8 -*-
"""扫描 skills/ 下**全部** skill 的入参契约（AST 静态分析，零调用）。

用途：为 AUTO_CALLABLE 白名单扩面提供事实依据——
不分品种地看每个 skill 的 run() 到底从 params 里取哪些键，
据此判断它属「路径类（可安全喂附件路径）」还是「需要结构化参数（不可盲调）」。

诚实纪律：只报告源码里**字面出现**的 params.get / params["..."] 键，
不猜测、不推断默认值。
"""
from __future__ import annotations

import ast
import os
import sys

_CTF = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(_CTF, "skills")

# 判定为「路径类」的典型键
PATH_KEYS = {"path", "text", "file", "file_path", "filepath", "input",
             "input_path", "paths", "filename", "src", "data", "content"}


def collect_keys(tree):
    """收集 run()（或同名 skill 主函数）里 params 的取值键。"""
    keys = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if not (node.name == "run" or node.name.startswith(("crypto_", "misc_",
                                                            "reverse_", "pwn_",
                                                            "web_", "pyc_"))):
            continue
        for sub in ast.walk(node):
            # params.get("k")
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                    and sub.func.attr == "get" \
                    and isinstance(sub.func.value, ast.Name) \
                    and sub.func.value.id == "params" and sub.args:
                a0 = sub.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    keys.add(a0.value)
            # params["k"]
            elif isinstance(sub, ast.Subscript) \
                    and isinstance(sub.value, ast.Name) \
                    and sub.value.id == "params":
                idx = sub.slice
                if isinstance(idx, ast.Constant) and isinstance(idx.value, str):
                    keys.add(idx.value)
    return keys


def main():
    names = sorted(f[:-3] for f in os.listdir(SKILLS)
                  if f.endswith(".py") and not f.startswith("_"))
    # 只报告本次关心的白名单外高频 skill；--all 输出全部
    focus = set(sys.argv[1:]) if len(sys.argv) > 1 else None
    rows = []
    for n in names:
        p = os.path.join(SKILLS, n + ".py")
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                tree = ast.parse(fh.read())
        except SyntaxError as e:
            rows.append((n, set(), "PARSE_FAIL %s" % e))
            continue
        except OSError as e:
            rows.append((n, set(), "READ_FAIL %s" % e))
            continue
        rows.append((n, collect_keys(tree), ""))
    if focus:
        rows = [r for r in rows if r[0] in focus]
    print("%-32s %s" % ("skill", "params keys"))
    print("-" * 100)
    path_like = []
    for n, keys, err in rows:
        tag = "".join(sorted(keys)) if keys else ("(%s)" % err if err else "(none)")
        is_path = bool(keys & PATH_KEYS)
        print("%-32s %s%s" % (n, tag[:60], "   <== PATH-LIKE" if is_path else ""))
        if is_path and not err:
            path_like.append((n, sorted(keys & PATH_KEYS)))
    print("\n" + "=" * 100)
    print("疑似路径类（含 %s 之一）共 %d 个：" % ("/".join(sorted(PATH_KEYS)),
                                          len(path_like)))
    for n, ks in path_like:
        print("  %-32s %s" % (n, ks))


if __name__ == "__main__":
    main()
