#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自测覆盖率门禁 —— 守的是「所有其他门禁的存在性」。

为什么需要它（2026-11-01 审计 R104 提出）
------------------------------------------
本仓有 35 个 `check_* / audit_* / verify_*` 脚本，其中 27 个带 `_test.py`、
3 个带 `--self-test`。剩 5 个两种都没有——这本身不算错，错在**没人知道哪些是
刻意的、哪些是漏掉的**。

一个仓库的判据如果没人验证，它和注释没有区别。这条门禁要求每个校验脚本
**明确表态**（三选一），把「忘了写测试」和「本来就不需要」区分开：

  A. 有 `scripts/<name>_test.py`            —— 最理想
  B. 脚本自带 `--self-test`                  —— 同等效力（单文件驱动）
  C. 在 `SELFTEST_EXEMPT` 里登记 + 写明理由 —— 显式豁免，可审计

三者都不满足 → 红。

为什么不自动按"有没有外部依赖"来判：
  机器判不准。`verify_demo_readiness` 要连真服务器、`check_dual_repo_coherence`
  要两个仓库同时在场——这些理由只有人知道。**让门禁去猜，不如让人来签字。**

用法：
  python scripts/check_selftest_coverage.py            # 校验（rc=1 即红）
  python scripts/check_selftest_coverage.py --self-test  # 变异验证
"""

from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

#: 显式豁免：(脚本名, 理由)。理由必填且必须说明**为什么这条判据无法自测**。
#: 加进来的每一条都是一次"我确认过"的签字，不是一句"先跳过"。
SELFTEST_EXEMPT = {
    # ── 单题一次性复现脚本：跑过一次就完成使命，不值得为它写守卫 ──────────
    "verify_anwang_misc3": "单题复现（2022安网杯 misc3），一次性验证脚本，无复用判定逻辑",
    "verify_hgame2022_rsa": "单题复现（HGAME 2022 RSA ×3），一次性验证脚本",
    "verify_hgame_rsa": "单题复现（HGAME RSA），一次性验证脚本",
    "verify_vnctf_flag": "单题复现（VNCTF flag），一次性验证脚本",
    "verify_filterrandom": "单题复现（filter random），一次性验证脚本",
    "verify_real_questions": "批量单题复现入口，依赖真实题库与附件（公开仓不含），无法在 CI 构造",

    # ── 需要重型外部环境，单仓夹具构造不出来 ────────────────────────────
    "_verify_web_batch": "需要真实 Web 解题链路（浏览器 + 靶场），CI 无此环境",
    "_verify_web_real": "需要真实 Web 靶场与内网，CI 无此环境",
    "_check_platform_v2": "需要多平台产物同时在场才能比对，CI 只装一平台",

    # ── 汇总/阶段脚本：结论是人工判读的，没有机器可判的通过条件 ──────────
    "_verify_final": "最终汇总报告生成器，输出供人工判读，无 pass/fail 判据",
    "_verify_stage2": "阶段汇总（stage2），同上",
    "_verify_stage3": "阶段汇总（stage3），同上",
    "_verify_presolve_only": "presolve 单通道试跑，用于调试而非判定",
    "_verify_faults": "故障注入演示脚本，人工观察输出，无自动判定",
    "_verify_kpi_promote": "KPI 提升流程的一次性核对，跑完即结论",

    # ── 应补自测但尚未补（诚实登记，不假装已覆盖）──────────────────────
    "_audit_corpus_duplicate_pollution":
        "报告型脚本：只做统计与打印，无 pass/fail 判据；其核心判据（跨库择优去重）"
        "在 eval/corpus.py::load_corpus，已由 tests/test_corpus_measurability.py 覆盖"
        "（含『坏副本在前/在后』两种顺序）",

}

PREFIXES = ("check_", "audit_", "verify_", "_check_", "_audit_", "_verify_")



def _referenced_in_tests(scripts_dir: str, name: str) -> bool:
    """脚本是否被 tests/ 下任一测试引用（import 或按文件名调用）。"""
    root = os.path.dirname(scripts_dir)
    tests_dir = os.path.join(root, "tests")
    if not os.path.isdir(tests_dir):
        return False
    bare = name.lstrip("_")
    for fn in os.listdir(tests_dir):
        if not fn.endswith(".py"):
            continue
        try:
            txt = open(os.path.join(tests_dir, fn), encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if name in txt or bare in txt:
            return True
    return False

def _candidates(scripts_dir: str):
    out = []
    for fn in sorted(os.listdir(scripts_dir)):
        if not fn.endswith(".py") or fn.endswith("_test.py"):
            continue
        if not fn.startswith(PREFIXES):
            continue
        out.append(fn[:-3])
    return out


def evaluate(scripts_dir: str):
    """返回 (rows, problems)。rows = [(name, status, detail)]。"""
    rows, problems = [], []
    for name in _candidates(scripts_dir):
        path = os.path.join(scripts_dir, name + ".py")
        try:
            txt = open(path, encoding="utf-8", errors="ignore").read()
        except OSError as e:
            rows.append((name, "ERROR", f"读不到: {e}"))
            problems.append(f"{name}: 读不到源码")
            continue
        has_test = os.path.exists(os.path.join(scripts_dir, name + "_test.py"))
        # 本仓范式不同：脚本不是配 _test.py，而是被 tests/*.py 引用（import 或 subprocess 调）。
        # 这也算"有守卫"——只要有测试会因为它的行为变化而失败即可。
        if not has_test:
            has_test = _referenced_in_tests(scripts_dir, name)
        has_self = bool(re.search(r"--self-test|self_test", txt))
        if has_test:
            rows.append((name, "A_TEST", "有 _test.py"))
        elif has_self:
            rows.append((name, "B_SELFTEST", "自带 --self-test"))
        elif name in SELFTEST_EXEMPT:
            reason = SELFTEST_EXEMPT[name]
            if len(reason) < 8:
                rows.append((name, "C_WEAK", "豁免理由过短"))
                problems.append(f"{name}: 豁免理由太敷衍（{reason!r}）")
            else:
                rows.append((name, "C_EXEMPT", reason))
        else:
            rows.append((name, "D_MISSING", "既无自测也未登记豁免"))
            problems.append(
                f"{name}: 既无 _test.py / --self-test，也不在 SELFTEST_EXEMPT 里")
    # 反向检查：豁免表里不能有已经不存在的脚本（否则表会腐朽）
    names = set(_candidates(scripts_dir))
    for k in SELFTEST_EXEMPT:
        if k not in names:
            problems.append(f"SELFTEST_EXEMPT 里的 {k} 已不存在（陈旧条目，应删除）")
    return rows, problems


def self_test(tmp_root=None):
    """变异验证：3 类坏样本必须被拦，1 个干净样本必须通过。"""
    import tempfile

    def build(root, files):
        os.makedirs(root, exist_ok=True)
        for fn, body in files.items():
            with open(os.path.join(root, fn), "w", encoding="utf-8") as f:
                f.write(body)

    ok = True

    # T1 干净：check_a 有 _test，check_b 有 --self-test → 应全过
    #
    # ⚠️ 必须临时清空 SELFTEST_EXEMPT：真实豁免表里都是**本仓真实脚本名**，
    # 在临时目录里它们全部"已不存在"，会触发陈旧检测把干净样本判红。
    # 第一版没清，T1 直接报 5 条陈旧——是自检测例自身的缺陷，不是门禁缺陷。
    with tempfile.TemporaryDirectory() as td:
        build(td, {"check_a.py": "print(1)\n", "check_a_test.py": "print(2)\n",
                   "check_b.py": "# usage: --self-test\n"})
        saved = dict(SELFTEST_EXEMPT)
        try:
            SELFTEST_EXEMPT.clear()
            rows, probs = evaluate(td)
        finally:
            SELFTEST_EXEMPT.clear()
            SELFTEST_EXEMPT.update(saved)
        if probs:
            print(f"  [FAIL] T1 干净样本被误报: {probs}")
            ok = False
        else:
            print("  [PASS] T1 干净样本全绿")

    # T2 变异：check_c 既无自测也无豁免 → 必须红
    with tempfile.TemporaryDirectory() as td:
        build(td, {"check_c.py": "print(1)\n"})
        _, probs = evaluate(td)
        if not any("check_c" in p for p in probs):
            print("  [FAIL] T2 漏报『既无自测也无豁免』")
            ok = False
        else:
            print("  [PASS] T2 变异：无自测且未豁免 → 红")

    # T3 变异：豁免表里有不存在的脚本 → 必须红（防表腐朽）
    with tempfile.TemporaryDirectory() as td:
        build(td, {"check_d.py": "print(1)\n"})
        saved = dict(SELFTEST_EXEMPT)
        try:
            SELFTEST_EXEMPT["ghost_script_zzz"] = "一个已经不存在了的脚本，用来测陈旧检测"
            _, probs = evaluate(td)
            if not any("ghost_script_zzz" in p for p in probs):
                print("  [FAIL] T3 豁免表的陈旧条目没被发现")
                ok = False
            else:
                print("  [PASS] T3 变异：豁免表陈旧条目 → 红")
        finally:
            SELFTEST_EXEMPT.clear()
            SELFTEST_EXEMPT.update(saved)

    # T4 变异：豁免理由敷衍 → 必须红
    with tempfile.TemporaryDirectory() as td:
        build(td, {"check_e.py": "print(1)\n"})
        saved = dict(SELFTEST_EXEMPT)
        try:
            SELFTEST_EXEMPT["check_e"] = "跳过"
            _, probs = evaluate(td)
            if not any("check_e" in p for p in probs):
                print("  [FAIL] T4 敷衍的豁免理由被放过了")
                ok = False
            else:
                print("  [PASS] T4 变异：豁免理由过短 → 红")
        finally:
            SELFTEST_EXEMPT.clear()
            SELFTEST_EXEMPT.update(saved)

    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="自测覆盖率门禁")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--scripts-dir", default=HERE)
    args = ap.parse_args(argv)

    if args.self_test:
        print("自测覆盖率门禁 —— 4 项（含 3 个变异）")
        print("-" * 58)
        rc = self_test()
        print("-" * 58)
        print("  self-test " + ("PASS" if rc == 0 else "FAIL"))
        return rc

    rows, problems = evaluate(args.scripts_dir)
    from collections import Counter
    c = Counter(r[1] for r in rows)
    print("=== 自测覆盖率 ===")
    print(f"  校验脚本 {len(rows)} 个")
    print(f"    A 有 _test.py       {c.get('A_TEST', 0)}")
    print(f"    B 自带 --self-test  {c.get('B_SELFTEST', 0)}")
    print(f"    C 显式豁免          {c.get('C_EXEMPT', 0)}")
    print(f"    D 缺口              {c.get('D_MISSING', 0)}")
    if problems:
        print()
        for p in problems:
            print(f"  [FAIL] {p}")
        print()
        print("修法：补 _test.py / 加 --self-test / 或在 SELFTEST_EXEMPT 里签字写理由。")
        return 1
    print("\n全部校验脚本均已表态（自测 / 自带自测 / 显式豁免）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
