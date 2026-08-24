# -*- coding: utf-8 -*-
"""写耦合度聚类（scripts/_coupling_cluster.py）单测（G4）。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import _coupling_cluster as cc  # noqa: E402


def test_build_jaccard_strong_coupling():
    """A、B 总是一起改（共现高），C 单独改（无共现）。"""
    commits = [
        ["core/a.py", "core/b.py"],
        ["core/a.py", "core/b.py"],
        ["core/a.py", "core/b.py"],
        ["skills/c.py"],
    ]
    files, J = cc.build_jaccard(commits)
    idx = {f: i for i, f in enumerate(files)}
    # A-B 共现 3 次，A 出现 3 次，B 出现 3 次 → Jaccard = 3/(3+3-3) = 1.0
    assert J[idx["core/a.py"]][idx["core/b.py"]] == 1.0
    # A-C 无共现 → 0
    assert J[idx["core/a.py"]][idx["skills/c.py"]] == 0.0


def test_cluster_by_threshold_separates():
    files = ["core/a.py", "core/b.py", "skills/c.py", "skills/d.py"]
    J = [
        [1.0, 0.9, 0.0, 0.0],
        [0.9, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.8],
        [0.0, 0.0, 0.8, 1.0],
    ]
    clusters = cc.cluster_by_threshold(files, J, theta=0.6)
    # 应聚成 2 簇：{a,b} 和 {c,d}
    cluster_sets = sorted([frozenset(c) for c in clusters], key=len, reverse=True)
    assert cluster_sets == [frozenset(["core/a.py", "core/b.py"]),
                            frozenset(["skills/c.py", "skills/d.py"])]


def test_cluster_below_threshold_stays_separate():
    files = ["a.py", "b.py"]
    J = [[1.0, 0.3], [0.3, 1.0]]
    clusters = cc.cluster_by_threshold(files, J, theta=0.6)
    assert len(clusters) == 2  # 0.3 < 0.6，不合并


def test_scope_from_cluster_common_prefix():
    assert cc.scope_from_cluster(["core/a.py", "core/b.py"]) == "core/**"
    assert cc.scope_from_cluster(["core/sub/x.py", "core/sub/y.py"]) == "core/sub/**"
    assert cc.scope_from_cluster(["agents/crypto.py"]) == "agents/crypto.py"


def test_scope_from_cluster_cross_topdir():
    """跨顶层目录簇不应返回误导性 /**，而应按顶层目录分组。"""
    out = cc.scope_from_cluster(["core/a.py", "core/b.py", "tests/test_a.py"])
    # 按顶层目录排序分组：core/** + tests/test_a.py
    assert out == "core/**; tests/test_a.py"
    # 单文件跨目录：两个精确路径
    out2 = cc.scope_from_cluster(["scripts/x.py", "skills/y.py"])
    assert out2 == "scripts/x.py; skills/y.py"


def test_unionfind_transitive():
    uf = cc.UnionFind(3)
    uf.union(0, 1)
    uf.union(1, 2)
    assert uf.find(0) == uf.find(2)  # 传递闭包


def test_average_linkage_separates():
    """基本分离：{a,b} 强耦合、{c,d} 强耦合，两对之间无共现。"""
    files = ["core/a.py", "core/b.py", "skills/c.py", "skills/d.py"]
    J = [
        [1.0, 0.9, 0.0, 0.0],
        [0.9, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.8],
        [0.0, 0.0, 0.8, 1.0],
    ]
    clusters = cc.cluster_average_linkage(files, J, theta=0.6)
    cluster_sets = sorted([frozenset(c) for c in clusters], key=len, reverse=True)
    assert cluster_sets == [frozenset(["core/a.py", "core/b.py"]),
                            frozenset(["skills/c.py", "skills/d.py"])]


def test_average_linkage_no_bridge_overmerge():
    """桥接场景：A-B=0.9、B-C=0.9、A-C=0.0（theta=0.6）。

    union-find 传递闭包会把 A、B、C 全合并；average-linkage 应先并 A-B，
    然后 {A,B} 与 C 的平均距离 = (1-0.0 + 1-0.9)/2 = 0.55 > 0.4，C 保持独立。
    这是根治稀疏历史下过度合并成 /** 的关键回归用例。
    """
    files = ["core/a.py", "core/b.py", "core/c.py"]
    J = [
        [1.0, 0.9, 0.0],
        [0.9, 1.0, 0.9],
        [0.0, 0.9, 1.0],
    ]
    clusters = cc.cluster_average_linkage(files, J, theta=0.6)
    cluster_sets = sorted([frozenset(c) for c in clusters], key=len, reverse=True)
    # 期望：{a,b} 一簇 + {c} 单独，而非 union-find 的 {a,b,c} 大簇
    assert cluster_sets == [frozenset(["core/a.py", "core/b.py"]),
                            frozenset(["core/c.py"])]
    # 对照：union-find 版本会过度合并
    over = cc.cluster_by_threshold(files, J, theta=0.6)
    assert any(frozenset(c) == frozenset(files) for c in over), "对照失败：union-find 应过度合并"


def test_average_linkage_below_threshold_stays_separate():
    files = ["a.py", "b.py"]
    J = [[1.0, 0.3], [0.3, 1.0]]
    clusters = cc.cluster_average_linkage(files, J, theta=0.6)
    assert len(clusters) == 2  # 平均距离 0.7 > 0.4，不合并
