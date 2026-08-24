# -*- coding: utf-8 -*-
"""写耦合度聚类（G4，2026-08-23）：用 git 历史文件共现矩阵自动划分 scope 簇。

原理（Gall et al. 1998「逻辑耦合」）：经常被同一 commit 一起修改的文件耦合度高，
应归入同一 scope（交给同一个 worker），减少写冲突；从不一起改的文件可分到不同
scope 提升并行度。

步骤：
1. `git log --name-only` 遍历历史 commit，收集每个 commit 的文件集合
2. 对同 commit 出现的文件对 (f_i, f_j) 计数 C_ij
3. Jaccard 归一化：J_ij = C_ij / (C_i + C_j - C_ij)
4. average-linkage（UPGMA）层次聚类：距离 = 1 - Jaccard，反复合并平均
   距离最小的簇对，直到最小平均距离 > (1 - theta)（默认簇算法，见下）
5. 输出 scope 簇建议（按目录前缀聚合）

算法选择说明（2026-08-23）：
- `cluster_average_linkage`（默认）：用「簇间平均相似度」判定合并，A-B、B-C
  相似但 A-C 不相似时，桥接文件不会把 A、C 错误串进一个簇——根治稀疏历史下
  过度合并成 `/**` 的问题。
- `cluster_by_threshold`（union-find 单链接，保留作对照）：J_ij >= theta 的边
  连通合并，等价于 single-linkage 传递闭包，桥接场景会过度合并。

用法：
  python scripts/_coupling_cluster.py --limit 200 --theta 0.6
"""
import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _is_backup_git_path(f: str) -> bool:
    """判断是否为 .git 目录或损坏备份目录（非可写代码 scope，须排除）。"""
    top = f.split("/")[0]
    return top == ".git" or top.startswith(".git.broken")


def collect_commits(limit: int = 200, max_files: int = 50):
    """遍历 git log，返回 [ [文件路径, ...], ... ]（每个 commit 一个文件列表）。

    max_files：过滤文件数超过该阈值的 commit。初始导入 / 大规模机械重构这类
    「一次提交几百个文件」的 commit 不反映真实的逻辑耦合（Gall et al. 1998：
    共现应来自「经常一起改」的演进历史，而非一次性导入），其假共现会把所有
    文件错误聚成一个 `/**` 大簇，故默认剔除 > 50 文件的 commit。
    """
    # -c core.quotepath=false：让 git 输出 UTF-8 文件名，而非中文名的八进制转义
    out = subprocess.run(
        ["git", "-c", "core.quotepath=false", "log", "--name-only",
         "--pretty=format:", "-n", str(limit)],
        cwd=ROOT, capture_output=True)
    text = out.stdout.decode("utf-8", errors="ignore")
    commits = []
    current = []
    for line in text.splitlines():
        line = line.strip().strip('"')
        if not line:
            if current:
                commits.append(current)
                current = []
            continue
        current.append(line)
    if current:
        commits.append(current)
    # 过滤：超大 commit（初始导入）+ .git/.git.broken 备份路径
    result = []
    for c in commits:
        c = [f for f in c if not _is_backup_git_path(f)]
        if c and len(c) <= max_files:
            result.append(c)
    return result


def build_jaccard(commits):
    """构建文件共现计数 + Jaccard 相似度矩阵。

    返回 (files, J)：files 是去重文件列表，J[i][j] 是 Jaccard 相似度（0-1）。
    """
    co_count = defaultdict(int)
    file_count = defaultdict(int)
    for files in commits:
        uniq = set(files)
        flist = list(uniq)
        for f in uniq:
            file_count[f] += 1
        for i in range(len(flist)):
            for j in range(i + 1, len(flist)):
                a, b = sorted((flist[i], flist[j]))
                co_count[(a, b)] += 1

    files = sorted(file_count.keys())
    idx = {f: i for i, f in enumerate(files)}
    n = len(files)
    J = [[0.0] * n for _ in range(n)]
    for (a, b), c in co_count.items():
        i, j = idx[a], idx[b]
        # Jaccard = 共现次数 / (a 出现 + b 出现 - 共现)
        denom = file_count[a] + file_count[b] - c
        if denom > 0:
            J[i][j] = J[j][i] = c / denom
    return files, J


class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


def cluster_by_threshold(files, J, theta: float):
    """并查集聚类：J[i][j] >= theta 的边连通合并。返回 [[文件, ...], ...]。"""
    n = len(files)
    uf = UnionFind(n)
    for i in range(n):
        for j in range(i + 1, n):
            if J[i][j] >= theta:
                uf.union(i, j)
    clusters = defaultdict(list)
    for i in range(n):
        clusters[uf.find(i)].append(files[i])
    # 按簇大小降序
    return sorted(clusters.values(), key=len, reverse=True)


def _avg_distance(ca, cb, J):
    """两簇间的平均 Jaccard 距离 = 1 - 平均相似度（UPGMA 的簇间距离）。"""
    total = 0.0
    for x in ca:
        row = J[x]
        for y in cb:
            total += row[y]
    return 1.0 - (total / (len(ca) * len(cb)))


def cluster_average_linkage(files, J, theta: float):
    """average-linkage (UPGMA) 层次聚类。

    从每个文件一个簇开始，反复合并平均距离最小的簇对，直到最小平均距离
    > (1 - theta)。返回 [[文件, ...], ...]，按簇大小降序。

    与 union-find 单链接的本质区别：合并判定用「簇间平均相似度」而非「存在
    一条 >= theta 的边」。桥接场景（A-B=0.9、B-C=0.9、A-C=0.0，theta=0.6）
    下，union-find 会把 A、B、C 全合并；average-linkage 先并 A-B（平均距离
    0.1），{A,B} 与 C 的平均距离 = 0.55 > 0.4，故 C 保持独立——不再被桥接
    文件串联成大簇。
    """
    n = len(files)
    clusters = [[i] for i in range(n)]  # 每个簇存文件下标
    active = set(range(n))

    while len(active) > 1:
        ids = sorted(active)
        best_d = None
        best_pair = None
        for ai in range(len(ids)):
            for bj in range(ai + 1, len(ids)):
                ca, cb = ids[ai], ids[bj]
                d = _avg_distance(clusters[ca], clusters[cb], J)
                if best_d is None or d < best_d:
                    best_d = d
                    best_pair = (ca, cb)
        # 最小平均距离已超过阈值（其余簇对距离只会更大），停止合并
        if best_d > (1.0 - theta):
            break
        ca, cb = best_pair
        clusters[ca].extend(clusters[cb])
        active.discard(cb)

    result = []
    for i in sorted(active):
        result.append([files[j] for j in clusters[i]])
    return sorted(result, key=len, reverse=True)


def scope_from_cluster(files):
    """把一个簇的文件聚合成 scope 建议字符串。

    - 单文件：返回精确路径
    - 同一顶层目录下：返回公共目录前缀 + /**（如 core/**、core/sub/**）
    - 跨顶层目录：按顶层目录分组，返回 "dir1/**; dir2/**; ..."，避免把
      无公共前缀的簇误导性显示成 /**（commonpath 为空时的旧 bug）。
    """
    if len(files) == 1:
        return files[0]
    top_groups = defaultdict(list)
    for f in files:
        top_groups[f.split("/")[0]].append(f)
    if len(top_groups) == 1:
        prefix = os.path.commonpath(files).replace("\\", "/")
        if any(f != prefix for f in files):
            return prefix + "/**"
        return prefix
    # 跨顶层目录：每个顶层目录各自聚合
    parts = []
    for top in sorted(top_groups):
        grp = top_groups[top]
        if len(grp) == 1:
            parts.append(grp[0])
        else:
            p = os.path.commonpath(grp).replace("\\", "/")
            parts.append(p + "/**" if any(g != p for g in grp) else p)
    return "; ".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description="写耦合度聚类定 scope（G4）")
    ap.add_argument("--limit", type=int, default=200, help="分析的历史 commit 数")
    ap.add_argument("--theta", type=float, default=0.6, help="Jaccard 聚类阈值（0-1）")
    ap.add_argument("--max-files", type=int, default=50,
                    help="剔除文件数超过该值的 commit（初始导入/机械重构，默认 50）")
    ap.add_argument("--min-size", type=int, default=2, help="最小簇大小（小于则列为单文件 scope）")
    a = ap.parse_args()

    commits = collect_commits(a.limit, a.max_files)
    if not commits:
        print("（无 git 历史，冷启动：默认按目录一级切分）")
        return 0
    files, J = build_jaccard(commits)
    clusters = cluster_average_linkage(files, J, a.theta)

    print(f"分析 {len(commits)} 个 commit、{len(files)} 个文件，θ={a.theta}")
    print("建议 scope 划分（写耦合度聚类）：")
    suggestions = []
    for cl in clusters:
        if len(cl) >= a.min_size:
            suggestions.append(scope_from_cluster(cl))
    # 排序去重
    for s in sorted(set(suggestions)):
        print(f"  {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
