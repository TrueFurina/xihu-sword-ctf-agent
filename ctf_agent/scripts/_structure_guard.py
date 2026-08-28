#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
目录结构守卫（2026-08-28）

目的：防止 agent / 协作者把文件随意堆在仓库根目录或 deliverables/idea-stage 的平铺层，
强迫一切产出归入对应子目录（详见仓库根 AGENTS.md）。

触发：
  - pre-commit 钩子调用（默认只检查本次「新增」文件 --diff-filter=A，不误伤重命名/既有）
  - 手动/CI 调用：python scripts/_structure_guard.py [--all]

规则（命中即违规，打印归位建议并 exit 1）：
  1) 仓库根级散落文件（路径不含 '/'）且后缀在受管清单，且不在根白名单
     白名单：README.md / CLAUDE.md / LICENSE / AGENTS.md
  2) deliverables/ 平铺文件（deliverables/<单段>）且后缀受管，且非 deliverables/overview.md
  3) idea-stage/ 平铺文件（idea-stage/<单段>）且非白名单
     白名单：IDEA_REPORT.md / 方案评估-IDEA1可行性效度评审-20260828.md

设计：
  - 仅标准库；git 调用失败时打印告警并 exit 0（自身 bug 不阻断提交，fail-open for self）。
  - 真正的违规才 exit 1（fail-closed for violations）。
"""
import os
import re
import sys
import subprocess

# 受管后缀（这些类型的散落文件必须归位）
MANAGED_EXT = {
    "md", "txt", "html", "json", "csv", "pdf",
    "png", "jpg", "jpeg", "xlsx", "yml", "yaml",
}

# 根级白名单：仅允许这些文件直接平铺在仓库根。
# REAL_SOLVES_LEDGER.md = 反注水法令 fact-layer（被 _antifraud/_merge_gate/_board/_fix_ledger_kpi
#   四处硬编码引用，且被 .gitignore 的 /data/* 排除——若移入 data/results/ 会从版本控制丢失，
#   故保留在根并显式白名单）；requirements.txt = 构建清单（pip 约定根级，universal convention）。
# 协同任务总账-TOP0.md = 包工头总账活文件（post-commit 自动记账硬编码写 ../协同任务总账-TOP0.md，
#   移动会破坏记账路径，故白名单保留在根）；_INDEX.md = 项目索引（归 docs/ 更规范，但历史散落
#   已存在，先白名单合法化防 --all 误报，doc-归位留给后续）。
ROOT_ALLOW = {"README.md", "README.zh.md", "CLAUDE.md", "LICENSE", "AGENTS.md",
              "REAL_SOLVES_LEDGER.md", "requirements.txt",
              "协同任务总账-TOP0.md", "_INDEX.md"}
DELIV_ROOT_ALLOW = {"deliverables/overview.md"}
IDEA_ROOT_ALLOW = {
    "idea-stage/IDEA_REPORT.md",
    "idea-stage/方案评估-IDEA1可行性效度评审-20260828.md",
}


def _git(*args):
    """统一 git 调用，关闭 quotePath 以免中文路径被加引号/八进制转义导致漏判。"""
    cmd = ["git", "-c", "core.quotePath=false"] + list(args)
    return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8", "ignore")


def unquote_path(p):
    """安全网：若 git 仍输出带引号/八进制转义的路径，还原为原始字节。"""
    p = p.strip()
    if p.startswith('"') and p.endswith('"'):
        p = p[1:-1]
    # 还原 \nnn 八进制转义（git quotePath 行为）
    if "\\" in p:
        try:
            p = p.encode("utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8")
        except Exception:
            pass
    return p


def repo_root():
    try:
        out = _git("rev-parse", "--show-toplevel")
        return out.strip() or None
    except Exception:
        return None


def staged_added_files():
    out = _git("diff", "--cached", "--name-only", "--diff-filter=A")
    return [unquote_path(p) for p in out.splitlines() if p.strip()]


def all_tracked_and_untracked():
    files = set()
    try:
        tracked = _git("ls-files")
        files.update(unquote_path(x) for x in tracked.splitlines() if x.strip())
    except Exception:
        pass
    try:
        untracked = _git("ls-files", "--others", "--exclude-standard")
        files.update(unquote_path(x) for x in untracked.splitlines() if x.strip())
    except Exception:
        pass
    return sorted(files)


# 受管目录（这些目录即使被 .gitignore 完全忽略，也要防磁盘堆积）
_WALK_ROOTS = ["deliverables", "idea-stage", "docs"]


def filesystem_strays():
    """直扫受管目录的磁盘文件（含被 gitignore 忽略者），用于 --all 全量 lint。
    不递归 ctf_agent/_archive/_tools_ghidra 等大目录，避免误报与耗时。"""
    root = repo_root()
    if not root:
        return []
    found = []
    for base in _WALK_ROOTS:
        d = os.path.join(root, base)
        if not os.path.isdir(d):
            continue
        for dirpath, _dirnames, fnames in os.walk(d):
            for fn in fnames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                found.append(rel)
    return found


def ext_of(path):
    _, ext = os.path.splitext(path)
    return ext.lstrip(".").lower()


def check_path(path):
    """返回 None 表示合规；返回字符串表示违规说明。"""
    ext = ext_of(path)
    if ext not in MANAGED_EXT:
        return None

    # 规则 1：根级散落
    if "/" not in path and os.path.basename(path) not in ROOT_ALLOW:
        return (
            f"根目录禁止平铺文件：{path}\n"
            f"    → 研究/idea 产物归 idea-stage/；工程交付归 deliverables/ 子目录；"
            f"项目元文档归 docs/；根仅允许 {sorted(ROOT_ALLOW)}"
        )

    # 规则 2：deliverables 平铺
    if re.match(r"^deliverables/[^/]+$", path) and path not in DELIV_ROOT_ALLOW:
        return (
            f"deliverables/ 根层禁止平铺文件：{path}\n"
            f"    → 归入 deliverables/ 的对应子目录（复盘赛报/治理协议/工程补丁/锐评质检/规划手册/可视化看板/归档_禁用引用）"
        )

    # 规则 3：idea-stage 平铺
    if re.match(r"^idea-stage/[^/]+$", path) and path not in IDEA_ROOT_ALLOW:
        return (
            f"idea-stage/ 根层禁止平铺文件：{path}\n"
            f"    → 归入 idea-stage/proposals/ 或 idea-stage/research/ 或 refine-logs/"
        )

    return None


def main():
    try:
        if repo_root() is None:
            print("⚠️ 结构守卫：未检测到 git 仓库，跳过（不阻断）")
            return 0

        if "--all" in sys.argv:
            files = set(all_tracked_and_untracked()) | set(filesystem_strays())
            mode = "全量扫描"
        else:
            files = staged_added_files()
            mode = "暂存新增"

        violations = []
        for p in files:
            reason = check_path(p)
            if reason:
                violations.append(reason)

        if not violations:
            print(f"✅ 目录结构守卫（{mode}）：无散落文件")
            return 0

        print(f"❌ 目录结构守卫（{mode}）：发现 {len(violations)} 处散落文件，请归入对应子目录")
        print("   规则详见仓库根 AGENTS.md")
        print("   ──")
        for v in violations:
            print("   " + v)
        return 1
    except Exception as e:  # 自身异常 fail-open，绝不因脚本 bug 阻断提交
        print(f"⚠️ 结构守卫：自检异常（{e}），已跳过，不阻断提交")
        return 0


if __name__ == "__main__":
    sys.exit(main())
