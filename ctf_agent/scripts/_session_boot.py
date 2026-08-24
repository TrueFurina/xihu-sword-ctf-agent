#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""会话启动门禁（2026-08-24 阶段2 车道方案）——会话的第一条指令就是这个命令。

设计原则（锐评六轮收敛 + 并发有序化方案 eaf29aa 落地）：
  治理的全部力量压缩进"会话执行的第一条命令"这一个注入点。
  人会忘、文档会漏，但"开工必须先跑本命令"是 100% 可控的注入点。

检查清单（fail-closed，任一项不过 → 打印处置并 exit 1）：
  ① 车道分支：当前分支必须是 w/<任务名>（main 直提由 pre-commit 拦截）
  ② 身份登记：CT_AGENT_SESSION 已设置（或 git config atomcode.session 兜底）
  ③ 工作树干净：git status --porcelain 为空（脏树 → 先收口，不许带脏开工）
  ④ 环境可用：.venv/Scripts/python.exe 存在（新 worktree 用 --fix-env 建 junction）
  ⑤ 快速冒烟：--smoke 时跑防错体系核心回归（<10s）

用法：
  python scripts/_session_boot.py             # 门禁检查
  python scripts/_session_boot.py --fix-env   # 自动创建 .venv junction（Windows）
  python scripts/_session_boot.py --smoke     # 门禁 + 快速回归冒烟

车道规范（一人一 worktree，物理隔离）：
  git worktree add ../wt-<任务名> -b w/<任务名>
  cd ../wt-<任务名>
  python scripts/_session_boot.py --fix-env   # 门禁 + 环境
  # 之后在本车道自由提交；main 只由合并闸门 squash 进（阶段3）
"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_WORKTREE = os.path.dirname(ROOT)  # E:/Program/西湖论剑/ctf_agent 的父目录


def sh(cmd, cwd=ROOT):
    return subprocess.run(cmd, cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")


def branch_name():
    out = sh(["git", "branch", "--show-current"])
    return out.stdout.strip()


def fix_env() -> bool:
    """Windows junction：新 worktree 没有 .venv，链接到主工作树的 .venv。"""
    venv = os.path.join(ROOT, ".venv")
    main_venv = os.path.join(MAIN_WORKTREE, "ctf_agent", ".venv")
    if os.path.exists(venv):
        print(f"✅ .venv 已存在：{venv}")
        return True
    if not os.path.isdir(main_venv):
        print(f"❌ 主工作树 .venv 不存在：{main_venv}（先跑主工作树 bash setup.sh）")
        return False
    try:
        r = subprocess.run(
            ["cmd", "/c", "mklink", "/J", venv, main_venv],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode == 0:
            print(f"✅ .venv junction 已创建：{venv} -> {main_venv}")
            return True
        print(f"❌ mklink 失败：{r.stdout} {r.stderr}")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"❌ junction 创建异常：{exc}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="会话启动门禁（车道方案）")
    ap.add_argument("--fix-env", action="store_true", help="自动创建 .venv junction")
    ap.add_argument("--smoke", action="store_true", help="额外跑快速回归冒烟")
    args = ap.parse_args()

    ok = True
    print("══ 会话启动门禁（阶段2 车道方案）══")

    # ── ① 车道分支 ──
    br = branch_name()
    if not br.startswith("w/"):
        print(f"❌ 车道分支：当前分支「{br or '(detached)'}」不是 w/<任务名>")
        print("   处置：git worktree add ../wt-<任务名> -b w/<任务名> 换车道后重试")
        ok = False
    else:
        print(f"✅ 车道分支：{br}")

    # ── ①b 车道位置（2026-08-24 第七轮锐评：门禁只看分支名、没看车道位置——
    #     违规会话切到 w/ 分支名就过了①，却占用了主工作树（孤儿 switch 事故根因）。
    #     判断：git-dir == common-dir = 主工作树；主工作树只允许 main，车道必须独立 worktree）──
    git_dir = sh(["git", "rev-parse", "--git-dir"]).stdout.strip()
    common_dir = sh(["git", "rev-parse", "--git-common-dir"]).stdout.strip()
    is_main_tree = os.path.normpath(git_dir) == os.path.normpath(common_dir)
    if is_main_tree and br != "main":
        print(f"❌ 车道位置：当前是主工作树（git-dir==common-dir={git_dir}），但分支是「{br}」")
        print("   处置：主工作树只允许 main；车道必须 git worktree add ../wt-<任务名> -b w/<任务名>（独立目录）")
        print("        已误入主工作树 → git switch main 回主树，再按上面建独立车道")
        ok = False
    else:
        loc = "主工作树(main)" if br == "main" else "独立 worktree 车道"
        print(f"✅ 车道位置：{loc}（git-dir={git_dir}）")

    # ── ② 身份登记 ──
    session = os.environ.get("CT_AGENT_SESSION") or sh(
        ["git", "config", "--get", "atomcode.session"]).stdout.strip()
    if not session:
        print("❌ 身份登记：CT_AGENT_SESSION 未设置，也无 git config atomcode.session")
        print("   处置：export CT_AGENT_SESSION=<你的会话名>（并 python scripts/_sign.py bind）")
        ok = False
    else:
        print(f"✅ 身份登记：{session}")

    # ── ③ 工作树干净 ──
    st = sh(["git", "status", "--porcelain"]).stdout.strip()
    if st:
        print("❌ 工作树脏（在飞改动，裸奔残留）：")
        for line in st.splitlines()[:15]:
            print(f"   {line}")
        print("   处置：先收口（提交到本车道或移交协调者），不许带脏开工")
        ok = False
    else:
        print("✅ 工作树干净")

    # ── ④ 环境可用 ──
    py = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
    if os.path.exists(py):
        print(f"✅ .venv 可用：{py}")
    elif args.fix_env:
        ok = fix_env() and ok
    else:
        print(f"❌ .venv 缺失（新 worktree 常见）：{py}")
        print("   处置：python scripts/_session_boot.py --fix-env（自动 junction 主工作树 .venv）")
        ok = False

    # ── ⑤ 快速冒烟 ──
    if args.smoke and ok:
        print("── 快速回归冒烟（防错体系核心测试）──")
        r = sh([sys.executable, "-m", "pytest",
                "tests/test_lease.py", "tests/test_sign.py",
                "tests/test_honesty_scan.py", "tests/test_closeout.py",
                "-q", "--no-header"])
        print(r.stdout[-800:] if r.stdout else "")
        if r.returncode != 0:
            print("❌ 冒烟失败：门禁自身被改坏或环境异常")
            ok = False
        else:
            print("✅ 冒烟通过")

    print()
    if ok:
        print("✅ 车道就绪：可以开工（提交走本车道，main 由合并闸门收）")
        return 0
    print("❌ 门禁未过：按上述处置逐项修复；修复不了 → 换车道/找协调者")
    return 1


if __name__ == "__main__":
    sys.exit(main())
