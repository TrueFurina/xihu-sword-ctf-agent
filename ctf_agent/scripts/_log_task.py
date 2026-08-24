#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_log_task.py —— 多智能体协同「一键登记任务到 TOP-0 总账」

设计哲学（共识驱动，不靠常驻进程）：
- 每个 AI 会话 / 人工会话，开工前、完工后各跑一次本脚本，把任务写入
  `E:\\Program\\西湖论剑\\协同任务总账-TOP0.md` 的「四、当前开放任务」段。
- 比手写 markdown 简单：一条命令即可，参数化；AI 自然愿意跑。
- 与 git post-commit hook 配合：commit 自动落账（机器强制），本脚本补登
  「非 commit」的意图/进度（共识层）。两层互补，无常驻进程负担。

用法：
  # 开工登记（往「当前开放任务」追加一行）
  python scripts/_log_task.py --start --id "G7" --owner "gu" \
      --what "重做 PKCS#1 离线复盘" --scope "data/results/**"

  # 完工回填（把指定 id 标记为 ✅ + 补 commit/发现）
  python scripts/_log_task.py --done "G7" --commit "abc1234" \
      --note "本地离线解出，非平台 accepted"

  # 加一条自由笔记到「实时变更流」段（如手动改文件未 commit）
  python scripts/_log_task.py --note "手动改 run.py 未提交：临时加日志"

  # 列出当前开放任务（不含已闭环）
  python scripts/_log_task.py --list

会话代号取自环境变量 CT_AGENT_SESSION，缺省记 "manual/<user>"。
"""
import argparse
import os
import re
import sys
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOP0 = os.path.normpath(os.path.join(REPO_ROOT, "..", "协同任务总账-TOP0.md"))

# 开放任务表头（四段）：| 任务ID | 归属 | 状态 | 阻塞原因 / 下一步 |
OPEN_HEAD = "| 任务ID | 归属 | 状态 | 阻塞原因 / 下一步 |"
OPEN_SEP = "|---|---|---|---|"
# 实时变更流表头（五段）
FLOW_HEAD = "| 时间 | 会话 | commit | 主题 | 改动文件 |"
FLOW_SEP = "|---|---|---|---|---|"


def sess() -> str:
    s = os.environ.get("CT_AGENT_SESSION") or ""
    if s:
        return s
    try:
        import getpass
        return "manual/" + (getpass.getuser() or "user")
    except Exception:
        return "manual/unknown"


def load() -> str:
    if not os.path.exists(TOP0):
        sys.stderr.write(f"[log_task] 总账不存在: {TOP0}\n")
        sys.exit(1)
    with open(TOP0, encoding="utf-8") as f:
        return f.read()


def save(s: str):
    with open(TOP0, "w", encoding="utf-8") as f:
        f.write(s)
    print(f"[log_task] ✅ 已更新总账: {TOP0}")


def ensure_open_section(content: str) -> str:
    """确保总账有四段（当前开放任务）表头；没有则追加。"""
    if OPEN_HEAD in content:
        return content
    block = (
        "\n## 四、当前开放任务（登记即开工，完工即回填）\n\n"
        "> 任何会话（AI/人工）开工前必须先在此登记一行；完工后把状态改为 ✅ 并补 commit/发现。\n\n"
        + OPEN_HEAD + "\n" + OPEN_SEP + "\n"
    )
    return content.rstrip() + "\n" + block


def ensure_flow_section(content: str) -> str:
    if FLOW_HEAD in content:
        return content
    block = (
        "\n## 五、实时变更流（自动记录）\n\n"
        "> 本段由 git post-commit / post-merge hook 自动追记；非 commit 的手动改动也请在此补登。\n\n"
        + FLOW_HEAD + "\n" + FLOW_SEP + "\n"
    )
    return content.rstrip() + "\n" + block


def cmd_start(args):
    content = ensure_open_section(load())
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    scope = args.scope or "（未指定）"
    row = f"| **{args.id}** | {args.owner} | 📝 进行中（{now}） | {args.what} · scope={scope} |"
    # 定位「当前开放任务」表头 OPEN_HEAD 之后紧邻的 OPEN_SEP 再插入，
    # 避免在更早出现的同名分隔符（如「会话代号表」）处误插。
    lines = content.split("\n")
    head_idx = None
    for i, l in enumerate(lines):
        if l.strip() == OPEN_HEAD:
            head_idx = i
            break
    if head_idx is None:
        # 兜底：未找到表头，追加到末尾
        lines.append(row)
        save("\n".join(lines))
        return
    out = []
    inserted = False
    for i, l in enumerate(lines):
        out.append(l)
        if (not inserted) and i > head_idx and l.strip() == OPEN_SEP:
            out.append(row)
            inserted = True
    if not inserted:  # 段被手动破坏，追加到末尾
        out.append(row)
    save("\n".join(out))


def cmd_done(args):
    content = load()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    # 把匹配 | **<id>** | 的行替换为 ✅
    task_id = args.done or args.id
    pat = re.compile(r'^\|\s*\*\*' + re.escape(task_id) + r'\*\*\s*\|')
    found = False
    new_lines = []
    for l in content.split("\n"):
        if pat.match(l):
            # 保留原归属，替换状态列与阻塞列
            cells = [c.strip() for c in l.strip().strip("|").split("|")]
            while len(cells) < 4:
                cells.append("")
            cells[0] = f"**{task_id}**"
            cells[2] = f"✅ 已完成（{now}）"
            note = args.note or ""
            commit = f" commit `{args.commit}`" if args.commit else ""
            cells[3] = (note + commit).strip() or "—"
            new_lines.append("| " + " | ".join(cells) + " |")
            found = True
        else:
            new_lines.append(l)
    if not found:
        sys.stderr.write(f"[log_task] 未找到任务 id={task_id}，请确认\n")
        sys.exit(1)
    save("\n".join(new_lines))


def cmd_note(args):
    content = ensure_flow_section(load())
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    row = f"| {now} | {sess()} | — | {args.note} | （手动改动，非 commit） |"
    # 定位「实时变更流」表头 FLOW_HEAD 之后紧邻的 FLOW_SEP 再插入。
    lines = content.split("\n")
    head_idx = None
    for i, l in enumerate(lines):
        if l.strip() == FLOW_HEAD:
            head_idx = i
            break
    if head_idx is None:
        lines.append(row)
        save("\n".join(lines))
        return
    out = []
    inserted = False
    for i, l in enumerate(lines):
        out.append(l)
        if (not inserted) and i > head_idx and l.strip() == FLOW_SEP:
            out.append(row)
            inserted = True
    if not inserted:
        out.append(row)
    save("\n".join(out))


def cmd_list(args):
    content = load()
    lines = content.split("\n")
    print("=== 当前开放任务（未闭环）===")
    in_open = False
    for l in lines:
        if OPEN_HEAD in l:
            in_open = True
            continue
        if in_open:
            if l.strip().startswith("|") and "---" not in l:
                # 跳过已 ✅
                if "✅" in l:
                    continue
                print(l)
            elif l.strip().startswith("## "):
                break
    print("(完)")


def main():
    ap = argparse.ArgumentParser(description="一键登记任务到 TOP-0 协同总账")
    ap.add_argument("--start", action="store_true", help="开工登记")
    ap.add_argument("--done", metavar="ID", help="完工回填（任务 id）")
    ap.add_argument("--note", help="往实时变更流补登一条手动改动")
    ap.add_argument("--list", action="store_true", help="列出当前开放任务")
    ap.add_argument("--id", help="任务 id（如 G7）")
    ap.add_argument("--owner", default=sess(), help="归属会话（默认 CT_AGENT_SESSION）")
    ap.add_argument("--what", help="做什么（开工登记用）")
    ap.add_argument("--scope", help="认领的文件域/租约 scope（开工登记用）")
    ap.add_argument("--commit", help="相关 commit hash（完工回填用）")
    args = ap.parse_args()

    if args.list:
        cmd_list(args)
    elif args.start:
        if not args.id or not args.what:
            sys.stderr.write("--start 需要 --id 和 --what\n")
            sys.exit(1)
        cmd_start(args)
    elif args.done:
        cmd_done(args)
    elif args.note:
        cmd_note(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
