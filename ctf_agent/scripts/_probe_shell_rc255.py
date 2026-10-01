"""零成本探针：复现 agent 持久工作区 shell 的 rc=255「读不到附件」故障。

背景（2026-10-01 抬预算对照实测发现）：
    A 档 5 题给足 2.5× 预算（单题 20 万 token）仍 0/5。翻日志发现真正的失败模式不是
    "想不出解法"，而是 **agent 根本没读到附件**：
        监督 LLM 裁决: 工作区 shell 持续不可用（rc=255 路径错误），
                      模型在重复无效的 recon 推理，无法读取脚本内容
        题目提示用 radare2 的 r2 脚本语言...当前在 Windows 上路径错误导致命令失败，
                      且尚未真正分析脚本内容
    如果 shell 真的读不到文件，那**再多的 token 也只是空烧**——这是比"能力 0"更值钱的发现。

本探针零 LLM 成本：在真实工作区（含中文路径）里跑 agent 会用的那几条命令，看 rc 与输出。

用法：
    python scripts/_probe_shell_rc255.py [--ws <工作区目录>] [--file <附件绝对路径>]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ws", default=None,
                    help="工作区目录（默认自动建一个，路径含中文以复现真实条件）")
    ap.add_argument("--file", default=None, help="要读的附件绝对路径")
    args = ap.parse_args()

    from core.session import Session

    root = Path(__file__).resolve().parents[1]
    if args.ws:
        ws = Path(args.ws)
    else:
        ws = root / "data" / "results" / "g_sessions" / "_probe_rc255"
    ws.mkdir(parents=True, exist_ok=True)

    target = args.file or str(
        root / "data" / "questions_ext" / "_attachments" / "crypto"
        / "2017q-cry-almost_xor" / "almostxor.py")

    print(f"工作区  : {ws}")
    print(f"目标文件: {target}")
    print(f"文件存在: {Path(target).exists()}")
    print()

    s = Session(str(ws), session_id="_probe")
    cmds = [
        ("dir（cmd 内置）", "dir"),
        ("type 读附件", f'type "{target}"'),
        ("python 读附件", f'python -c "print(open(r\\"{target}\\", encoding=\\"utf-8\\", errors=\\"replace\\").read()[:200])"'),
        ("cd 到工作区", f'cd /d "{ws}"'),
        ("echo 自检", "echo probe-ok"),
    ]
    bad = 0
    for label, cmd in cmds:
        rec = s.run(cmd, timeout=30, note=label)
        out = (rec.stdout or "").strip()[:160].replace("\n", " | ")
        err = (rec.stderr or "").strip()[:160].replace("\n", " | ")
        flag = "" if rec.returncode == 0 else "  <== 非零"
        if rec.returncode != 0:
            bad += 1
        print(f"[{label}] rc={rec.returncode}{flag}")
        if out:
            print(f"    stdout: {out}")
        if err:
            print(f"    stderr: {err}")
    print()
    print(f"非零返回 {bad}/{len(cmds)} 条")
    print("判读：若「type 读附件」/「python 读附件」非零 → 工作区 shell 确实读不到附件，")
    print("      则 A 档 0/5 的主因是执行环境缺陷而非解题能力，应先修环境再谈能力测量。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
