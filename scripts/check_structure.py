#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仓库结构自检入口（2026-08-28）
调用 ctf_agent/scripts/_structure_guard.py。
用法：
  python scripts/check_structure.py            # 仅检查本次新增（与 pre-commit 同口径）
  python scripts/check_structure.py --all      # 全量扫描工作区（含既有/未提交散落）
退出码：0=合规，1=发现散落文件。
"""
import os
import subprocess
import sys

try:
    root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"],
        stderr=subprocess.DEVNULL,
    ).decode("utf-8", "ignore").strip()
except Exception:
    root = os.getcwd()

target = os.path.join(root, "ctf_agent", "scripts", "_structure_guard.py")
cmd = [sys.executable, target] + sys.argv[1:]
sys.exit(subprocess.call(cmd))
