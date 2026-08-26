#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""密钥泄漏扫描器（P0-1 防回归门禁，2026-08-21 赛后）。

用法：
    python scripts/_scan_secrets.py                 # 扫描工作区全部文件（排除 .git/.venv）
    python scripts/_scan_secrets.py --cached        # 扫描 git diff --cached（pre-commit 用）
    python scripts/_scan_secrets.py --files a b c   # 扫描指定文件列表

匹配规则（任一命中即报错退出码 1）：
    - ak_live_ 平台 AccessKey（西湖论剑官方）
    - sk-[A-Za-z0-9]{16,}  OpenAI 风格 API Key
    - DASCTF_TOKEN= / CTF_AGENT_PLATFORM_TOKEN= 明文赋值

注意：本脚本只扫描"将要进入 git"的内容（--cached 模式）或显式/工作区文件；
不扫描 .git 目录（历史清洗需用户决策，见修复总结）。
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import Iterable, List

# 命中即报错的正则（保持紧凑，避免误伤普通文字）
_SECRET_PATTERNS = (
    re.compile(r"ak_live_[A-Za-z0-9]{6,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"(?:DASCTF_TOKEN|CTF_AGENT_PLATFORM_TOKEN)\s*=\s*[A-Za-z0-9_\-]{8,}"),
)

# 跳过目录/文件（.git、venv、二进制、日志）
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", ".bak_sprint"}
_SKIP_EXTS = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".7z", ".gz",
              ".tar", ".bin", ".exe", ".elf", ".so", ".pdf", ".jar", ".class", ".pyo",
              ".pcap", ".pcapng", ".db", ".sqlite", ".lime", ".raw", ".img", ".iso",
              ".woff", ".ttf", ".otf", ".mp4", ".mp3", ".wav"}
_SKIP_FILES = {"package-lock.json", "poetry.lock", "Pipfile.lock"}
# 大文件只读头部（防 2GB 内存镜像/大附件把扫描器拖死；密钥通常出现在文本头部）
_MAX_READ_BYTES = 2 * 1024 * 1024


def scan_text(text: str, path: str = "") -> List[str]:
    """扫描文本，返回命中描述列表。"""
    hits: List[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        for pat in _SECRET_PATTERNS:
            m = pat.search(line)
            if m:
                # 脱敏展示：只显示前后缀，不打印完整密钥
                secret = m.group(0)
                shown = secret[:8] + "..." + secret[-4:] if len(secret) > 14 else secret[:6] + "..."
                hits.append(f"{path}:{idx}: 疑似密钥 {shown!r} (pattern={pat.pattern[:30]}...)")
                break
    return hits


def scan_files(paths: Iterable[str]) -> List[str]:
    """扫描给定文件路径，返回命中列表。"""
    hits: List[str] = []
    for path in paths:
        if not os.path.isfile(path):
            continue
        ext = os.path.splitext(path)[1].lower()
        base = os.path.basename(path)
        if ext in _SKIP_EXTS or base in _SKIP_FILES:
            continue
        try:
            size = os.path.getsize(path)
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read(_MAX_READ_BYTES) if size > _MAX_READ_BYTES else fh.read()
        except OSError:
            continue
        hits.extend(scan_text(text, path))
    return hits


def walk_workspace(root: str) -> List[str]:
    """遍历工作区（排除 .git/.venv 等）返回文件路径。"""
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            out.append(os.path.join(dirpath, fn))
    return out


def cached_files() -> List[str]:
    """git diff --cached --name-only -z → 文件路径列表（pre-commit 场景）。"""
    try:
        raw = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "-z"],
            capture_output=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [p for p in raw.decode("utf-8", errors="ignore").split("\0") if p]


def main() -> int:
    parser = argparse.ArgumentParser(description="密钥泄漏扫描器（防回归门禁）")
    parser.add_argument("--cached", action="store_true", help="扫描 git 暂存区（pre-commit 用）")
    parser.add_argument("--files", nargs="*", default=None, help="扫描指定文件列表")
    args = parser.parse_args()

    if args.files is not None:
        files = args.files
    elif args.cached:
        files = cached_files()
    else:
        files = walk_workspace(os.getcwd())

    hits = scan_files(files)
    if hits:
        print("❌ 密钥泄漏扫描失败（疑似凭据进入提交/工作区）：")
        for h in hits:
            print(f"   - {h}")
        print("请先在平台侧轮换对应凭据并脱敏后再提交；如确认是误报，检查命中行。")
        return 1
    if args.cached:
        print("✅ 暂存区密钥扫描通过（无 ak_live_/sk-/DASCTF_TOKEN 明文）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
