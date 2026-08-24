#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""诚实口径扫描器（机器事前拦截假水位，2026-08-23）。

背景：本项目平台 accepted = 0（初赛真实战绩）。任何活跃文档里出现
「解出数递增 / 真实解出 flag / +N 真实解出」这类表述，都是把离线刷题
（本地 strings 扫描 / 数学推导）冒充成平台战报，违反《真实战绩口径声明》。
本脚本把《test_report_honesty.py》的扫描逻辑升级为可挂 pre-commit 的
机器门禁：假水位在 commit 时即被拦截，而非等测试事后报警。

用法：
    python scripts/_honesty_scan.py                 # 扫描活跃文档（data/results + docs）
    python scripts/_honesty_scan.py --cached        # 扫描暂存区（pre-commit 用）
    python scripts/_honesty_scan.py --files a b c   # 扫描指定文件列表

规则（任一命中即报错退出码 1）：
    - 短语：冲第一 / 真实水位 89%|92%|100% / 自主 7/7 / 将功补过 / 解出数提升
    - 正则：解出数 X→Y 递增（如"解出数 15→16"）/ +N 真实解出 / 真实解出…flag

排除（已归档/第三方，不参与诚实口径）：
    - `_archive` 前缀文件（如 _archive_离线刷题复盘-*.md）
    - 目录路径含 archive / race_attachments / work_web / platform_downloads
"""

from __future__ import annotations

import argparse
import io
import os
import re
import subprocess
import sys
from typing import Iterable, List

# 命中即报错的短语（历史违规样本，保持紧凑避免误伤）
# ⚠️ 2026-08-23 对齐补全：补裸数字区间（5→13/13→15/15→16/16→26）堵"提交绿、测试红"；
#   注意**不补裸词"真实解出"**——会误伤方法论表述（"先真实解出题验证"），
#   结果宣称由下方正则 `真实解出[^。\n]*flag` / `\+\d+\s*真实解出` 抓（test_methodology_not_hit 契约）。
_FORBIDDEN_PHRASES = (
    "冲第一", "真实水位 89%", "真实水位 92%", "真实水位 100%",
    "自主 7/7", "将功补过", "解出数提升",
    "5→13", "13→15", "15→16", "16→26",
    "解出数 16", "解出数 26",
)

# 命中即报错的正则（覆盖"短语"抓不住的递增/结果宣称模式）
_FORBIDDEN_PATTERNS = (
    # 解出数递增（如"解出数 5→13"、"解出数 15→16"）：平台 accepted=0 时任何递增都是假水位
    re.compile(r"解出数\s*\d+\s*→\s*\d+"),
    # "+N 真实解出"（如"+1 真实解出"）
    re.compile(r"\+\d+\s*真实解出"),
    # "真实解出…flag"（结果宣称，如"真实解出——flag 拿到"）；不跨句号/换行，避免
    # 误伤"先真实解出题验证"这类方法论表述
    re.compile(r"真实解出[^。\n]*flag"),
)

# 使用-提及区分：引号包裹的内容是「提及」违规词（如治理记录里引用「将功补过」说明
# "已去掉该词"），裸词才是「使用」。剥离引号后匹配，避免自我指涉死循环。
_QUOTE_RE = re.compile(r"「[^」]*」|『[^』]*』|“[^”]*”|“[^”]*”|\"[^\"]*\"")


def _strip_quoted(text: str) -> str:
    """剥离引号包裹的内容（「」/『』/双引号），仅对剩余文本做违规匹配。"""
    return _QUOTE_RE.sub("", text)

# 排除目录关键字（已归档/第三方下载）
_SKIP_DIR_KEYWORDS = ("archive", "race_attachments", "work_web", "platform_downloads")
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache"}


def scan_text(text: str, path: str = "") -> List[str]:
    """扫描文本，返回命中描述列表（先剥离引号内的「提及」再匹配）。"""
    hits: List[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = _strip_quoted(line)
        for phrase in _FORBIDDEN_PHRASES:
            if phrase in stripped:
                hits.append(f"{path}:{idx}: 假水位短语 {phrase!r}")
        for pat in _FORBIDDEN_PATTERNS:
            m = pat.search(stripped)
            if m:
                shown = m.group(0)
                if len(shown) > 40:
                    shown = shown[:40] + "…"
                hits.append(f"{path}:{idx}: 假水位表述 {shown!r}")
    return hits


def scan_files(paths: Iterable[str]) -> List[str]:
    """扫描给定文件路径（仅 .md），返回命中列表。"""
    hits: List[str] = []
    for path in paths:
        if not os.path.isfile(path) or not path.endswith(".md"):
            continue
        base = os.path.basename(path)
        if base.startswith("_archive"):
            continue
        try:
            with io.open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        hits.extend(scan_text(text, path))
    return hits


def active_doc_files(root: str) -> List[str]:
    """遍历 data/results 与 docs 下的活跃 .md（排除 _archive 前缀与归档目录）。"""
    out: List[str] = []
    for base in ("data/results", "docs"):
        full = os.path.join(root, base)
        if os.path.isfile(full) and full.endswith(".md"):
            out.append(full)
        elif os.path.isdir(full):
            for dp, dirnames, fns in os.walk(full):
                dirnames[:] = [d for d in dirnames
                               if d not in _SKIP_DIRS and not any(k in d for k in _SKIP_DIR_KEYWORDS)]
                # 归档目录内的文件整体跳过（仅过滤 dirnames 会漏掉直接位于归档目录下的 .md）
                if any(k in os.path.basename(dp) for k in _SKIP_DIR_KEYWORDS):
                    continue
                for fn in fns:
                    if fn.endswith(".md") and not fn.startswith("_archive"):
                        out.append(os.path.join(dp, fn))
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


def commit_message_path() -> str:
    """当前 commit message 文件路径（git rev-parse --git-path COMMIT_EDITMSG）。"""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--git-path", "COMMIT_EDITMSG"],
            capture_output=True, check=True, text=True,
        ).stdout.strip()
        return out or ""
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def scan_commit_message() -> List[str]:
    """扫描当前 commit message（.git/COMMIT_EDITMSG）——堵 99fb169 类翻车：
    commit message 里写『真实解出 flag DASCTF{...}』的假水位，文件扫描拦不到。"""
    path = commit_message_path()
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return []
    return scan_commit_text(text)


# commit message 专属：flag 明文检测（2026-08-23 锐评 P2-1 实装，堵 99fb169 复发）
# 99fb169 教训：commit message 里直接写真实 flag（DASCTF{...}）是明文泄露。
# 不进全局 _FORBIDDEN_PATTERNS（避免误伤文档/代码里的占位示例），只查 commit message。
# 脱敏展示：命中只显示前缀 + 长度，不打印完整 flag（密钥三不）。
_FLAG_PLAINTEXT_PATTERNS = (
    re.compile(r"DASCTF\{[^}\n]{4,}\}"),     # 平台 flag 格式（正式赛）
    re.compile(r"flag\{[^}\n]{6,}\}"),       # 通用 flag 格式（长度阈值避免误伤 flag{x} 占位）
    re.compile(r"xctf\{[^}\n]{4,}\}"),       # XCTF 平台格式
)


def scan_commit_text(text: str) -> List[str]:
    """commit message 全量检查：假水位短语 + flag 明文（两部分各自独立）。"""
    hits = scan_text(text, "COMMIT_EDITMSG")
    for idx, line in enumerate(text.splitlines(), start=1):
        for pat in _FLAG_PLAINTEXT_PATTERNS:
            m = pat.search(line)
            if m:
                shown = m.group(0)
                safe = shown[:14] + "…" if len(shown) > 14 else shown
                hits.append(f"COMMIT_EDITMSG:{idx}: flag 明文 {safe}（真实 flag 不应进 commit message——99fb169 教训）")
    return hits


def scan_commit_message_file(path: str) -> List[str]:
    """扫描指定 commit message 文件（commit-msg 钩子传入 $1，机制上可靠）。"""
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return []
    return scan_commit_text(text)


def main() -> int:
    parser = argparse.ArgumentParser(description="诚实口径扫描器（拦截假水位）")
    parser.add_argument("--cached", action="store_true", help="扫描 git 暂存区（pre-commit 用）")
    parser.add_argument("--commit-msg", action="store_true", help="扫描当前 commit message（兼容旧调用）")
    parser.add_argument("--commit-msg-file", default=None, help="扫描指定 commit message 文件（commit-msg 钩子传 $1）")
    parser.add_argument("--files", nargs="*", default=None, help="扫描指定文件列表")
    args = parser.parse_args()

    if args.commit_msg_file is not None:
        hits = scan_commit_message_file(args.commit_msg_file)
        if hits:
            print("❌ commit message 检出假水位表述（离线刷题冒充战报）：")
            for h in hits:
                print(f"   - {h}")
            print("处置：改 commit message——平台 accepted=0，解出/递增只允许出现『离线推导，非平台 accepted』。")
            return 1
        print("✅ commit message 诚实口径扫描通过")
        return 0

    if args.commit_msg:
        hits = scan_commit_message()
        if hits:
            print("❌ commit message 检出假水位表述（离线刷题冒充战报）：")
            for h in hits:
                print(f"   - {h}")
            print("处置：改 commit message——平台 accepted=0，解出/递增只允许出现『离线推导，非平台 accepted』。")
            return 1
        print("✅ commit message 诚实口径扫描通过")
        return 0

    if args.files is not None:
        files = args.files
    elif args.cached:
        files = cached_files()
    else:
        files = active_doc_files(os.getcwd())

    hits = scan_files(files)
    if hits:
        print("❌ 诚实口径扫描失败（活跃文档检出假水位表述）：")
        for h in hits:
            print(f"   - {h}")
        print("平台 accepted=0，任何『解出数递增/真实解出 flag』都是离线刷题冒充战报。")
        print("处置：把该段改为诚实表述（标注『离线/本地推导，非平台 accepted』），或归档到 _archive_ 前缀文件。")
        return 1
    if args.cached:
        print("✅ 暂存区诚实口径扫描通过（无假水位表述）")
    else:
        print("✅ 活跃文档诚实口径扫描通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
