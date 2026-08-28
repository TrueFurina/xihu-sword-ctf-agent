#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布导出（作战计划 2.2 双仓库模型，2026-08-25）——从作战仓库导出公开树。

设计（第九轮作战计划 第二部分）：
  作战仓库（私有，本仓库）→ 发布脚本导出 → 发布仓库（公开）。
  发布树 = git archive 当前 HEAD + 白名单删除 + 题库 flag 字段脱敏 + fail-closed 自检。

流程：
  1. git archive HEAD 导出到输出目录（临时目录或 --out 指定）；
  2. 白名单删除：data/results/、docs/internal/、logs/、_archive/ 等内部资产；
  3. 题库 JSON flag 字段 → "<redacted>"（防御性脱敏，题库当前已是 sha256 占位）；
  4. 自检（fail-closed）：导出树扫描真实 flag 明文 / API key，零命中才放行；
  5. 可选 --tag：通过后打 tag public-YYYYMMDD（推送由外部/CI 决定）。

自检规则（避免误伤代码判断字符串）：
  - FAIL（硬失败）：DASCTF{...} / vnctf{...} / flag{...} 花括号内为实质内容
    （hex/随机串/较长 payload）且非引号包裹的判断字符串、非格式描述；
  - API key：sk-{16+}、Bearer {20+}、ghp_{30+}。
  - WARN（不失败）：引号包裹的 "flag{" 判断字符串、格式描述（如 DASCTF{init1-init2}）。

用法：
  python scripts/release_export.py                 # 导出到临时目录 + 自检
  python scripts/release_export.py --out D:/tmp/release  # 指定输出目录
  python scripts/release_export.py --tag           # 自检通过后打 tag public-YYYYMMDD
  python scripts/release_export.py --scan-only     # 只扫描当前仓库跟踪树，不导出
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

REAL_FLAG_RE = re.compile(
    r"(?:DASCTF|flag|CTF|vnctf|QNFPGS|SYNT)\{[^}\n]{10,}\}",
    re.IGNORECASE,
)
# 引号包裹的判断字符串（代码里 if "flag{" in ... 之类）——不算泄漏
QUOTED_FLAG_RE = re.compile(r"[\"'](?:flag|dasctf|ctf|vnctf)\{", re.IGNORECASE)
# 格式描述（花括号内是简短占位符）——不算泄漏
FORMAT_DESC_RE = re.compile(
    r"(?:DASCTF|flag|CTF|vnctf)\{(?:[a-zA-Z0-9_\-]{1,20})\}", re.IGNORECASE,
)
SECRET_RE = re.compile(
    r"(?:sk-[A-Za-z0-9]{16,}|Bearer [A-Za-z0-9._\-]{20,}|ghp_[A-Za-z0-9]{30,})"
)

# 发布树必须剔除的内部资产目录（相对仓库根）
EXCLUDE_DIRS = [
    "ctf_agent/data/results",
    "ctf_agent/docs/internal",
    "ctf_agent/logs",
    "ctf_agent/data/results_backup",
    "_archive",
    "_backup",
    "_git_backup",
]
# 发布树剔除的散件
EXCLUDE_FILES = [
    "ctf_agent/benchmark_report.json",
]

# 明确的假 flag / 占位 / 反例 —— 一律豁免（不算泄漏）
FAKE_FLAG_PATTERNS = [
    r"<redacted>",              # 我们自己的脱敏占位
    r"mock|fake|demo|placeholder",  # 假 flag（mock_web_target_flag、fake_first_attempt…）
    r"vafvqr_ebg13_synt",       # ROT13 测试假 flag（inside_rot13_flag）
    r"inside_rot13",            # 测试注释里的明文说明
    r"init1-init2",             # 格式描述（lfsr 题型 DASCTF{init1-init2}）
    r"caesar_shift_2026",       # 教学示例
    r"\\x[0-9a-fA-F]{2}",       # 转义控制字符 = 注释反例说明（presolve.py 实证垃圾）
    r"fault_test|sqli_waf_bypass|ECB_block_attack",  # 测试/教学示例 flag
    r"DASCTF\{/flag\{",         # 参数前缀列表说明（crypto_high_exponent.json input_spec）
]
FAKE_FLAG_RE = re.compile("|".join(FAKE_FLAG_PATTERNS), re.IGNORECASE)


def sh(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=600, cwd=cwd,
    )


def repo_root() -> Path:
    r = sh(["git", "rev-parse", "--show-toplevel"])
    if r.returncode != 0:
        print(f"❌ 不在 git 仓库内: {r.stderr.strip()}")
        sys.exit(1)
    return Path(r.stdout.strip())


def redact_question_flags(tree: Path) -> int:
    """题库 JSON 的 flag 字段 → '<redacted>'（防御性）。返回脱敏文件数。"""
    n = 0
    for jf in tree.rglob("*.json"):
        if "questions" not in str(jf).replace("\\", "/"):
            continue
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, dict) and data.get("flag") and data["flag"] != "<redacted>":
            data["flag"] = "<redacted>"
            jf.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            n += 1
    return n


def scan_tree(tree: Path, files: list[Path] | None = None) -> tuple[list[str], list[str]]:
    """扫描导出树。返回 (FAIL 列表, WARN 列表)。

    files=None → 遍历 tree 下全部文件（导出树用，树是干净的 git archive）；
    files=显式列表 → 只扫这些文件（scan_current 用，避免遍历 .venv/_archive 等）。
    """
    fails: list[str] = []
    warns: list[str] = []
    scan_list = files if files is not None else [p for p in tree.rglob("*") if p.is_file()]
    for p in scan_list:
        if not p.is_file():
            continue
        if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".zip", ".rar",
                                ".pcapng", ".pdf", ".pyc", ".b64", ".bin", ".wav"}:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = p.relative_to(tree)
        # API key —— 硬失败
        for m in SECRET_RE.finditer(text):
            fails.append(f"{rel}: API key 疑似 {m.group(0)[:16]}…")
        # 真实 flag 明文（排除判断字符串、格式描述、假 flag/占位/反例）
        for m in REAL_FLAG_RE.finditer(text):
            token = m.group(0)
            line = text[: m.start()].count("\n") + 1
            # 排除引号包裹的判断字符串：检查命中位置前是否在引号上下文内
            before = text[max(0, m.start() - 3): m.start()]
            if '"' in before or "'" in before:
                warns.append(f"{rel}:{line}: 判断字符串 {token[:30]}…")
                continue
            if FORMAT_DESC_RE.fullmatch(token):
                warns.append(f"{rel}:{line}: 格式描述 {token[:30]}…")
                continue
            if FAKE_FLAG_RE.search(token):
                warns.append(f"{rel}:{line}: 假 flag/占位/反例 {token[:30]}…")
                continue
            fails.append(f"{rel}:{line}: 真实 flag 明文 {token[:40]}…")
    return fails, warns


def export(out_dir: Path) -> int:
    root = repo_root()
    print(f"── 发布导出（来源仓库: {root}）──")
    # git archive 输出是字节流（可能含非 UTF-8 文件名），直接走管道给 tar
    r = subprocess.run(
        ["git", "archive", "HEAD"], cwd=root,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600,
    )
    if r.returncode != 0:
        print(f"❌ git archive 失败: {r.stderr.decode(errors='replace').strip()}")
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    # 用 Python tarfile 解包（Windows 外部 tar 对中文文件名会报 Invalid empty pathname）
    import io
    import tarfile
    try:
        with tarfile.open(fileobj=io.BytesIO(r.stdout), mode="r:") as tf:
            tf.extractall(path=str(out_dir), filter="data")
    except Exception as exc:  # noqa: BLE001
        print(f"❌ 解包失败: {exc}")
        return 1
    # 白名单删除
    for d in EXCLUDE_DIRS:
        target = out_dir / d
        if target.exists():
            shutil.rmtree(target)
            print(f"  剔除目录: {d}")
    for f in EXCLUDE_FILES:
        target = out_dir / f
        if target.exists():
            target.unlink()
            print(f"  剔除文件: {f}")
    # 题库 flag 脱敏
    n = redact_question_flags(out_dir)
    if n:
        print(f"  题库 flag 字段脱敏: {n} 个 JSON")
    return verify(out_dir)


def verify(tree: Path) -> int:
    print(f"── 发布自检（fail-closed: {tree}）──")
    fails, warns = scan_tree(tree)
    for w in warns:
        print(f"  ⚠️  {w}")
    if fails:
        print(f"❌ 自检失败：发现 {len(fails)} 处真实泄漏：")
        for f in fails[:30]:
            print(f"    - {f}")
        print("   处置：剔除对应文件或脱敏后重试（发布树不允许任何真实 flag/密钥）")
        return 1
    print(f"✅ 自检通过：零真实 flag / 零 API key（{len(warns)} 处判断字符串/格式描述已豁免）")
    return 0


def scan_current() -> int:
    """只扫描当前跟踪树（不导出），用于发布前摸底。"""
    root = repo_root()
    print(f"── 扫描当前跟踪树（{root}，仅摸底，基于 git ls-files）──")
    r = sh(["git", "ls-files", "-z"], cwd=root)
    if r.returncode != 0:
        print(f"❌ git ls-files 失败: {r.stderr.strip()}")
        return 1
    files = [root / f for f in r.stdout.split("\0") if f]
    print(f"  跟踪文件 {len(files)} 个")
    fails, warns = scan_tree(root, files=files)
    for w in warns[:20]:
        print(f"  ⚠️  {w}")
    if fails:
        print(f"❌ 发现 {len(fails)} 处真实泄漏：")
        for f in fails[:30]:
            print(f"    - {f}")
        return 1
    print(f"✅ 跟踪树零真实泄漏（{len(warns)} 处豁免）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="发布导出（作战计划 2.2 双仓库模型）")
    ap.add_argument("--out", type=str, default=None, help="输出目录（默认临时目录）")
    ap.add_argument("--tag", action="store_true", help="自检通过后打 tag public-YYYYMMDD")
    ap.add_argument("--scan-only", action="store_true", help="只扫描当前跟踪树，不导出")
    args = ap.parse_args()

    if args.scan_only:
        return scan_current()

    if args.out:
        out_dir = Path(args.out)
        code = export(out_dir)
    else:
        tmp = Path(tempfile.mkdtemp(prefix="release_export_"))
        code = export(tmp)
        print(f"  输出目录: {tmp}")

    if code != 0:
        return code
    if args.tag:
        tag = f"public-{date.today():%Y%m%d}"
        r = sh(["git", "tag", tag])
        if r.returncode == 0:
            print(f"✅ 已打 tag: {tag}")
        else:
            print(f"❌ 打 tag 失败: {r.stderr.strip()}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
