#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布导出（作战计划 2.2 双仓库模型，2026-08-25）——从作战仓库导出公开树。

设计（第九轮作战计划 第二部分）：
  作战仓库（私有，本仓库）→ 发布脚本导出 → 发布仓库（公开）。
  发布树 = git archive 当前 HEAD + 白名单删除 + 自检（凭据 fail-closed）。

═══════════════════════════════════════════════════════════════════════════════
【判定政策（2026-09-19 政策收口，本文件如实对齐现行政策 —— 请勿凭直觉改回严判据）】
═══════════════════════════════════════════════════════════════════════════════
本闸门原先按一套**比现行政策更严的旧策略**编码：明文 flag（DASCTF{...} / vnctf{...} /
flag{...}）一律判为硬失败。该旧策略已于 2026-09-19 显式废止。现在：

  · 明文 flag      → **WARN（仅提示，不计入失败、不影响退出码）**
  · 凭据 / 密钥     → **FAIL（硬红线，fail-closed）**

政策依据 —— 用户两条永久指令 + 一次追加裁决（原文摘要，勿删）：
  · 2026-08-29：「flag 明文公开无实质风险，**全都不管了，全都公开！除了我的 api,token**」
  · 2026-09-01：「**永远，不管答案密钥泄露**」
  · 2026-09-19 追加裁决：**维持现状、不反解 sha256**（不为发布而脱敏/改数据）

**为什么明文 flag 不算泄漏（本项目的产品论据，删掉它等于删掉政策依据）**：
  历史命中清单里的 `scripts/verify_10732.py` / `scripts/verify_specialcurve2.py` /
  `scripts/_antifraud.py` / `scripts/_merge_gate.py` 中的明文 flag，**是机器验证器的期望值**
  —— 正是项目 tagline「machine-verified」的实现基础。若为了发布而把它们脱敏，公开读者就
  无法复现验证，等于**亲手拆掉这个卖点**。所以正确方向是**对齐闸门政策**，而不是脱敏数据。

**为什么 export() 默认不脱敏题库 flag 字段（实测依据 —— 勿改回"默认脱敏"）**：
  实测 `data/questions_real/` 共 **92 题**：**87 题** `flag` 与 `flag_sha256` **逐字同值**、
  **0 题异值**、**5 题只有 `flag` 而无 `flag_sha256`**（例：`real_crypto_anxun2020_coolboy.json`
  的 `flag` 与 `flag_sha256` 均为 `a1a65ec2…d0d2`）。即题库 `flag` 字段**本身就是 sha256 真值
  的载体**。所以脱敏顶层 `flag` 键不是"多此一举"，而是**删掉可验证的真值本身**（那 5 题更是
  直接失去唯一真值）——直接摧毁 tagline「machine-verified」。
  → 结论：`export()` 默认**不**脱敏；仅显式 `--redact-flags` 时才执行（2026-09-19 用户裁决：
  维持现状、不反解 sha256、不为发布改数据）。

因此：明文 flag 只打印提示（保留审计痕迹，便于人工复核命中项确实只是 flag 而非凭据），
绝不阻断退出码。

═══════════════════════════════════════════════════════════════════════════════
【唯一硬红线】API key / token / 私钥 —— 命中即 FAIL，且**只允许追加、绝不允许削弱**
═══════════════════════════════════════════════════════════════════════════════
见下方 `SECRET_PATTERNS`。这条防线独立于 flag 政策：转公开前由 QA 用等价模式集跨
**全部 81 个 commit / 1605 个对象 / 1115 个 blob** 扫描命中 0 —— 这才是本仓库敢转 public
的真正底气，改动该列表必须重跑历史全量扫描。

流程：
  1. git archive HEAD 导出到输出目录（临时目录或 --out 指定）；
  2. 白名单删除：data/results/、docs/internal/、logs/、_archive/ 等内部资产；
  3. 自检（fail-closed on secrets）：扫描 API key 明文（硬失败）+ 明文 flag（提示）；
  4. 可选 --redact-flags：对导出树题库 JSON 的**顶层 flag 键**做防御性脱敏
     （默认**关闭** —— 见 redact_question_flags() 的覆盖范围说明）；
  5. 可选 --tag：通过后打 tag public-YYYYMMDD（推送由外部/CI 决定）。

用法：
  python scripts/release_export.py                 # 导出到临时目录 + 自检
  python scripts/release_export.py --out D:/tmp/release  # 指定输出目录
  python scripts/release_export.py --tag           # 自检通过后打 tag public-YYYYMMDD
  python scripts/release_export.py --scan-only     # 只扫描当前仓库跟踪树，不导出
  python scripts/release_export.py --redact-flags  # 额外脱敏导出树题库顶层 flag 键
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

# 明文 flag 形态（花括号内为实质内容）——政策上**不算泄漏**，仅作 WARN 提示
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

# ─────────────────────────────────────────────────────────────────────────────
# 🔴 硬红线：凭据 / 密钥检测 —— 命中即 FAIL（fail-closed）。
# 规则：
#   1) 只允许**追加**新形态；严禁删除 / 收窄范围（例如把 {20,} 改回 {30,}）来"让闸门变绿"。
#   2) 元组为 (规则名, 正则)：规则名用于失败行打标，便于定位。
#   3) 名单源自 2026-09-19 转公开前 QA 的全历史扫描（12 条模式 / 81 commit / 1605 对象 /
#      1115 blob → 命中 0），此处为其在发布闸内的等价落地并做了形态补全。
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS: list[tuple[str, str]] = [
    # OpenAI 风格 key 与其中转前缀
    ("sk_key", r"sk-[A-Za-z0-9]{16,}"),
    ("sk_tr_key", r"sk_tr_[A-Za-z0-9]{12,}"),
    # GitHub PAT 家族：ghp_(classic) / gho_(oauth) / ghu_(user) / ghs_(server) / ghr_(refresh)
    ("github_pat", r"gh[pousr]_[A-Za-z0-9]{20,}"),
    # HTTP Authorization 头里的长效 token
    ("bearer_token", r"Bearer [A-Za-z0-9._\-]{20,}"),
    # AWS Access Key ID
    ("aws_access_key_id", r"AKIA[0-9A-Z]{16}"),
    # Google API key
    ("google_api_key", r"AIza[0-9A-Za-z_\-]{35}"),
    # Slack token
    ("slack_token", r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    # PEM 私钥块
    ("pem_private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
SECRET_RE = re.compile("|".join(f"(?P<{name}>{pat})" for name, pat in SECRET_PATTERNS))

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
    """题库 JSON 的**顶层** `flag` 键 → '<redacted>'（防御性）。返回脱敏文件数。

    ⚠️ 实际覆盖范围（2026-09-19 如实校正 —— 不要再写成"题库已脱敏"）：
      · 只处理路径中含 "questions" 的 *.json；
      · 只改**顶层** `flag` 键；`description` / `title` / `solution` 及任何嵌套字段
        **一律不动**。实测确有题库把明文写在别处，本函数**覆盖不到**：
          - `data/questions_real/reverse/real_reverse_anxun2020_notright.json` 的
            `description` 内嵌明文 flag；
          - `data/questions_real/web/real_web_longjian2025_which_sql.json` 的
            `description` 内嵌等价变体 flag。
        故"跑过本函数"**不等于**"题库已脱敏"。
      · 与"泄漏防线"无关：真正的硬防线是 SECRET_PATTERNS（凭据/密钥）。

    政策说明（为什么 export() 默认**不**调用本函数 —— 附实测依据，勿凭直觉改回默认脱敏）：
      · 本函数**只改顶层 `flag` 键**，**从不动 `flag_sha256`**（若连 `flag_sha256` 一起抹掉，
        才是真的丢失真值）；
      · 但实测 `data/questions_real/` **92 题**中 **87 题** `flag` 与 `flag_sha256` 逐字同值、
        **0 题异值**、**5 题只有 `flag` 无 `flag_sha256`** —— 即 `flag` 字段本身就是 sha256
        真值载体。脱敏它 = 删掉可验证的真值本身（那 5 题直接失去唯一真值），
        与 tagline「machine-verified」直接冲突，不是"多此一举"；
      · 现行政策下明文 flag 也不再算泄漏（见模块头「判定政策」）。
    故 export() 默认**不调用**本函数，仅在显式 --redact-flags 时调用。
    """
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

    FAIL **只**包含凭据/密钥（硬红线，见 SECRET_PATTERNS）；明文 flag 一律进 WARN
    —— 政策上 flag 明文公开无实质风险（依据见模块头「判定政策」），保留打印只为审计。

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
        # ── 硬红线：API key / token / 私钥 —— 硬失败 ──
        for m in SECRET_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            kind = m.lastgroup or "secret"
            fails.append(f"{rel}:{line}: 凭据/密钥疑似 [{kind}] {m.group(0)[:16]}…")
        # ── 明文 flag —— 政策允许，仅提示（分类打标便于审计） ──
        for m in REAL_FLAG_RE.finditer(text):
            token = m.group(0)
            line = text[: m.start()].count("\n") + 1
            # 分类：引号包裹的判断字符串 / 格式描述 / 假 flag 占位 / 真实明文 flag
            before = text[max(0, m.start() - 3): m.start()]
            if '"' in before or "'" in before:
                kind = "判断字符串"
            elif FORMAT_DESC_RE.fullmatch(token):
                kind = "格式描述"
            elif FAKE_FLAG_RE.search(token):
                kind = "假 flag/占位/反例"
            else:
                kind = "明文 flag（政策允许，非泄漏）"
            warns.append(f"{rel}:{line}: {kind} {token[:40]}…")
    return fails, warns


def export(out_dir: Path, redact_flags: bool = False) -> int:
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
    # 题库 flag 脱敏：默认关闭（政策上明文 flag 非泄漏，且脱敏会毁掉 machine-verified 真值）
    if redact_flags:
        n = redact_question_flags(out_dir)
        print(f"  题库顶层 flag 键脱敏（--redact-flags）: {n} 个 JSON "
              f"（仅顶层 flag 键；description 等字段不在覆盖范围）")
    return verify(out_dir)


def verify(tree: Path) -> int:
    print(f"── 发布自检（fail-closed on secrets: {tree}）──")
    fails, warns = scan_tree(tree)
    for w in warns:
        print(f"  ⚠️  {w}")
    if fails:
        print(f"❌ 自检失败：发现 {len(fails)} 处凭据/密钥泄漏（硬红线）：")
        for f in fails[:30]:
            print(f"    - {f}")
        print("   处置：剔除对应文件 / 改为环境变量注入后重试（发布树不允许任何真实密钥；"
              "明文 flag 不在此列，按政策仅提示）")
        return 1
    print(f"✅ 自检通过：零 API key / 零凭据（{len(warns)} 处明文 flag / 判断字符串 / 格式描述"
          f"按政策仅提示，不阻断）")
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
    print(f"  WARN（明文 flag / 判断字符串 / 格式描述 —— 政策上非泄漏，仅审计）{len(warns)} 处：")
    for w in warns:
        print(f"  ⚠️  {w}")
    if fails:
        print(f"❌ 发现 {len(fails)} 处凭据/密钥泄漏（硬红线）：")
        for f in fails[:30]:
            print(f"    - {f}")
        return 1
    print(f"✅ 跟踪树零凭据泄漏（{len(warns)} 处明文 flag / 豁免按政策仅提示）")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    """构造命令行参数解析器（独立成函数，便于测试断言政策默认值）。"""
    ap = argparse.ArgumentParser(description="发布导出（作战计划 2.2 双仓库模型）")
    ap.add_argument("--out", type=str, default=None, help="输出目录（默认临时目录）")
    ap.add_argument("--tag", action="store_true", help="自检通过后打 tag public-YYYYMMDD")
    ap.add_argument("--scan-only", action="store_true", help="只扫描当前跟踪树，不导出")
    ap.add_argument(
        "--redact-flags", dest="redact_flags", action="store_true", default=False,
        help="导出时额外脱敏题库 JSON 顶层 flag 键（默认关闭：政策上明文 flag 非泄漏，"
             "且脱敏会移除 machine-verified 的 sha256 真值）",
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.scan_only:
        return scan_current()

    if args.out:
        out_dir = Path(args.out)
        code = export(out_dir, redact_flags=args.redact_flags)
    else:
        tmp = Path(tempfile.mkdtemp(prefix="release_export_"))
        code = export(tmp, redact_flags=args.redact_flags)
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
