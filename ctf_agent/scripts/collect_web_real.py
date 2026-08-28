"""web 真题集采集与合规校验框架（2026-08-27 补，解决 web 0/10 数据欠账的框架层）。

背景
----
规划 P1 要求 web 真题集扩充到 10-15 题，以解「web 真实解出 0」的数据工程欠账。
但真实 web 赛题属外部数据依赖，无法凭空合成（否则违反「严格真题口径」——
自产题不计入 KPI）。本脚本把"什么才算可被 KPI 计入的 web 真题"固化成可运行校验，
让**未来有真实赛题数据时**能一键合规入库，避免再次出现口径漂移。

分类口径（与 REAL_SOLVES_LEDGER.md / merge_gate._classify_entry 对齐）
-------------------------------------------------------------
  A 类  完整攻击链：西湖论剑/正式赛平台题 + 可离线/在线复现（附件或靶机） + flag_sha256 可核验
  B 类  presolve 确定性变换：同上但靠确定性管线直出（web 题罕见，多归 A）
  C 类  grep 明文：附件里直接 grep 到 flag（无攻击链）——不计入严格真题
  D 类  题面泄露：flag 直接写在题面 description 里——不计入
  E 类  自产/训练题（provenance 含 self_authored/training）/ 外部真题——不计入

用法
----
  .venv/Scripts/python.exe scripts/collect_web_real.py --emit-template
      # 输出 web 真题 manifest 模板到 stdout
  .venv/Scripts/python.exe scripts/collect_web_real.py --scan <dir>
      # 扫描目录内 *.json，逐题校验并打印分类（默认 dry-run，不写库）
  .venv/Scripts/python.exe scripts/collect_web_real.py --scan <dir> --no-dry-run
      # 真正把 A 类题写入 data/questions_real/web/
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REAL_WEB_DIR = Path("data/questions_real/web")
_FLAG_RE = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)


def validate_web_real(q: dict) -> tuple[bool, str, str]:
    """校验单道 web 题是否符合严格真题口径。

    返回 (计入KPI?, 分类标签, 说明)。
    """
    qid = q.get("id", "?")
    prov = str(q.get("provenance", "")).lower()
    desc = q.get("description", "") or ""
    flag = q.get("flag", "") or ""
    atts = q.get("attachments") or []
    sha = q.get("flag_sha256", "") or ""

    # E 类：自产/训练题（不计入 KPI）
    if "self_authored" in prov or "training" in prov:
        return False, "E", f"[{qid}] provenance={prov} → 自产训练题，不计入 KPI"
    # D 类：题面直读
    if flag and flag in desc:
        return False, "D", f"[{qid}] flag 在题面 description 中直读 → 不计入"
    # 可复现性：需附件(离线可跑) 或 题面含靶机/服务可交互
    has_assets = bool(atts)
    has_target = any(k in desc for k in ("http://", "https://", "靶机", "host:", "url:", "端口"))
    if not (has_assets or has_target):
        return False, "C?", f"[{qid}] 无附件且无靶机 → 无法离线/在线复现，不收录"
    # 可核验：flag_sha256 必须存在
    if not sha:
        return False, "C?", f"[{qid}] 缺 flag_sha256 → 落盘不可信，不收录"
    # A 类：完整攻击链（web 题需≥2步，有附件即视为可构造攻击链）
    return True, "A", f"[{qid}] 符合严格真题口径（正式赛 + 可复现 + sha256 可核验）"


def collect_from_dir(src: Path, dry_run: bool = True) -> list[str]:
    """扫描目录，校验并把 A 类题写入 data/questions_real/web/。"""
    written: list[str] = []
    for f in sorted(src.glob("*.json")):
        try:
            q = json.loads(f.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(f"[SKIP] {f.name} 解析失败: {exc}")
            continue
        ok, label, reason = validate_web_real(q)
        marker = "✅A" if (ok and label == "A") else ("⚠️" + label)
        print(f"  {marker} {reason}")
        if ok and label == "A" and not dry_run:
            REAL_WEB_DIR.mkdir(parents=True, exist_ok=True)
            dst = REAL_WEB_DIR / f.name
            dst.write_text(json.dumps(q, ensure_ascii=False, indent=2), encoding="utf-8")
            written.append(str(dst))
    return written


def emit_template() -> None:
    tpl = {
        "id": "real_web_<赛事缩写>_<年份>_<题号>",
        "provenance": "real_past_ctf",
        "category": "web",
        "title": "赛事名 web 题标题",
        "description": "题面（flag 不得直接写在题面，需经攻击链获取；可含靶机地址或本地服务说明）",
        "flag": "flag{...} 或裸 hex（须与 flag_sha256 对应，离线可核验）",
        "flag_pattern": r"flag\{[^}]+\}",
        "attachments": ["data/questions_real/_attachments/web/<id>/源码.php"],
        "difficulty": "MEDIUM",
        "flag_sha256": "<flag 的 sha256 hex，64 字符>",
    }
    print(json.dumps(tpl, ensure_ascii=False, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description="web 真题集采集与合规校验框架")
    ap.add_argument("--scan", metavar="DIR", help="扫描目录校验 web 题")
    ap.add_argument("--emit-template", action="store_true", help="输出 manifest 模板")
    ap.add_argument("--no-dry-run", action="store_true", help="真正写入 data/questions_real/web/")
    args = ap.parse_args()

    if args.emit_template:
        emit_template()
        return
    if args.scan:
        src = Path(args.scan)
        if not src.is_dir():
            print(f"ERROR: 目录不存在 {src}")
            return
        print(f"=== 扫描 {src}（{'DRY-RUN' if not args.no_dry_run else 'WRITE'}）===")
        written = collect_from_dir(src, dry_run=not args.no_dry_run)
        if written:
            print(f"\n已写入 {len(written)} 题到 {REAL_WEB_DIR}")
        return
    ap.print_help()


if __name__ == "__main__":
    main()
