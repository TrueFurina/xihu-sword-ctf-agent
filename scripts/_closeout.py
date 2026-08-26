# -*- coding: utf-8 -*-
"""收尾脚本（G3，2026-08-23）：强制在飞改动清零 + 扫描临时文件垃圾。

用途：会话停止前（用户喊停 / 自然结束）跑一次，确保工作树 clean 或改动已提交，
消除纲领 §4「在飞改动禁令」的"改了不提交就消失"炸弹。

命令：
  python scripts/_closeout.py --check       # 有在飞改动 → exit 1（报告 M/D 文件与未跟踪脚本）
  python scripts/_closeout.py --scan-junk   # 扫根目录 _probe*.bin 等临时文件垃圾（只报告，不删除）
"""
import argparse
import glob
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git_status_porcelain():
    out = subprocess.run(["git", "status", "--porcelain", "-z"],
                         cwd=ROOT, capture_output=True)
    return out.stdout.decode("utf-8", errors="ignore")


def check_inflight() -> list:
    """返回在飞改动清单：[(状态, 路径), ...]。空 = 工作树干净。"""
    entries = [e for e in _git_status_porcelain().split("\0") if e.strip()]
    result = []
    for e in entries:
        # git status --porcelain -z 前两个字符是 XY 状态，第三个字符起是路径
        status = e[:2].strip()
        path = e[3:].strip()
        if status:
            result.append((status, path))
    return result


def _inflight_with_scope_alert(inflight: list) -> list:
    """为在飞改动标注 scope 越界告警（闸3，2026-08-24 并发有序化）。

    读 coordination.json 存活租约 scope，在飞文件不在任何存活租约内 → 标 ⚠️ 裸改
    （未登记、无租约保护，正是"并发裸奔"互踩风险的实证）。
    """
    alerts = []
    try:
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import _lease  # noqa: PLC0415
        doc = _lease.load()
        scopes_all = []
        for lease in (doc or {}).get("leases", {}).values():
            scopes_all.extend(lease.get("scope", []))
    except Exception as _e:
        scopes_all = []  # 读不到租约 → 不误报，只提示
    for status, path in inflight:
        if not scopes_all or any(_lease.path_in_scope(path, [s]) for s in scopes_all):
            continue
        alerts.append((status, path))
    return alerts


def scan_junk() -> list:
    """扫根目录的临时探测/垃圾文件（未跟踪的一次性脚本与二进制产物）。"""
    patterns = [
        os.path.join(ROOT, "_probe*.py"),
        os.path.join(ROOT, "_try_*.py"),
        os.path.join(ROOT, "_probe*.bin"),
        os.path.join(ROOT, "_png*.bin"),
        os.path.join(ROOT, "_fix_round*.py"),
        os.path.join(ROOT, "_fix_presolve*.py"),
        os.path.join(ROOT, "*.log"),
    ]
    junk = []
    for pat in patterns:
        for p in glob.glob(pat):
            if os.path.isfile(p):
                junk.append(os.path.relpath(p, ROOT))
    return sorted(set(junk))


def main() -> int:
    ap = argparse.ArgumentParser(description="收尾检查（在飞改动 + 临时文件垃圾）")
    ap.add_argument("--check", action="store_true", help="检查在飞改动（有则 exit 1）")
    ap.add_argument("--scan-junk", action="store_true", help="扫临时文件垃圾（只报告）")
    a = ap.parse_args()

    if a.check:
        inflight = check_inflight()
        if not inflight:
            print("✅ 工作树干净，无在飞改动")
            return 0
        print(f"❌ 发现 {len(inflight)} 处在飞改动（要么持租约提交，要么 checkout 回退）：")
        for status, path in inflight[:30]:
            print(f"   {status}  {path}")
        print("   处置：连贯→持租约提交；残缺→git checkout -- <file> 回退")
        return 1

    if a.scan_junk:
        junk = scan_junk()
        if not junk:
            print("✅ 未发现临时探测/垃圾文件")
            return 0
        print(f"⚠️ 发现 {len(junk)} 个临时探测/垃圾文件（建议归档或清理）：")
        for p in junk:
            print(f"   {p}")
        return 0

    # 无参数：都做
    rc_check = main_check_only()
    rc_junk = main_junk_only()
    return rc_check


def main_check_only():
    inflight = check_inflight()
    if not inflight:
        print("✅ 工作树干净，无在飞改动")
        return 0
    print(f"❌ 发现 {len(inflight)} 处在飞改动：")
    for status, path in inflight[:30]:
        print(f"   {status}  {path}")
    # 闸3：scope 越界告警（并发裸奔实证——未登记改动无租约保护）
    alerts = _inflight_with_scope_alert(inflight)
    if alerts:
        print(f"⚠️ 其中 {len(alerts)} 处不在任何存活租约 scope 内（裸改——2026-08-24 闸3）：")
        for status, path in alerts[:15]:
            print(f"   ⚠️ {status}  {path}")
        print("   处置：确认归属会话 → acquire 对应 scope 后提交，或协调者裁决还原")
    return 1


def main_junk_only():
    junk = scan_junk()
    if junk:
        print(f"⚠️ 临时垃圾文件 {len(junk)} 个（建议清理）：")
        for p in junk:
            print(f"   {p}")
    else:
        print("✅ 无临时垃圾文件")
    return 0


if __name__ == "__main__":
    sys.exit(main())
