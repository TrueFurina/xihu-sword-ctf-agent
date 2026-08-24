#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合并闸门（阶段3 单一红绿灯，2026-08-24；P0-1 接真值 2026-08-24）——main 只通过本闸门更新。

设计（咨询诊断落地：物理系统 > 宣言系统）：
  main 分支只允许通过"合并"进入，且每次合并必须过本闸门：
    ① KPI 不降断言（双通道）：
       a. 台账计数：REAL_SOLVES_LEDGER.md 的 offline_verified 计数 >= 基线
          （防"台账被删行"；基线文件 data/results/KPI_BASELINE.json）
       b. 真值回归：已解出题回归集【真跑可复现命令】（防"台账造假/功劳错配"）——
          确定性 verifier（skill 直出 / verify 脚本），不依赖 LLM provider（熔断不阻塞合并）
    ② 全量测试：pytest tests/ -m "not slow"（merge 频率低，30s 可接受）
  任一项失败 exit 1 → 中止合并（fail-closed）。裁判与实现分离：
  会话在分支上说"我验证过了"不算数，闸门重跑才算数。

调用方：
  - git_hooks/pre-merge-commit（git 2.24+，真正 merge commit 时触发）
  - git_hooks/pre-commit 第⑧道（MERGE_HEAD 检测，兼容 squash-merge）

用法：
  python scripts/_merge_gate.py            # 全量：KPI 双通道 + 全量测试
  python scripts/_merge_gate.py --kpi-only # 只做 KPI 双通道（快速，供 pre-commit ⑧ 复用）
  python scripts/_merge_gate.py --full-baseline  # 全量 15 道真题真值跑，落盘基线（每日定时，不阻塞合并）
"""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(ROOT, "REAL_SOLVES_LEDGER.md")
BASELINE = os.path.join(ROOT, "data", "results", "KPI_BASELINE.json")


def sh(cmd, cwd=ROOT, timeout=600):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout,
                          text=True, encoding="utf-8", errors="replace")


# ── P0-1：已解出题回归集（真值通道，2026-08-24）──
# 每项 = {id, cmd(可复现命令), flag_contains(台账 flag 前缀，脱敏只取前 16 字符)}
# 判定：命令 exit 0 且 stdout 含 flag_contains → 该题仍解出（KPI 未降的真值证据）。
# 台账声明来源：REAL_SOLVES_LEDGER.md 第二节。
# ⚠️ 2026-08-24 实测修正：台账声称的"可复现命令"并非全部可复现——
#   specialcurve2 的 skill 是无 __main__ 的库模块（python -m 只加载不执行），
#   10732 无可复现脚本（台账已声明待固化）。回归集只收真正可复现的题，
#   其余如实列入 KNOWN_GAP——这就是"接真值"要暴露的台账与现实的差距。
REGRESSION_CHECKS = [
    {
        "id": "10733",
        "cmd": [sys.executable, "scripts/verify_10733.py"],
        "flag_contains": "DASCTF{rabbits6sc5mpl",
    },
]

KNOWN_GAP = [
    {"id": "10732",
     "reason": "可复现脚本待固化（台账 2026-08-24 声明）"},
    {"id": "real_crypto_specialcurve2",
     "reason": "台账可复现命令不可用：skill 为无 __main__ 的库模块，python -m 无输出（2026-08-24 实测）"},
]


def dirty_check() -> bool:
    """收尾门禁（2026-08-24 调控落地）：合并回 main 前工作树必须干净。

    在飞改动（未收尾的 M/D/??）= 禁止合并——防"改了不提交就消失"的
    炸弹经车道合并进 main（纲领 §4）。处置：先 _closeout.py --check 收尾。
    """
    r = sh(["git", "status", "--porcelain"])
    dirty = [ln for ln in r.stdout.strip().splitlines() if ln.strip()]
    if dirty:
        print(f"❌ 收尾门禁：工作树有 {len(dirty)} 处在飞改动，先收尾再合并：")
        for ln in dirty[:8]:
            print(f"   {ln}")
        return False
    print("✅ 收尾门禁：工作树干净")
    return True


def count_offline_verified() -> int:
    """统计台账中 offline_verified 标记数（KPI 计数通道 a）。"""
    if not os.path.isfile(LEDGER):
        print(f"❌ 台账缺失：{LEDGER}")
        return -1
    try:
        with open(LEDGER, encoding="utf-8") as f:
            return sum("offline_verified" in line for line in f)
    except OSError as exc:
        print(f"❌ 台账读取失败：{exc}")
        return -1


def regression_check() -> bool:
    """真值回归（KPI 计数通道 b）：已解出题回归集真跑可复现命令。"""
    print(f"── KPI 真值回归（{len(REGRESSION_CHECKS)} 道已解出题）──")
    ok = True
    for item in REGRESSION_CHECKS:
        try:
            r = sh(item["cmd"])
        except subprocess.TimeoutExpired:
            print(f"❌ 回归超时（>600s）：{item['id']}——skill/verify 链路异常")
            ok = False
            continue
        hit = item["flag_contains"] in (r.stdout or "")
        if r.returncode == 0 and hit:
            print(f"✅ 仍解出：{item['id']}（{item['flag_contains']}…）")
        else:
            print(f"❌ 回归失败：{item['id']} exit={r.returncode} "
                  f"flag命中={hit}——台账称已解出但无法复现")
            ok = False
    if KNOWN_GAP:
        print(f"ℹ️ 已知缺口（可复现脚本未固化，暂不入回归集）："
              f"{', '.join(g['id'] for g in KNOWN_GAP)}")
    if not ok:
        print("   处置：先修复回归失败的 skill/verify 脚本，或如实降级台账状态")
    return ok


def load_baseline() -> dict:
    if os.path.isfile(BASELINE):
        try:
            with open(BASELINE, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def save_baseline(verified: int, test_stats: dict | None = None) -> None:
    """落盘 KPI 基线（2026-08-24 锐评⑦：单一数字太薄，加维度便于发现隐性退化）。

    维度：
      offline_verified   台账 offline_verified 计数（唯一 KPI，不降断言用）
      regression_count   真题回归集题数（真值通道覆盖范围）
      test_passed/test_total  全量测试通过/总数（测试基线漂移检测：278→271 类下降必须解释）
      chain_worst_step   链路失败步最高步（goal_log 统计，判断瓶颈迁移）
    """
    os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
    bl = {"offline_verified": verified,
          "regression_count": len(REGRESSION_CHECKS),
          "as_of": "2026-08-24"}
    if test_stats:
        bl.update({k: v for k, v in test_stats.items()
                   if k in ("test_passed", "test_total", "test_skipped")})
    # 尝试读链路失败步统计（P1 Step3 产物），有则记入基线
    try:
        _cs = sorted(__import__("pathlib").Path(ROOT, "data", "results")
                     .glob("chain_stats_*.json"))
        if _cs:
            _d = json.loads(_cs[-1].read_text(encoding="utf-8"))
            _steps = _d.get("steps", {})
            _worst = max(_steps, key=lambda k: _steps[k].get("count", 0)) if _steps else ""
            if _worst:
                bl["chain_worst_step"] = f"{_worst}({_steps[_worst].get('pct', 0)}%)"
    except Exception:  # noqa: BLE001 - 基线加维度失败不阻塞
        pass
    with open(BASELINE, "w", encoding="utf-8") as f:
        json.dump(bl, f, ensure_ascii=False, indent=2)


def kpi_check() -> bool:
    """KPI 不降断言（双通道）：台账计数 >= 基线 且 回归集真跑全过。"""
    n = count_offline_verified()
    if n < 0:
        return False
    bl = load_baseline()
    if "offline_verified" not in bl:
        # 首次运行：以当前计数建立基线（幂等，不误伤历史合并）
        save_baseline(n)
        print(f"ℹ️ KPI 基线不存在，已建立：offline_verified={n}（{BASELINE}）")
    else:
        base = bl["offline_verified"]
        if n < base:
            print(f"❌ KPI 计数断言失败：offline_verified {n} < 基线 {base}")
            print("   合并会降低已确认解出数——先核查台账是否误删 offline_verified 记录")
            return False
        print(f"✅ KPI 计数断言通过：offline_verified {n} >= 基线 {base}")
    # 真值回归：台账计数只是文本，回归集才是"能复现"的证据
    if not regression_check():
        return False
    return True


def full_tests() -> bool:
    """全量测试门禁：pytest tests/ -m "not slow"。通过后把测试数写入 KPI 基线
    （测试基线漂移检测：278→271 类下降在看板暴露并须解释，2026-08-24 锐评⑦）。"""
    print("── 全量测试（merge 级门禁，~30s）──")
    py = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
    if not os.path.exists(py):
        py = sys.executable
    r = sh([py, "-m", "pytest", "tests/", "-q", "-m", "not slow"])
    tail = r.stdout[-1200:] if r.stdout else ""
    print(tail[-800:])
    if r.returncode != 0:
        print("❌ 全量测试失败：merge 禁止带红进 main")
        return False
    # 解析 "N passed, M skipped" 落基线（供看板漂移检测）
    m = re.search(r"(\d+) passed", tail)
    m2 = re.search(r"(\d+) skipped", tail)
    if m:
        _n = count_offline_verified()
        if _n >= 0:
            save_baseline(_n, test_stats={
                "test_passed": int(m.group(1)),
                "test_total": int(m.group(1)) + int(m2.group(1)) if m2 else int(m.group(1)),
                "test_skipped": int(m2.group(1)) if m2 else 0,
            })
            print(f"ℹ️ 测试基线已刷新：{m.group(1)} passed（{BASELINE}）")
    print("✅ 全量测试通过")
    return True


def full_baseline() -> bool:
    """全量 15 道真题真值跑，结果落盘为基线（每日定时跑，不阻塞合并）。"""
    print("── 全量真题真值基线（15 道 questions_real，真实链路）──")
    py = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
    if not os.path.exists(py):
        py = sys.executable
    r = sh([py, "-m", "eval.benchmark",
            "--questions-dir", "data/questions_real",
            "--provider", "baidu,qwen", "--wallclock", "300"])
    print((r.stdout or "")[-1500:])
    if r.returncode != 0:
        print("❌ 全量基准跑失败：请检查 provider/网络后重试（不阻塞合并，仅影响基线新鲜度）")
        return False
    # 解析报告落盘：benchmark 输出已含 solved 统计；同时更新台账计数基线
    n = count_offline_verified()
    if n >= 0:
        save_baseline(n)
    print(f"✅ 全量基准跑完成：台账 offline_verified={n}，基线已刷新")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="合并闸门（KPI 不降 + 全量测试）")
    ap.add_argument("--kpi-only", action="store_true", help="只做 KPI 断言（快速）")
    ap.add_argument("--full-baseline", action="store_true",
                    help="全量真题真值跑并落盘基线（每日定时，不阻塞合并）")
    args = ap.parse_args()

    if args.full_baseline:
        return 0 if full_baseline() else 1

    # 收尾门禁（2026-08-24 调控落地）：合并回 main 前工作树必须干净——
    # 在飞改动（未收尾的 M/D/??）禁止经车道合并进 main（纲领 §4 炸弹）。
    if not dirty_check():
        return 1
    ok = kpi_check()
    if not ok:
        return 1
    if not args.kpi_only and not full_tests():
        return 1
    print("✅ 合并闸门通过：可以进 main")
    return 0


if __name__ == "__main__":
    sys.exit(main())
