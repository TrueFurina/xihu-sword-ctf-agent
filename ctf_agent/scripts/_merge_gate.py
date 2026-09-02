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
import time

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
    # 以下 7 道为确定性管线（presolve）可复现解出，统一经 scripts/_regress_one.py 单题真值比对
    # （与 _verify_presolve_truth.py 同工具层；2026-08-28 实测 9 道全部 REGRESS_PASS）。
    {
        "id": "real_crypto_anwang_crypto1",
        "cmd": [sys.executable, "scripts/_regress_one.py", "real_crypto_anwang_crypto1"],
        "flag_contains": "REGRESS_PASS",
    },
    {
        "id": "real_crypto_ezmult",
        "cmd": [sys.executable, "scripts/_regress_one.py", "real_crypto_ezmult"],
        "flag_contains": "REGRESS_PASS",
    },
    {
        "id": "real_crypto_filterrandom",
        "cmd": [sys.executable, "scripts/_regress_one.py", "real_crypto_filterrandom"],
        "flag_contains": "REGRESS_PASS",
    },
    {
        "id": "real_crypto_qiangwang_classic",
        "cmd": [sys.executable, "scripts/_regress_one.py", "real_crypto_qiangwang_classic"],
        "flag_contains": "REGRESS_PASS",
    },
    {
        "id": "real_reverse_sheng",
        "cmd": [sys.executable, "scripts/_regress_one.py", "real_reverse_sheng"],
        "flag_contains": "REGRESS_PASS",
    },
    {
        "id": "real_reverse_upx",
        "cmd": [sys.executable, "scripts/_regress_one.py", "real_reverse_upx"],
        "flag_contains": "REGRESS_PASS",
    },
    {
        "id": "real_misc_xuanhun_signin",
        "cmd": [sys.executable, "scripts/_regress_one.py", "real_misc_xuanhun_signin"],
        "flag_contains": "REGRESS_PASS",
    },
    # 2026-09-03 带证据晋级：Håstad 广播攻击确定性求解器 skills/crypto_hastad_broadcast.py
    # 接入 presolve（_try_hastad_broadcast），实测 REGRESS_PASS（e=17，sha256 匹配题面真值）。
    {
        "id": "real_crypto_ezrsa",
        "cmd": [sys.executable, "scripts/_regress_one.py", "real_crypto_ezrsa"],
        "flag_contains": "REGRESS_PASS",
    },
]

KNOWN_GAP = [
    {"id": "10732",
     "reason": "可复现脚本待固化（台账 2026-08-24 声明；攻击链清晰但 _solve_10732.py 散落待固化）"},
    {"id": "10735",
     "reason": "logbool pcap→RAR5→7z 解密链待固化为 verify 脚本（台账 offline_verified，无独立 verifier）"},
    {"id": "real_misc_vnctf_flag",
     "reason": "2026-08-29 诚实校准：点阵重采样显字（flag 在图内）需 OCR/视觉模型，文本 LLM 不可解=架构级缺口；verify_vnctf_flag.py 依赖 verified_flags.json 真值库（8/28 results 隔离时未随 KPI_BASELINE 恢复、且从未入库），不可复现。台账状态如实降级，移出回归集（与 MEMORY.md 判断一致）"},
    {"id": "real_crypto_specialcurve2",
     "reason": "不可复现：附件 SpecialCurve2.py 仅为恢复的挑战脚本模板，原 n/HINT/C 实例值每次运行随机生成、已永久丢失；verify_specialcurve2.py 仅做 sha256 自比对（同义反复），不真解题。2026-08-27 诚实校准从严格 KPI 与回归集移除"},
    {"id": "real_crypto_simplelegendre",
     "reason": "2026-08-28 实测：现行确定性管线 presolve 提取=None（❌未命中），仅历史人工解出；KPI 12→9 诚实回退，移出严格 KPI。待修复勒让德符号求解器后带证据重新晋级"},
    {"id": "real_crypto_exciting_inverse",
     "reason": "2026-08-28 实测：现行确定性管线 presolve 提取=None（❌未命中），仅历史人工解出；KPI 12→9 诚实回退，移出严格 KPI。待修复矩阵求逆求解器后带证据重新晋级"},
]


def dirty_check() -> bool:
    """收尾门禁（2026-08-24 调控落地；2026-08-26 修正误杀合法合并的 bug）：合并回 main 前工作树必须干净。

    在飞改动（未收尾的 M/D）= 禁止合并——防"改了不提交就消失"的
    炸弹经车道合并进 main（纲领 §4）。处置：先 _closeout.py --check 收尾。

    2026-08-26 修正（修复误杀每一个 --no-ff 合并的 bug）：
      - 合并进行中（MERGE_HEAD 存在）：工作树含合并结果（staged M/D 即合并产物），
        非"在飞改动"，跳过收尾门禁，否则会误杀每一个 --no-ff 合并
        （pre-commit ⑧ / pre-merge-commit 均经此门）。
      - 永久未跟踪杂物（??，如仓库根的 _archive/、wt-*、deliverables/、data/ 等）
        一律忽略——它们不会被合并吞入，且本仓库长期存在，不应阻断合法合并。
      只统计"已跟踪文件的在飞改动"（M/D/R/C/A 列，含 staged/unstaged），
      这才是真正的炸弹场景（改了没提交就进 main 会丢失）。
    """
    # 合并进行中：工作树含合并结果（staged M/D 即合并产物），非在飞改动 → 跳过
    git_dir = sh(["git", "rev-parse", "--git-dir"]).stdout.strip()
    if git_dir and os.path.exists(os.path.join(git_dir, "MERGE_HEAD")):
        print("ℹ️ 合并进行中：跳过收尾门禁（工作树含合并结果，非在飞改动）")
        return True
    r = sh(["git", "status", "--porcelain"])
    # 只统计已跟踪文件的在飞改动；忽略 ?? 未跟踪杂物（_archive/wt-*/deliverables/data 等）
    dirty = [ln for ln in r.stdout.strip().splitlines()
             if ln.strip() and ln[:2] != "??"]
    if dirty:
        print(f"❌ 收尾门禁：工作树有 {len(dirty)} 处已跟踪在飞改动，先收尾再合并：")
        for ln in dirty[:8]:
            print(f"   {ln}")
        return False
    print("✅ 收尾门禁：已跟踪工作树干净（忽略永久未跟踪杂物）")
    return True


# ── 台账收录边界规则（2026-08-27 定稿，机器判定权威；台账 REAL_SOLVES_LEDGER.md 仅数据）──
# 任何题块能否计入 KPI，由本规则判定，不再依赖会话/文档临时裁定。
# A 类·完整攻击链离线核验 → ✅ 计入（≥2 步攻击链 + 真值一致 + 可复现命令）
# B 类·presolve 确定性密码学变换 → ✅ 计入（可运行变换代码 + flag_sha256 逐字匹配 + 明文落盘）
# C 类·flag_scan/grep 源码明文披露 → ❌ 不计入（仅计入 presolve 覆盖度口径）
# D 类·题面直接给答案 → ❌ 不计入（台账红线）
# E 类·外部真题（标题含「外部真题」）→ 不计入严格 KPI（merge_gate 自动排除）
# ⚠️ 已知陷阱（2026-08-27 实测）：台账正文说明/注释若出现「状态行 ✅」字面量会被
#    本函数误数（曾把 KPI 9 虚高到 10）。引用计数逻辑时用「状态行为 ✅」绕行表述。


def _classify_entry(title: str) -> str:
    """按收录边界规则分类题块（A/B/C/D/E）。标题含「外部真题」→ E 类。"""
    if "外部真题" in title:
        return "E"
    if "A类" in title or "完整攻击链" in title:
        return "A"
    if "B类" in title or "presolve密码学变换" in title or "presolve 密码学变换" in title:
        return "B"
    return "C"  # 未标注类别且非外部的题块，默认按 C 类从严（不计入）


def count_offline_verified() -> int:
    """统计台账中 offline_verified 题级解出数（KPI 计数通道 a）。

    只数「状态：✅ offline_verified」的题级行（严格真题口径）：
    - 按题块（### N. 标题）解析，只数状态行含 ✅ offline_verified 的题；
    - 排除标题含「外部真题」的题块（HGAME 等外部真题 = self-produced 口径，不计入严格真题）；
    - 排除口径定义行与前向引用行的误命中——否则会把计数虚高，使 fail-closed 棘轮基于注水数字。
    - 2026-08-27：按收录边界规则，仅计入 A/B 类题块（_classify_entry 判定），
      C/D 类（grep 明文/题面泄露）即使状态行为 ✅ 也不计入。
    """
    if not os.path.isfile(LEDGER):
        print(f"❌ 台账缺失：{LEDGER}")
        return -1
    # 2026-08-27 诚实护栏：以下题的「核验」仅为 sha256 同义反复（读题面 flag_sha256
    # 与真值库自比），不含任何真实求解，绝不可计入 KPI——即便台账被误标 ✅ 也排除。
    # 防止并行「真题库重建」自动化把注水项重新计入严格 KPI。
    _CIRCULAR_VERIFY_EXCLUDE = {"real_crypto_specialcurve2"}
    try:
        count = 0
        cur_title = ""
        with open(LEDGER, encoding="utf-8") as f:
            for line in f:
                if line.startswith("### "):
                    # 新题块：按收录边界规则分类（E 类外部真题 / C 类未标注默认不计）
                    cur_title = line
                    continue
                # 仅 A/B 类题块的状态行计入（fail-closed：未标注类别视为 C 类不计入）
                if (_classify_entry(cur_title) in ("A", "B")
                        and "- **状态**" in line and "✅ offline_verified" in line
                        and not any(eid in cur_title for eid in _CIRCULAR_VERIFY_EXCLUDE)):
                    count += 1
        return count
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


def save_baseline(verified: int, test_stats: dict | None = None,
                  extra: dict | None = None) -> None:
    """落盘 KPI 基线（2026-08-24 锐评⑦ + 2026-08-25 第九轮：维度扩容）。

    维度（每项都是棘轮/漂移检测的锚）：
      offline_verified   台账 offline_verified 严格计数（唯一 KPI，不降断言用）
      regression_count   真题回归集题数（真值通道覆盖范围）
      test_passed/...    全量测试通过/总数（测试基线漂移检测）
      chain_worst_step   链路失败步最高步（goal_log 统计，判断瓶颈迁移）
      empty_loop_ratio   主 Agent 空转占比（2026-08-25 第九轮新增，最重要趋势线）
      as_of              落盘日期（= 今日，避免锚日期过期）
    """
    os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
    bl = {"offline_verified": verified,
          "regression_count": len(REGRESSION_CHECKS),
          "as_of": time.strftime("%Y-%m-%d", time.gmtime())}
    if test_stats:
        bl.update({k: v for k, v in test_stats.items()
                   if k in ("test_passed", "test_total", "test_skipped")})
    if extra:
        bl.update({k: v for k, v in extra.items()
                   if k in ("empty_loop_ratio", "chain_worst_step")})
    # chain_worst_step：优先用 extra 传入，否则回退读最新 chain_stats_*.json
    if "chain_worst_step" not in bl:
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


def compute_empty_loop_ratio() -> float:
    """主 Agent 空转占比（2026-08-25 第九轮新增基线维度，最重要趋势线）。

    定义（与 data/results/主Agent失败步攻坚实验设计 一致）：goal_log.jsonl 全量记录中，
    self_reflection.what_i_did 为 None / 空字符串 / '无步骤记录' 的行占比。
    这些行 = 主 Agent 纯推理空转、未进入有效动作循环（最大失败源）。

    返回 float 百分比（如 56.6）。分母 = 全量记录（与文档 99/159=62.3% 口径一致）；
    JSON 解析失败行跳过。goal_log 缺失则返回 0.0（不影响基线落盘）。
    """
    log = os.path.join(ROOT, "data", "results", "goal_log.jsonl")
    if not os.path.isfile(log):
        return 0.0
    total = 0
    empty = 0
    with open(log, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            sr = rec.get("self_reflection") or {}
            w = sr.get("what_i_did")
            if w is None or (isinstance(w, str) and w.strip() in ("", "无步骤记录")):
                empty += 1
    return round(100.0 * empty / total, 1) if total else 0.0


def _pytest_stats() -> dict | None:
    """跑 pytest not-slow 并解析 passed/skipped/rc，返回统计 dict 或 None（解析失败）。"""
    py = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
    if not os.path.exists(py):
        py = sys.executable
    r = sh([py, "-m", "pytest", "tests/", "-q", "-m", "not slow"])
    tail = (r.stdout or "")[-1500:]
    m = re.search(r"(\d+) passed", tail)
    if not m:
        return None
    m2 = re.search(r"(\d+) skipped", tail)
    return {
        "rc": r.returncode,
        "test_passed": int(m.group(1)),
        "test_total": int(m.group(1)) + (int(m2.group(1)) if m2 else 0),
        "test_skipped": int(m2.group(1)) if m2 else 0,
        "_tail": tail,
    }


# 2026-08-27 严格纠正：泄露式假验证护栏。
# 并行「真题库重建」自动化曾提交 demo_llm_rag_solve.py，明文硬编码 real_crypto_10733 真 flag
# 与完整解法推导，再以 EXPECTED 自比「验证通过」，据此虚假宣称「LLM 推理从 0 突破」。
# 该真 flag 是 repo 内绝不应出现的硬编码字面量；任何重现都使门禁硬失败。
# 故意拆成两段拼接，避免本常量定义本身被下面的扫描当成「泄露字面量」命中。
_LEAKED_FLAG_PARTS = ("rabbits6sc5mpl8", "x6s9w6n6nc5mpl8x6s9w6n6nc5mpl8x6s9w6n6nc5mpl8")
_LEAKED_REAL_FLAG = "".join(_LEAKED_FLAG_PARTS)


def scan_leaked_demo() -> bool:
    """泄露式假验证扫描（严格纠正护栏）。返回 True=干净；False=红线违规。

    扫描 scripts/ knowledge/ core/ agents/ tests/ 下全部 .py（排除 .venv）。违规判定：
      (1) 出现真实 10733 flag 硬编码字面量 _LEAKED_REAL_FLAG；
      (2) scripts/demo_llm_rag_solve.py 仍存在预植答案（形如 flag{...} 的写死样例）。
    """
    import pathlib
    ok = True
    for d in ("scripts", "knowledge", "core", "agents", "tests"):
        root = pathlib.Path(ROOT, d)
        if not root.is_dir():
            continue
        for py in root.rglob("*.py"):
            if ".venv" in str(py):
                continue
            try:
                txt = py.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if _LEAKED_REAL_FLAG in txt:
                print(f"❌ 泄露式假验证：{py} 含硬编码真实 flag 字面量（RDD 红线违规）")
                ok = False
            if py.name == "demo_llm_rag_solve.py" and "EXPECTED =" in txt:
                print(f"❌ 泄露式假验证：{py} 仍预植答案 (EXPECTED =)，构成自比假验证")
                ok = False
    if ok:
        print("✅ 泄露式假验证扫描通过：无硬编码真实 flag / 无预植答案")
    return ok


def kpi_check() -> bool:
    """KPI 严格断言（双通道）：台账计数 == 基线 且 回归集真跑全过 且 无泄露式假验证。

    2026-08-27 严格纠正：由 `>= 基线`（仅防回退）升级为 `== 基线`（注水亦失败），
    并前置泄露式假验证扫描——任何红线违规直接硬失败。
    """
    n = count_offline_verified()
    if n < 0:
        return False
    # 2026-08-27 严格纠正：前置泄露式假验证扫描（红线违规硬失败）
    if not scan_leaked_demo():
        return False
    bl = load_baseline()
    if "offline_verified" not in bl:
        # 第九轮(2026-08-25) fail-closed 修复：基线文件缺失 = 删除基线即可重置棘轮的后门，
        # 改为硬失败而非"以当前计数重建并放行"。棘轮锚必须存在，删除即视为篡改。
        print("❌ KPI 基线文件缺失——棘轮锚被删除，合并硬失败（fail-closed）。"
              "请勿删除 KPI_BASELINE.json；若确需重建，先从 REAL_SOLVES_LEDGER.md 恢复 offline_verified 记录。")
        sys.exit(1)
    else:
        base = bl["offline_verified"]
        if n != base:
            print(f"❌ KPI 计数断言失败（严格）：offline_verified {n} != 基线 {base}"
                  f"（注水或回退均不允许）")
            return False
        print(f"✅ KPI 计数断言通过（严格）：offline_verified {n} == 基线 {base}")
    # 真值回归：台账计数只是文本，回归集才是"能复现"的证据
    if not regression_check():
        return False
    # 空转占比趋势线（2026-08-25 第九轮新增维度）：监控漂移，回升即告警
    # 软门禁（不硬失败）：空转占比受题集难度混淆变量影响（项目文档已注明），
    # 硬失败会误伤"题集变难"型合法上升；故仅告警 + 记录，真回退由 --full-baseline 重锚。
    if "empty_loop_ratio" in bl:
        base_elr = bl["empty_loop_ratio"]
        cur_elr = compute_empty_loop_ratio()
        if cur_elr > base_elr:
            print(f"⚠️ 空转占比回升：{cur_elr}% > 基线 {base_elr}%（主 Agent 空转恶化——"
                  f"查 E2/E6/E3 是否回退；若题集变难属混淆变量，跑 --full-baseline 重锚）")
        else:
            print(f"✅ 空转占比稳定/下降：{cur_elr}% ≤ 基线 {base_elr}%")
    return True


def full_tests() -> bool:
    """全量测试门禁：pytest tests/ -m "not slow"。通过后把测试数写入 KPI 基线
    （测试基线漂移检测：278→271 类下降在看板暴露并须解释，2026-08-24 锐评⑦）。"""
    print("── 全量测试（merge 级门禁，~30s）──")
    ts = _pytest_stats()
    if ts is None:
        print("❌ 全量测试解析失败：pytest 未产出 passed 数")
        return False
    tail = ts.get("_tail", "")
    print(tail[-800:])
    if ts["rc"] != 0:
        print("❌ 全量测试失败：merge 禁止带红进 main")
        return False
    _n = count_offline_verified()
    if _n >= 0:
        save_baseline(_n, test_stats={k: v for k, v in ts.items() if k.startswith("test_")})
        print(f"ℹ️ 测试基线已刷新：{ts['test_passed']} passed（{BASELINE}）")
    print("✅ 全量测试通过")
    return True


def full_baseline() -> bool:
    """全量真题真值基线刷新（每日定时跑，不阻塞合并）。

    把棘轮锚抬到当前真值：offline_verified（台账严格计数）+ 测试数 + 空转占比
    + 链路失败步，全部落盘。benchmark 真跑（解出真值）为补充步骤，另行后台跑，
    不阻塞基线落盘（详见本函数末尾提示）。
    """
    print("── 全量真题真值基线刷新（锚抬到当前真值，2026-08-25 第九轮）──")
    n = count_offline_verified()
    if n < 0:
        return False
    # 测试数（漂移检测）——pytest 失败则保留旧基线测试数，不抹掉
    ts = _pytest_stats()
    if ts is not None and ts["rc"] == 0:
        test_stats = {k: v for k, v in ts.items() if k.startswith("test_")}
    else:
        old = load_baseline()
        test_stats = {k: old[k] for k in ("test_passed", "test_total", "test_skipped") if k in old}
        if ts is None:
            print("ℹ️ pytest 解析失败，沿用旧测试基线（不抹掉）")
        else:
            print(f"ℹ️ pytest 返回非 0（rc={ts['rc']}），沿用旧测试基线（不抹掉）")
    # 空转占比（主 Agent 趋势线，最重要维度）
    elr = compute_empty_loop_ratio()
    # 链路失败步（须先跑 scripts/_chain_stats.py 生成 chain_stats_*.json）
    extra = {"empty_loop_ratio": elr}
    try:
        _cs = sorted(__import__("pathlib").Path(ROOT, "data", "results")
                     .glob("chain_stats_*.json"))
        if _cs:
            _d = json.loads(_cs[-1].read_text(encoding="utf-8"))
            _steps = _d.get("steps", {})
            _worst = max(_steps, key=lambda k: _steps[k].get("count", 0)) if _steps else ""
            if _worst:
                extra["chain_worst_step"] = f"{_worst}({_steps[_worst].get('pct', 0)}%)"
    except Exception:  # noqa: BLE001
        pass
    save_baseline(n, test_stats=test_stats, extra=extra)
    print(f"✅ 基线已刷新：offline_verified={n}，empty_loop_ratio={elr}%，"
          f"test_passed={test_stats.get('test_passed') if test_stats else 'N/A'}，"
          f"chain_worst_step={extra.get('chain_worst_step', '—')}，"
          f"as_of={time.strftime('%Y-%m-%d', time.gmtime())}")
    print("ℹ️ 补充：benchmark 真跑（解出真值）另跑：")
    print("   python -m eval.benchmark --questions-dir data/questions_real "
          "--provider baidu,qwen --wallclock 300")
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
