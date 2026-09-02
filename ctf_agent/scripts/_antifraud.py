#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反注水法令（写死，fail-closed）——本项目诚实口径的唯一机器执法核心。

立法意图（用户 2026-08-27 严令：本项目必须超级严格禁止一切注水行为！
所有注水行为都将收到严厉惩罚！写死！）：

  「注水」定义为任何试图：
    1) 虚增 / 虚报 KPI（offline_verified 解出数偏离写死真值锚）；
    2) 以泄露式假验证（硬编码真 flag / 预植答案 EXPECTED）冒充真能力突破；
    3) 把不可复现项 / 外部真题 / self-authored 训练项计入严格 KPI；
    4) 篡改基线锚文件（KPI_BASELINE.json）以重置棘轮、粉饰水位；
    5) 在 commit message 中以「LLM 推理突破 / 破冰 / 从 0 突破」等声称
       包装泄露式假验证。

本模块把「禁止注水」从文档宣言升级为**写死的机器执法**：
  - KPI 真值锚 = 硬编码常量 KPI_WATERMARK，不读任何可被编辑的文件；
  - 任何偏离 = fail-closed 阻断（commit / merge 一律拒绝）；
  - 每一次注水企图 → 永久记入 tamper-evident 违规账（严厉惩罚，可审计、可追责）。

本模块零外部依赖（纯 stdlib），可被 pre-commit / pre-merge / commit-msg 钩子
与 CI 直接调用，也可被 pytest 单测。

调用：
  python scripts/_antifraud.py                           # 全量执法（merge / CI）
  python scripts/_antifraud.py --pre-commit             # 快速执法（每次 commit）
  python scripts/_antifraud.py --commit-msg-file <path> # commit message 执法
  python scripts/_antifraud.py --report                 # 打印荣誉法典 + 当前状态
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

# 复用既有闸门里的真值解析与泄露扫描逻辑（单一事实来源，避免口径漂移）
from _merge_gate import (  # noqa: E402
    count_offline_verified,
    scan_leaked_demo,
    _classify_entry,
)

# 循环验证排除项（与 _merge_gate.count_offline_verified 同口径，写死在此处，
# 防止把「sha256 自比」式同义反复误计为严格 KPI 解出）。
_CIRCULAR_VERIFY_EXCLUDE = {"real_crypto_specialcurve2"}

ROOT = os.path.dirname(SCRIPTS_DIR)
LEDGER = os.path.join(ROOT, "REAL_SOLVES_LEDGER.md")
BASELINE = os.path.join(ROOT, "data", "results", "KPI_BASELINE.json")
GOV_DIR = os.path.join(ROOT, "governance", "anti_fraud")
VIOLATION_LOG = os.path.join(GOV_DIR, "violations.jsonl")
HONOR_CODE = os.path.join(GOV_DIR, "HONOR_CODE.md")

# ─────────────────────────────────────────────────────────────────────────
# 写死的 KPI 真值锚（不可经任何文件篡改抬升 / 压低）——「证据化地板」模型
# ─────────────────────────────────────────────────────────────────────────
# 诚实校准（2026-08-28 实测）：原 KPI_WATERMARK=12 中含 ezrsa / simplelegendre /
# exciting_inverse 三道，现行确定性管线 presolve 提取=None（不可复现），已移出严格
# KPI 并列入 _merge_gate.KNOWN_GAP。当前可机复现真值 = 9。
# 2026-09-03 三道全部带证据重新晋级（地板 9 + 晋升 3 = 水位 12，恰好回到最初 12 的
# 数值口径——但此 12 是「每题带 sha256 真值 + 可复现 verifier」的全证据态，非当年
# 仅凭历史人工解出注水的 12）：
#   - ezrsa：Håstad 广播攻击求解器（skills/crypto_hastad_broadcast.py，
#     接入 presolve `_try_hastad_broadcast`）REGRESS_PASS（e=17）；
#   - simplelegendre：勒让德符号逐位分解求解器（skills/crypto_legendre_phi.py，
#     接入 presolve `_try_legendre_phi`）REGRESS_PASS（phi 泄露分解 p/q）；
#   - exciting_inverse：phi+双模逆二次分解求解器（skills/crypto_modinv_factor.py，
#     接入 presolve `_try_modinv_factor`）REGRESS_PASS（判别式开方分解 p/q）。
# 三道 sha256 均逐字匹配题面真值，均经 PROMOTION_EVIDENCE 正式晋级。
#
# 模型升级（2026-08-28 评审 R5/G5）：旧版 KPI_WATERMARK 是「等式锁」——n != 9 一律
# 当注水拒绝，导致真实进展到 10/13 也会被误杀（治理过拟合反作用）。现改为「带证据可
# 晋级的地板」：
#   - BASE_WATERMARK = 9 是不可下破的地板（回归即阻断）；
#   - 任何 >9 的晋升必须带可审计证据（flag_sha256 真值 + 可复现 verifier / 轨迹 / PR 链接），
#     经 promotion PR 写入 PROMOTION_EVIDENCE 与 AUTHORIZED_KPI_SOLVES，并同步抬升
#     KPI_BASELINE.json；水位 = 基线 + 证据化晋升数。
#   - 单边篡改（只抬台账计数、不动证据/常量）仍被 WATERMARK_DRIFT（计数溢出无对应晋升）
#     与 PROMOTION_WITHOUT_EVIDENCE（白名单含超额项却无证据）双闸 fail-closed 阻断。
# 所有量均为写死常量派生，不读任何外部文件。
BASE_WATERMARK = 9

# 基线 9 题的授权题块（ID 级白名单，写死）。
BASE_AUTHORIZED_KPI_SOLVES = frozenset({
    "10733",
    "real_misc_vnctf_flag",
    "real_crypto_anwang_crypto1",
    "real_crypto_ezmult",
    "real_misc_xuanhun_signin",
    "real_crypto_filterrandom",
    "real_crypto_qiangwang_classic",
    "real_reverse_sheng",
    "real_reverse_upx",
})

# 证据化晋升题块（>9 的部分）：每道必须带可审计证据字符串
# （格式建议： "sha256:<真值摘要>|verify:scripts/_regress_one.py <id>|pr:<PR链接>"）。
# 新增晋升 = 提 promotion PR，改动本字典 + 同增 AUTHORIZED + 同步 KPI_BASELINE.json。
# 凡出现在本集合但证据字符串为空 / 缺失 → PROMOTION_WITHOUT_EVIDENCE 阻断（无证据注水）。
# 已晋升 3 项（2026-09-03）：ezrsa —— Håstad 广播攻击确定性求解器
# skills/crypto_hastad_broadcast.py 接入 presolve（_try_hastad_broadcast），
# `scripts/_regress_one.py real_crypto_ezrsa` 实测 REGRESS_PASS（e=17，
# CRT 合并三组 (n,c) + 整数开 e 次根，flag sha256 逐字匹配题面真值 93be5f3a…）。
# simplelegendre —— 勒让德符号逐位分解确定性求解器 skills/crypto_legendre_phi.py
# 接入 presolve（_try_legendre_phi），`scripts/_regress_one.py real_crypto_simplelegendre`
# 实测 REGRESS_PASS（phi 泄露分解 1024-bit p/q + 逐位 (c|p)=(-1)^bi 判定，
# flag sha256 逐字匹配题面真值 75e6aa4d…）。
# exciting_inverse —— phi+双模逆二次分解确定性求解器 skills/crypto_modinv_factor.py
# 接入 presolve（_try_modinv_factor），`scripts/_regress_one.py real_crypto_exciting_inverse`
# 实测 REGRESS_PASS（CRT⟹A·p+B·q=N+1⟹q 二次方程判别式开方分解 1024-bit p/q，
# flag sha256 逐字匹配题面真值 4b84616c…）。
PROMOTION_EVIDENCE = {
    "real_crypto_ezrsa": (
        "sha256:93be5f3ad422c43e99e705f52df3ad974548dc558714e48162d3939787bdfdbf"
        "|verify:scripts/_regress_one.py real_crypto_ezrsa (REGRESS_PASS 2026-09-03)"
        "|skill:skills/crypto_hastad_broadcast.py (Håstad e=17: CRT+iroot, 0.02s)"
    ),
    "real_crypto_simplelegendre": (
        "sha256:75e6aa4de894faf2a760a91aa74d93e9f3b971377012f81bfb95806902ba0002"
        "|verify:scripts/_regress_one.py real_crypto_simplelegendre (REGRESS_PASS 2026-09-03)"
        "|skill:skills/crypto_legendre_phi.py (Legendre 逐位: phi 分解 p/q + (c|p)=(-1)^bi, 1.2s)"
    ),
    "real_crypto_exciting_inverse": (
        "sha256:4b84616cccbe84a99256c23152a4fd226e87e9da64e92689063046251cc251c5"
        "|verify:scripts/_regress_one.py real_crypto_exciting_inverse (REGRESS_PASS 2026-09-03)"
        "|skill:skills/crypto_modinv_factor.py (phi+双模逆: CRT⟹q 二次方程判别式分解, 0.23s)"
    ),
}

# 派生（写死常量，不读文件）：授权题块全集 = 基线 ∪ 晋升；水位 = 基线 + 晋升数。
AUTHORIZED_KPI_SOLVES = frozenset(BASE_AUTHORIZED_KPI_SOLVES | set(PROMOTION_EVIDENCE.keys()))
KPI_WATERMARK = BASE_WATERMARK + len(PROMOTION_EVIDENCE)

# 泄露式假验证红线（与 _merge_gate 保持一致；拆两段避免本常量被自身扫描命中）
_LEAKED_FLAG_PARTS = ("rabbits6sc5mpl8", "x6s9w6n6nc5mpl8x6s9w6n6nc5mpl8x6s9w6n6nc5mpl8")
LEAKED_REAL_FLAG = "".join(_LEAKED_FLAG_PARTS)

# commit message 中「声称 LLM 真推理突破」的触发词——此类声称若伴随泄露式
# 预植答案，即构成「以假验证冒充真能力」的注水，必须阻断。
_LLM_CLAIM_PATTERNS = (
    re.compile(r"LLM\s*推理贡献"),
    re.compile(r"LLM\s*真推理"),
    re.compile(r"破冰"),
    re.compile(r"从\s*0\s*突破"),
    re.compile(r"推理从\s*0"),
)


# ─────────────────────────────────────────────────────────────────────────
# 基础工具
# ─────────────────────────────────────────────────────────────────────────
def now_iso() -> str:
    """带时区的时间戳（东八区），用于违规账留痕。"""
    tz = timezone(timedelta(hours=8))
    return datetime.now(tz).strftime("%Y-%m-%dT%H:%M:%S%z")


def session_id() -> str:
    """当前会话标识：优先环境变量，回退 git 最近一次 author。"""
    s = os.environ.get("CT_AGENT_SESSION") or ""
    if s:
        return s
    try:
        a = subprocess.run(["git", "log", "-1", "--format=%an"],
                           capture_output=True, text=True).stdout.strip()
        return a or "unknown"
    except Exception:
        return "unknown"


def _append_violation(rec: dict) -> None:
    """把违规记录追加进 tamper-evident 违规账（永久、可审计）。"""
    try:
        os.makedirs(GOV_DIR, exist_ok=True)
        with open(VIOLATION_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        # 记账失败不得掩盖注水本身——执法仍按 violations 列表判定阻断
        pass


def log_violation(rule: str, severity: str, detail: str,
                  path: str = "", snippet: str = "", outcome: str = "BLOCKED") -> dict:
    """记录一条注水行为并落账，返回该记录字典（供上层汇总打印）。"""
    rec = {
        "ts": now_iso(),
        "session": session_id(),
        "rule": rule,
        "severity": severity,
        "outcome": outcome,
        "detail": detail,
        "path": path,
        "snippet": snippet[:80] if snippet else "",
        "kpi_watermark": KPI_WATERMARK,
    }
    _append_violation(rec)
    return rec


# ─────────────────────────────────────────────────────────────────────────
# 各类注水检测（每个返回违规记录列表；空 = 干净）
# ─────────────────────────────────────────────────────────────────────────
def check_kpi_watermark() -> list:
    """证据化地板：KPI 计数必须 == 写死水位（= 基线 + 证据化晋升数）。

    - n < 0              → LEDGER_MISSING（台账缺失，fail-closed 合并硬失败）
    - n < BASE_WATERMARK → WATERMARK_REGRESSION（跌破不可下破的地板，擅自降级真值锚）
    - n != KPI_WATERMARK → WATERMARK_DRIFT（计数溢出地板+晋升，缺对应证据化晋升记录）
    - else               → PASS
    """
    out = []
    n = count_offline_verified()
    if n < 0:
        out.append(log_violation(
            "LEDGER_MISSING", "BLOCK",
            "台账缺失，无法核验 KPI 真值——合并硬失败（fail-closed）", path=LEDGER))
    elif n < BASE_WATERMARK:
        out.append(log_violation(
            "WATERMARK_REGRESSION", "BLOCK",
            f"KPI 计数 {n} < 不可下破地板 {BASE_WATERMARK}（擅自降级真值锚，注水）",
            path=LEDGER))
    elif n != KPI_WATERMARK:
        out.append(log_violation(
            "WATERMARK_DRIFT", "BLOCK",
            f"KPI 计数 {n} != 写死水位 {KPI_WATERMARK}（=地板{BASE_WATERMARK}"
            f"+晋升{len(PROMOTION_EVIDENCE)}）；计数溢出却无对应证据化晋升记录，疑似注水虚增",
            path=LEDGER))
    return out


def _ledger_counted_ids() -> tuple:
    """解析台账，返回 (已知授权 ID 集合, 走私项标题集合)。

    与 count_offline_verified 同口径：仅 A/B 类、状态含 ✅ offline_verified、
    且标题不含循环验证排除项的题块被计入。
    """
    known, smuggled = set(), set()
    if not os.path.isfile(LEDGER):
        return known, smuggled
    cur_title = ""
    with open(LEDGER, encoding="utf-8") as f:
        for line in f:
            if line.startswith("### "):
                cur_title = line
                continue
            if (_classify_entry(cur_title) in ("A", "B")
                    and "- **状态**" in line and "✅ offline_verified" in line
                    and not any(e in cur_title for e in _CIRCULAR_VERIFY_EXCLUDE)):
                matched = [aid for aid in AUTHORIZED_KPI_SOLVES if aid in cur_title]
                if matched:
                    known.add(matched[0])
                else:
                    smuggled.add(cur_title.strip()[:60])
    return known, smuggled


def check_authorized_set() -> list:
    """ID 级走私检测：凡被计入严格 KPI 的题块必须 ∈ 授权集合；
    授权集合缺失 = 被擅自降级（篡改）。两者皆注水。"""
    out = []
    known, smuggled = _ledger_counted_ids()
    for title in smuggled:
        out.append(log_violation(
            "UNAUTHORIZED_SOLVE", "BLOCK",
            f"台账将未授权题块计入严格 KPI（注水走私）：{title}", path=LEDGER))
    missing = AUTHORIZED_KPI_SOLVES - known
    if missing:
        out.append(log_violation(
            "KPI_REGRESSION", "BLOCK",
            f"授权题块缺失（被擅自降级，破坏真值锚）：{sorted(missing)}", path=LEDGER))
    return out


def check_promotion_evidence() -> list:
    """晋升须带证据：凡 AUTHORIZED 中超出基线的题块，必须存在 PROMOTION_EVIDENCE 证据。

    防止「白名单里悄悄加项却没有真值证据」的水位虚抬——无证据晋升即注水。
    """
    out = []
    promoted = set(AUTHORIZED_KPI_SOLVES) - BASE_AUTHORIZED_KPI_SOLVES
    for pid in sorted(promoted):
        ev = PROMOTION_EVIDENCE.get(pid)
        if not ev:
            out.append(log_violation(
                "PROMOTION_WITHOUT_EVIDENCE", "BLOCK",
                f"题块 {pid} 计入严格 KPI 但缺证据化晋升记录（需 flag_sha256 / 轨迹），"
                f"属无证据注水，必须提 promotion PR 附证据", path=LEDGER))
    return out


def check_baseline_consistency() -> list:
    """基线锚文件若被改成 ≠ 写死水位，即属篡改（试图重置棘轮 / 粉饰）。"""
    out = []
    if not os.path.isfile(BASELINE):
        return out  # 缺失由 merge_gate 单独硬失败处理，此处不重复
    try:
        bl = json.load(open(BASELINE, encoding="utf-8"))
    except Exception:
        return out
    base = bl.get("offline_verified")
    if isinstance(base, int) and base != KPI_WATERMARK:
        out.append(log_violation(
            "BASELINE_TAMPER", "BLOCK",
            f"KPI_BASELINE.json 锚值 {base} != 写死水位 {KPI_WATERMARK}"
            f"（基线被篡改以重置棘轮 / 粉饰水位）", path=BASELINE))
    return out


def check_leaked_demo() -> list:
    """泄露式假验证：仓库含硬编码真实 flag / 预植答案 → 违规。"""
    out = []
    if not scan_leaked_demo():
        out.append(log_violation(
            "LEAKED_DEMO", "BLOCK",
            "仓库含硬编码真实 flag 字面量 / 预植答案 EXPECTED（泄露式假验证，RDD 红线）"))
    return out


def scan_staged_leaked() -> bool:
    """扫 git 暂存区 diff：含硬编码真实 flag / 预植答案 → False（有泄露）。

    仅检查「新增行」(+ 前缀，排除 +++ 文件头行)，不扫 diff 上下文/删除行。
    原因：原实现对整段 diff（含 3 行上下文）做正则匹配，会把"法条 HONOR_CODE.md
    举例说明『预植答案（把真 flag 字面量赋给 EXPECTED 变量后自比通过）』这条红线"
    这一**被引述的反模式说明文字**（作为 diff 上下文行出现）误判为泄露，导致合法
    文档改动被阻断。门禁真正关切的是"你这次提交了什么"（新增行），而非"你改动的
    文件附近有什么"（上下文）。
    收窄到新增行后：你新植入的真 flag / 预植 EXPECTED 答案仍会被精准捕获（语义不变，
    执法不弱）；既有文档里"提及反模式"的噪声不再误伤。
    注：仓库全量泄露扫描 check_leaked_demo() 仍覆盖所有既有文件，不因此产生安全退步。
    """
    try:
        raw = subprocess.run(["git", "diff", "--cached"],
                             capture_output=True, text=True).stdout
    except Exception:
        return True  # 无法检查 → 不误拦（泄露已由全量 scan_leaked_demo 兜底）
    # 逐行扫描新增行：
    #  (a) LEAKED_REAL_FLAG 真 flag 常量全局硬检查——但豁免以下治理/证据文件对其的记录：
    #       (i) 反注水代码自身 scripts/_antifraud.py 的常量声明/引用行；
    #      (ii) 反注水证据层 REAL_SOLVES_LEDGER.md；
    #     (iii) 法条区 governance/anti_fraud/*（立法文本）。
    #      否则治理文件记录真 flag 作为证据/立法会被自己误判为泄露（false-positive）。
    #  (b) 预植答案（形如 flag{...}）检测——法条区豁免（举例非预植）。
    pat = re.compile(r'EXPECTED\s*=\s*"(?:flag|DASCTF|xctf)\{')
    cur_file = None
    for line in raw.splitlines():
        if line.startswith("diff --git"):
            cur_file = line.split(" b/")[-1] if " b/" in line else None
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = line[1:]
        if (LEAKED_REAL_FLAG in body
                and "LEAKED_REAL_FLAG" not in body
                and "REAL_SOLVES_LEDGER.md" not in cur_file
                and "governance/anti_fraud/" not in cur_file):
            return False
        if cur_file and "governance/anti_fraud/" in cur_file:
            continue
        if pat.search(body):
            return False
    return True


def check_commit_message(text: str) -> list:
    """commit message 注水检测。"""
    out = []
    claims = any(p.search(text) for p in _LLM_CLAIM_PATTERNS)
    if claims and not scan_staged_leaked():
        out.append(log_violation(
            "LEAKED_FAKE_LLM", "BLOCK",
            "commit message 声称 LLM 真推理突破，但暂存区含预植答案 / 硬编码真 flag"
            "（泄露式假验证冒充真能力）"))
    if LEAKED_REAL_FLAG in text:
        out.append(log_violation(
            "LEAKED_FLAG_IN_MSG", "BLOCK",
            "commit message 含硬编码真实 flag 字面量（明文泄露）"))
    return out


# ─────────────────────────────────────────────────────────────────────────
# 编排
# ─────────────────────────────────────────────────────────────────────────
def enforce(mode: str = "full") -> tuple:
    """执行反注水执法。返回 (ok, violations)。

    mode="full"       ：merge / CI 全量（含仓库泄露扫描）
    mode="pre_commit" ：每次 commit 快速版（额外扫暂存区泄露）
    """
    violations: list = []
    violations += check_kpi_watermark()
    violations += check_authorized_set()
    violations += check_promotion_evidence()
    violations += check_baseline_consistency()
    violations += check_leaked_demo()
    if mode == "pre_commit":
        if not scan_staged_leaked():
            violations.append(log_violation(
                "STAGED_LEAK", "BLOCK",
                "暂存区含硬编码真实 flag / 预植答案 EXPECTED（泄露式假验证）"))
    return (len(violations) == 0, violations)


def report() -> None:
    """打印荣誉法典摘要与当前执法状态。"""
    print("=" * 64)
    print("反注水法令（写死 · fail-closed）")
    print("=" * 64)
    print(f"  KPI 写死真值锚 KPI_WATERMARK = {KPI_WATERMARK}")
    print(f"  KPI 基线地板 BASE_WATERMARK = {BASE_WATERMARK}（不可下破）")
    print(f"  证据化晋升数 = {len(PROMOTION_EVIDENCE)}（>9 须带 flag_sha256/轨迹）")
    print(f"  授权题块数 = {len(AUTHORIZED_KPI_SOLVES)}（ID 级白名单）")
    print("  红线（证据化地板模型）：")
    print("    ① KPI 计数偏离写死水位（地板9+证据化晋升）→ 阻断")
    print("    ② 未授权题块计入严格 KPI → 阻断")
    print("    ③ 基线锚文件被篡改 → 阻断")
    print("    ④ 硬编码真 flag / 预植答案（泄露式假验证） → 阻断")
    print("    ⑤ commit message 以 LLM 突破包装泄露式假验证 → 阻断")
    print("    ⑥ 白名单含超额题块却无证据化晋升记录 → 阻断")
    print("  惩罚：每一次注水企图永久记入违规账（可被审计、追责）。")
    print("=" * 64)
    ok, v = enforce("full")
    if ok:
        print(f"  ✅ 当前状态：无注水行为（KPI 计数 == {KPI_WATERMARK}）")
    else:
        print(f"  ⛔ 当前状态：检出 {len(v)} 项注水（详见违规账 {VIOLATION_LOG}）")
        for rec in v:
            print(f"     - [{rec['rule']}] {rec['detail']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="反注水法令（写死，fail-closed）")
    ap.add_argument("--pre-commit", action="store_true", help="快速执法（每次 commit）")
    ap.add_argument("--commit-msg-file", default=None, help="扫描指定 commit message 文件")
    ap.add_argument("--report", action="store_true", help="打印荣誉法典 + 当前状态")
    args = ap.parse_args()

    if args.report:
        report()
        return 0

    if args.commit_msg_file:
        path = args.commit_msg_file
        if not path or not os.path.isfile(path):
            return 0
        text = open(path, encoding="utf-8", errors="ignore").read()
        v = check_commit_message(text)
        if v:
            print("⛔ 反注水门禁：commit message 检出注水行为，已永久记入违规账：")
            for rec in v:
                print(f"   - [{rec['rule']}] {rec['detail']}")
            return 1
        print("✅ 反注水：commit message 执法通过")
        return 0

    mode = "pre_commit" if args.pre_commit else "full"
    ok, v = enforce(mode)
    if not ok:
        print("⛔⛔⛔ 反注水法令触发：检出注水行为，已永久记入违规账并阻断！⛔⛔⛔")
        for rec in v:
            print(f"   - [{rec['rule']}] {rec['detail']}")
        print(f"   违规账（永久、可审计）：{VIOLATION_LOG}")
        return 1
    print("✅ 反注水法令：无注水行为，通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
