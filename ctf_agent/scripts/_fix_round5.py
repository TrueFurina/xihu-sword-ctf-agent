#!/usr/bin/env python3
"""Round-5 深度修复脚本（指导老师锐评落地）。

只做精确字符串替换 + 计数断言，不做任何模糊改写。
改完打印每个文件的 OK/FAIL，FAIL 即退出非零。
"""
import sys

ROOT = "E:\\Program\\西湖论剑\\ctf_agent"


def edit(path: str, old: str, new: str, occ: int = 1):
    full = ROOT + "\\" + path
    with open(full, "r", encoding="utf-8", newline="") as f:
        raw = f.read()
    nl = "\r\n" if "\r\n" in raw else "\n"
    content = raw.replace("\r\n", "\n")
    cnt = content.count(old)
    if cnt != occ:
        raise SystemExit(f"FAIL {path}: 期望 {occ} 处，实际 {cnt} 处\n---OLD---\n{old}")
    content = content.replace(old, new)
    with open(full, "w", encoding="utf-8", newline="") as f:
        f.write(content.replace("\n", nl))
    print(f"OK   {path}  (替换 {cnt} 处)")


# ── 1. RSA 自动检测补 Wiener 分支 ─────────────────────────────
edit(
    "skills/rsa_fermat_factor.py",
    '''        else:
            attack = "fermat"''',
    '''        else:
            # 大 e（接近 n 量级）通常是 Wiener（小 d）场景，优先试 Wiener；否则费马
            if e > 0 and n > 0 and e.bit_length() >= n.bit_length() // 2:
                attack = "wiener"
            else:
                attack = "fermat"''',
)

# ── 2. presolve 6 段串行 → 6 路并发 ───────────────────────────
edit(
    "core/presolve.py",
    '''    # 1) flag_scan（源码注释/HTML alert 明文）
    flag = await _try_flag_scan(question, registry)
    if flag and _passes_answer_check(question, flag, answers):
        return flag
    # 2) crypto_auto（crypto/misc 确定性攻击）
    flag = await _try_crypto_auto(question, registry)
    if flag and _passes_answer_check(question, flag, answers):
        return flag
    # 3) 数学引擎矩阵
    flag = await _try_math_engine(question)
    if flag and _passes_answer_check(question, flag, answers):
        return flag
    # 4) 关键词 fast_solve
    flag = await _try_fast_solve(question)
    if flag and _passes_answer_check(question, flag, answers):
        return flag
    # 5) jpeg_png_embedded（JPEG 尾部嵌 PNG 提取 + OCR，2026-08-22 M3 补强）
    flag = await _try_jpeg_png_embedded(question)
    if flag and _passes_answer_check(question, flag, answers):
        return flag
    # 6) description 末尾明文答案启发式（2026-08-22 M3）
    #    CTF EASY 题常用"解出 X"/"answer is X"/"得到 X"在 description 直接给答案。
    #    启发式：抓取"解出 X"中的 X 并按题目 flag_pattern 包装。
    flag = await _try_desc_answer(question)
    if flag and _passes_answer_check(question, flag, answers):
        return flag
    return None''',
    '''    # 并发预扫（2026-08-22 锐评整改：6 路确定性嗅探一次性并发，最短解题时延=各路最大值而非求和）
    # 顺序不再决定优先级——任一路命中且通过答案校验即返回。
    _presolve_tasks = [
        _try_flag_scan(question, registry),
        _try_crypto_auto(question, registry),
        _try_math_engine(question),
        _try_fast_solve(question),
        _try_jpeg_png_embedded(question),
        _try_desc_answer(question),
    ]
    _presolve_results = await asyncio.gather(*_presolve_tasks, return_exceptions=True)
    for _r in _presolve_results:
        if isinstance(_r, Exception):
            logger.debug("[presolve] 并发嗅探异常: %s", _r)
            continue
        if _r and _passes_answer_check(question, _r, answers):
            return _r
    return None''',
)

# ── 3. 删除 _emergency.py 明文 flag 炸弹 ──────────────────────
edit(
    "scripts/_emergency.py",
    '        "10733": "rabbits1sc0mpl3x1s4w1n1nc0mpl3x1s4w1n1nc0mpl3x1s4w1n1nc0mpl3",\n',
    "",
)

# ── 4. benchmark_report.json 去「可引用」误导 ──────────────────
edit(
    "data/results/benchmark_report.json",
    '    "disclaimer": "mock 数字禁止引用；真实模式=主 Agent 全链路可引用",',
    '    "disclaimer": "N=1 样本量无意义，禁止作为能力证据引用；真实模式=主 Agent 全链路但仅跑过 1 题（crypto-001），须用 eval.benchmark 全量重跑",',
)

# ── 5a. run_cli 接 plan_challenges 先易后难 ───────────────────
edit(
    "run.py",
    '''    questions = load_questions("data/questions")
    if category:
        questions = [q for q in questions if q.category == category]
    if not questions:''',
    '''    questions = load_questions("data/questions")
    if category:
        questions = [q for q in questions if q.category == category]
    # 锐评整改（2026-08-22）：先易后难排序——简单题（crypto/misc EASY）优先拿分，
    # 治正式赛 CRYPTO-01 埋头难题 3h 0 解出。race_strategy.plan_challenges 在此接线。
    try:
        from core.race_strategy import plan_challenges
        questions = plan_challenges(questions)
    except Exception:
        pass
    if not questions:''',
)

# ── 5b. run_web question_loader 接 plan_challenges ────────────
edit(
    "run.py",
    '''    def question_loader():
        from eval.cases import load_questions

        return load_questions("data/questions")''',
    '''    def question_loader():
        from eval.cases import load_questions
        qs = load_questions("data/questions")
        # 锐评整改（2026-08-22）：先易后难排序（race_strategy.plan_challenges 接线）
        try:
            from core.race_strategy import plan_challenges
            qs = plan_challenges(qs)
        except Exception:
            pass
        return qs''',
)

print("\nALL FIXES APPLIED")
