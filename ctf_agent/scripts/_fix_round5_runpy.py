"""⚠️ 历史一次性修复脚本（2026-08-22 已执行）——仅保留作考古参考，不要重跑。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isfile(os.path.join(ROOT, "run.py")):
    sys.exit("历史修复脚本，仅在ctf_agent根目录下有意义，已不建议重跑")


def edit(path, old, new, occ=1):
    full = ROOT + "\\" + path
    with open(full, "r", encoding="utf-8", newline="") as f:
        raw = f.read()
    nl = "\r\n" if "\r\n" in raw else "\n"
    content = raw.replace("\r\n", "\n")
    cnt = content.count(old)
    if cnt != occ:
        raise SystemExit(f"FAIL {path}: 期望 {occ} 实际 {cnt}\n{old[:60]}")
    content = content.replace(old, new)
    with open(full, "w", encoding="utf-8", newline="") as f:
        f.write(content.replace("\n", nl))
    print(f"OK {path} x{occ}")


# 5a. run_cli 接 plan_challenges
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

# 5b. run_web question_loader 接 plan_challenges
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
print("\nRUN.PY FIXES APPLIED")
