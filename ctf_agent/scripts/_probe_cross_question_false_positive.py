"""实证：跨题误判（A 题提交 B 题 flag）在现行代码下的判定结果。

背景：
  run.py build_solver 用 `preset_answers(load_questions("data/questions"))`
  构造答案表，只有 ~49 条；而 is_correct 的 _valid_exact 是**全局集合**
  （任意一题的 flag 都算对）。唯一防线是 solver 尾部的 per-question
  精确校验（line ~391），但它**只对答案表内的题生效**。

本脚本验证三种情形下「错 flag 是否被枪毙」：
  ① 题在答案表内 + 真值是 sha256     → 应被拒
  ② 题在答案表内 + 真值是明文 flag   → 应被拒
  ③ 题**不在**答案表内（有自身 sha256）→ 关键：是否被自行仲裁拒掉

零 LLM 成本：纯本地构造 Question + 直接调 flag_matches 判定路径。
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.cases import Question  # noqa: E402


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def build(flag_value, with_sha):
    """构造一个 Question：真值 = flag_value。"""
    kwargs = {
        "id": "probe_%d" % (abs(hash(flag_value)) % 10 ** 6),
        "title": "probe",
        "category": "crypto",
        "description": "probe",
    }
    if with_sha:
        kwargs["flag_sha256"] = sha(flag_value)
    else:
        kwargs["flag"] = flag_value
    return Question(**kwargs)


def per_question_check(q, submitted, answers, answers_q):
    """复刻 run.py line ~368-400 的判定顺序（不含 LLM 部分）。"""
    # ① 自身真值仲裁（P0 修复）
    validated = None
    if getattr(q, "flag_sha256", None):
        validated = q.flag_matches(submitted)
    # ② 答案表精确校验（legacy fallback）
    expected = answers.get(str(q.id))
    expected_q = answers_q.get(str(q.id))
    if expected and expected is not None:
        ok = expected_q.flag_matches(submitted) if expected_q else (submitted == expected)
        if not ok:
            validated = False  # 覆盖：不匹配的拒掉
    return validated


def main():
    real_a = "flag{REAL_ANSWER_A}"
    real_b = "flag{REAL_ANSWER_B}"

    qa_sha = build(real_a, with_sha=True)
    qb_sha = build(real_b, with_sha=True)
    qa_plain = build(real_a, with_sha=False)
    qb_plain = build(real_b, with_sha=False)

    scenarios = [
        ("① sha256 题 + 在答案表", qa_sha, {str(qa_sha.id): real_a},
         {str(qa_sha.id): qa_sha}),
        ("② 明文题 + 在答案表", qa_plain, {str(qa_plain.id): real_a},
         {str(qa_plain.id): qa_plain}),
        ("③ sha256 题 + 不在答案表", qa_sha, {}, {}),
        ("④ 明文题 + 不在答案表", qa_plain, {}, {}),
    ]

    print("%-30s %-12s %-10s %s" % ("场景", "提交B题flag", "判定结果", "是否放行"))
    print("-" * 72)
    escaped = []
    for name, q, answers, answers_q in scenarios:
        submitted = real_b  # 故意提交 B 题的答案
        v = per_question_check(q, submitted, answers, answers_q)
        verdict = {True: "validated", False: "hallucination", None: "未判定"}[v]
        leaked = (v is not False)
        print("%-30s %-12s %-10s %s" % (
            name, "是", verdict, "★ 放行(假阳逃逸)" if leaked else "已拦截"))
        if leaked:
            escaped.append(name)
    print()
    print("逃逸场景数: %d / %d" % (len(escaped), len(scenarios)))
    for e in escaped:
        print("   ", e)
    print()
    print("结论：is_correct 的全局集合无法拦截跨题 flag（它甚至看不见题号），")
    print("      真正起作用的是自身真值仲裁与答案表精确校验这两道 per-question 关卡。")


if __name__ == "__main__":
    main()
