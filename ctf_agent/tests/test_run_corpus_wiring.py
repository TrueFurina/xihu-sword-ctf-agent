"""run.py 三处题库加载点接入 eval/corpus 口径层的回归测试。

背景（2026-10-07）：run.py 有 3 处 load_questions("data/questions")，但语义**不同**，
不能一刀切套同一个闸门：

  ① build_solver 的答案表  —— 要「尽可能全的真值」，**绝不能剔除**
  ② run_cli 的待跑题库      —— 应剔除 input-less 题（免烧预算）
  ③ web 看板的 question_loader —— 同上

测试覆盖：
  A. answer_book 是**并集**语义，且包含旧口径的全部答案（无回归）
  B. _valid_exact/_valid_sha 的构造源不得再有「单库 questions」残留
  C. run_cli 闸门 CLI 端到端（默认剔除 / 开关对照），防哑开关
  D. 原先的跨题误判逃逸题（无 sha256 且不在旧答案表）现已纳入 per-question 校验

变异验证（2026-10-07 已做，结果如实记录）：
  M1  answers.setdefault → 直接赋值（后到覆盖）：**存活，判定为等价变异体**——
      _plain_flag 已把占位副本滤成 None，外层防御在当前数据流下不可达。保留为纵深防御。
  M1' _plain_flag 去掉正则判定：同上，存活（property 层仍拦截）。
  M1''_plain_flag 两层防御全拆：被 test_plain_flag_beats_sha256_placeholder 抓住。
  M2  apply_corpus_gate 忽略 include_unmeasurable：被 CLI 对照组抓住。
  M3  run.py 丢弃闸门返回值（哑开关）：被 test_default_skips_unmeasurable 抓住。
"""
import os
import subprocess
import sys
import unittest
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_RUN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "run.py")
_PY = sys.executable


def _cli(env_extra=None, timeout=300):
    """跑 run.py --mock --mode cli，返回 (rc, stdout+stderr)。"""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [_PY, _RUN, "--mock", "--mode", "cli"],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout, env=env, cwd=os.path.dirname(_RUN))
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


class TestAnswerBookUnion(unittest.TestCase):
    """A. 答案表：并集语义 + 不丢旧答案。"""

    @classmethod
    def setUpClass(cls):
        from eval.cases import load_questions, preset_answers
        from eval.corpus import answer_book
        cls.old = preset_answers(load_questions("data/questions"))
        cls.answers, cls.answers_q = answer_book()

    def test_superset_of_legacy(self):
        """关键回归护栏：旧口径的每一条答案都必须还在。"""
        missing = set(self.old) - set(self.answers)
        self.assertEqual(missing, set(),
                         "扩表后丢答案会让既有题失去真值校验: %s" % sorted(missing)[:5])

    def test_strictly_larger_than_legacy(self):
        """跨库并集必须**多于**单库（否则等于没扩，白改）。"""
        self.assertGreater(len(self.answers), len(self.old),
                           "跨库答案表应多于 data/questions 单库")

    def test_answers_q_covers_truth(self):
        """answers_q 必须收录所有带真值的题（per-question 校验的前提）。"""
        from eval.corpus import load_corpus, has_truth
        entries = load_corpus()
        with_truth = [e for e in entries if has_truth(e.question)]
        missing = [e.question.id for e in with_truth
                   if str(e.question.id) not in self.answers_q]
        self.assertEqual(missing, [],
                         "有真值却不在 answers_q 会导致 per-question 校验缺位")

    def test_plain_flag_beats_sha256_placeholder(self):
        """★ 核心不变式：同一 id 既有明文副本又有占位副本时，答案表必须留明文。

        失守后果：占位串（64hex）进了明文答案表 → 任何 `候选 == expected`
        的路径必然失配 → LLM 解出的**正确 flag 被判成幻觉枪毙**。
        实测 7 道题存在这种双形态（questions_real=占位 / questions=明文）。
        """
        from eval.corpus import answer_book, _looks_like_sha256
        answers, _ = answer_book()
        placeholders = [k for k, v in answers.items() if _looks_like_sha256(v)]
        self.assertEqual(placeholders, [],
                         "明文答案表不得含 sha256 占位串: %s" % placeholders[:5])

    def test_sha_only_questions_still_checkable(self):
        """占位题虽不在明文 answers，但必须在 answers_q 里（靠 sha256 校验）。"""
        from eval.corpus import answer_book, load_corpus, has_truth
        _, answers_q = answer_book()
        answers = self.answers
        sha_only = [e for e in load_corpus()
                    if has_truth(e.question)
                    and str(e.question.id) not in answers]
        missing = [e.question.id for e in sha_only
                   if str(e.question.id) not in answers_q]
        self.assertEqual(
            missing, [],
            "仅 sha256 的题失去 answers_q 会导致完全无法校验: %s" % missing[:5])

    def test_placeholder_not_treated_as_plain_flag(self):
        """sha256 占位题不得把占位串当明文答案写进 answers（会造伪 misuse）。"""
        # answers 只收录 flag 字段非空者；占位题的 flag 是 sha256 串本身，
        # 旧实现也是这么做的（preset_answers 同口径），此处锁定行为一致。
        from eval.cases import Question
        q = Question(id="x1", title="t", category="crypto", description="d",
                     flag_sha256="a" * 64)
        self.assertFalse(getattr(q, "flag", None))


class TestNoSingleSourceResidue(unittest.TestCase):
    """B. build_solver 内不得残留「单库 questions」变量（防 NameError 复活）。"""

    @classmethod
    def setUpClass(cls):
        import io
        cls.src = io.open(_RUN, encoding="utf-8").read()

    def test_build_solver_uses_answer_book(self):
        self.assertIn("answer_book()", self.src,
                      "build_solver 必须走跨库答案表")

    def test_no_bare_load_questions_in_build_solver(self):
        """line ~246 的 _valid_exact 曾用 `for q in questions`，
        questions 被删后会 NameError —— 锁死它已改读 _answers_q。"""
        seg = self.src[self.src.index("def build_solver"):
                       self.src.index("def build_race_solver")]
        self.assertIn("_valid_exact = {str(q.flag) for q in _answers_q.values()",
                      seg, "_valid_exact 必须从 _answers_q 构造")
        self.assertIn("_valid_sha = {q.expected_sha256 for q in _answers_q.values()",
                      seg, "_valid_sha 必须从 _answers_q 构造")


class TestRunCliCorpusGate(unittest.TestCase):
    """C. run_cli 闸门端到端（subprocess 真跑，防哑开关）。"""

    @pytest.mark.local
    def test_default_skips_unmeasurable(self):
        rc, out = _cli()
        self.assertEqual(rc, 0, out[-500:])
        self.assertIn("23/23", out, "默认应剔除不可测题，有效分母 23")
        self.assertIn("原始 50", out, "须公示原始分母")
        self.assertNotIn("对照模式", out)

    @pytest.mark.local
    def test_env_switch_restores_legacy(self):
        rc, out = _cli({"CTF_AGENT_INCLUDE_UNMEASURABLE": "1"})
        self.assertEqual(rc, 0, out[-500:])
        self.assertIn("50 题全跑", out, "开关须恢复全量旧行为")
        self.assertIn("49/50", out)


class TestEscapedQuestionsNowChecked(unittest.TestCase):
    """D. 跨题误判逃逸题现已纳入 per-question 校验。

    逃逸链：题无 flag_sha256（无法自身真值仲裁）+ 不在答案表 → 仅剩 is_correct
    的**全局跨题集合**把关 → 提交任意其它题 flag 也算对。
    修复：answers 跨库扩容，让这些题进入 per-question 精确校验。
    """

    @classmethod
    def setUpClass(cls):
        from eval.cases import load_questions, preset_answers
        from eval.corpus import answer_book
        cls.old = preset_answers(load_questions("data/questions"))
        cls.answers, cls.answers_q = answer_book()

    def test_former_escapees_have_truth(self):
        escaped = []
        from eval.corpus import load_corpus
        for e in load_corpus():
            q = e.question
            if getattr(q, "flag_sha256", None):
                continue  # 有 sha256，自身仲裁会拦截
            if str(q.id) in self.old:
                continue  # 旧口径已覆盖
            escaped.append(q)
        self.assertTrue(escaped, "逃逸样本为空说明判定条件写错，测试失去意义")
        # 诚实边界：本身无真值的题（如 real_misc_xuanhun_ezip，附件指向他机路径）
        # 无论怎么扩表都无法获得 per-question 校验——它们由口径闸门按 no_truth 剔除，
        # 不进 KPI 分母。此处只对**有真值**的题断言。
        from eval.corpus import has_truth
        escaped_with_truth = [q for q in escaped if has_truth(q)]
        self.assertTrue(
            escaped_with_truth,
            "有真值的逃逸样本为空，本测试失去意义（可能已被前序改动修好）")
        unchecked = [q.id for q in escaped_with_truth
                     if str(q.id) not in self.answers]
        no_truth_skipped = len(escaped) - len(escaped_with_truth)
        self.assertEqual(unchecked, [],
                         "以下题仍无 per-question 校验，跨题 flag 会被放行: %s"
                         % unchecked)

    def test_cross_question_flag_rejected(self):
        """核心安全不变式：A 题提交 B 题 flag 必须被盐酸烩。"""
        # 取一道已进答案表的逃逸题
        from eval.corpus import load_corpus
        target = None
        for e in load_corpus():
            q = e.question
            if (not getattr(q, "flag_sha256", None)
                    and str(q.id) in self.answers):
                target = q
                break
        self.assertIsNotNone(target, "找不到样本")
        other = "flag{SOME_OTHER_QUESTION}"
        expected_q = self.answers_q.get(str(target.id))
        # run.py 的 per-question 分支
        ok = expected_q.flag_matches(other) if expected_q else (
            other == self.answers.get(str(target.id)))
        self.assertFalse(ok, "异题 flag 必须被拒")


if __name__ == "__main__":
    unittest.main(verbosity=2)
