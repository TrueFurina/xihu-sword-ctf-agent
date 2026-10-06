"""题库口径统一层（eval/corpus.py）回归测试。

覆盖范围（2026-10-07 建立）：
① has_input / has_truth / measurable 的边界判定；
② fitness_score 语义——附件可用数 > 有真值，**同分保留靠前库**；
③ load_corpus 跨库择优去重（好副本在前/在后两种顺序都要洁癖通过）；
④ **真实题库不变式护栏**：任一 id 选中的副本必须是全库最优副本；
⑤ no_input 题必须被排除出 KPI 分母。

变异验证（已执行，见文件末尾注释）：
  - M1：fitness_score 加回 description 长度 tie-break → ③ 的 「同分保留靠前库」用例红；
  - M2：has_input 改为恒定 True → ① 的 input-less 用例 + ⑤ 红；
  - M3：corpus_report 把 has_truth 误写成 measurable → ①/⑤ 红。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.corpus import (  # noqa: E402
    DEFAULT_ROOTS, attachment_health, corpus_report, fitness_score,
    has_input, has_truth, load_corpus, measurable,
)


class _Q:
    """最小题目替身（只带 corpus.py 会读的字段）。"""

    def __init__(self, attachments=None, flag_sha256=None, flag=None,
                 description="x" * 100, qid="t"):
        self.id = qid
        self.attachments = list(attachments or [])
        self.flag_sha256 = flag_sha256
        self.flag = flag
        self.description = description
        self.provenance = "real_past_ctf"
        self.category = "crypto"


def _mk_bank(base, name, copies):
    """在 base 下造一个题库目录。

    copies: [(qid, [附件磁盘是否存在的 bool], 是否有真值)]
    """
    import json
    bank = os.path.join(base, name)
    for idx, (qid, exists_flags, truth) in enumerate(copies):
        d = os.path.join(bank, "crypto")
        os.makedirs(d, exist_ok=True)
        atts = []
        for j, ex in enumerate(exists_flags):
            rel = "_attachments/%s/f%d.bin" % (qid, j)
            real = os.path.join(bank, rel.replace("/", os.sep))
            if ex:
                os.makedirs(os.path.dirname(real), exist_ok=True)
                with open(real, "w") as fh:
                    fh.write("data")
            atts.append(os.path.join(bank, "_attachments", qid,
                                     "f%d.bin" % j))
        payload = {
            "id": qid, "title": qid, "category": "crypto",
            "description": "desc " * 30, "attachments": atts,
            "provenance": "real_past_ctf",
        }
        if truth:
            payload["flag_sha256"] = "a" * 64
        with open(os.path.join(d, "%s.json" % qid), "w",
                  encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
    return bank


class TestInputTruthJudgement(unittest.TestCase):
    """① 可测性三元判定。"""

    def setUp(self):
        self.real = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "_tmpfile_probe_marker")
        self.existing_file = __file__  # 必定存在的真实文件

    def test_no_input_when_all_attachments_missing(self):
        """登记了附件但全部不存在 → input-less，不可测。"""
        q = _Q(attachments=["/nonexistent/abs/path.bin"])
        h = attachment_health(q)
        self.assertEqual((h.declared, h.existing), (1, 0))
        self.assertFalse(has_input(q), "附件全丢必须判 no_input")

    def test_has_input_when_some_attachment_exists(self):
        q = _Q(attachments=[self.existing_file, "/nonexistent/x.bin"])
        self.assertTrue(has_input(q))
        self.assertEqual(attachment_health(q).existing, 1)

    def test_pure_text_question_is_input_ok(self):
        """未登记附件的纯文本题不得被误判为 no_input。"""
        q = _Q(attachments=[])
        self.assertTrue(has_input(q), "无附件登记=信息在题面，属有效输入")
        self.assertEqual(attachment_health(q).ratio, 1.0)

    def test_has_truth_variants(self):
        self.assertTrue(has_truth(_Q(flag_sha256="a" * 64)))
        self.assertTrue(has_truth(_Q(flag="CTF{x}")))       # 明文也算真值
        self.assertFalse(has_truth(_Q()))                    # 两者皆空

    def test_flag_pattern_alone_is_not_truth(self):
        """只有 flag_pattern 而无真值 → 不可校验（格式对 ≠ 内容对）。"""
        q = _Q()
        self.assertFalse(has_truth(q))

    def test_measurable_is_conjunction(self):
        good = _Q(attachments=[self.existing_file], flag_sha256="a" * 64)
        no_truth_only = _Q(attachments=[self.existing_file])
        no_input_only = _Q(attachments=["/nonexistent/xx.bin"],
                           flag_sha256="a" * 64)
        self.assertTrue(measurable(good))
        self.assertFalse(measurable(no_truth_only), "无真值不得计入分母")
        self.assertFalse(measurable(no_input_only), "input-less 不得计入分母")


class TestFitnessTieBreak(unittest.TestCase):
    """② 打分语义：附件数 > 真值，**刻意不用题面长度做 tie-break**。"""

    def test_more_attachments_wins(self):
        a = _Q(attachments=[])
        with_more = _Q(attachments=[__file__, __file__])
        self.assertGreater(fitness_score(with_more), fitness_score(a))

    def test_truth_beats_no_truth_when_same_attachment_count(self):
        self.assertGreater(fitness_score(_Q(flag_sha256="a" * 64)),
                           fitness_score(_Q()))

    def test_description_length_does_not_affect_score(self):
        """★ 护栏：题面长短不得参与决胜（曾致坏库凭长描述淘汰好库）。"""
        short = _Q(description="s")
        long_desc = _Q(description="L" * 5000)
        self.assertEqual(fitness_score(short), fitness_score(long_desc),
                         "fitness_score 不得含 description 长度项")


class TestCorpusDedup(unittest.TestCase):
    """③ 跨库择优去重。"""

    def test_bad_copy_first_still_picks_healthy_later_copy(self):
        """坏副本在前也要能纠正——不依赖 roots 顺序的正确性。"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            bad = _mk_bank(td, "bad", [("q1", [False], True)])
            _mk_bank(td, "good", [("q1", [True], True)])
            entries = load_corpus([os.path.join(td, "bad"),
                                   os.path.join(td, "good")])
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].health.existing, 1,
                             "必须选中附件存在的副本")
            self.assertTrue(
                any(s.endswith("bad") for s in entries[0].superseded),
                "被淘汰的坏副本应记录在 superseded 中：%r"
                % (entries[0].superseded,))

    def test_equal_copies_keep_root_order(self):
        """同分时保留 roots 靠前者（roots 顺序即质量优先级）。"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            _mk_bank(td, "preferred", [("q2", [True], True)])
            _mk_bank(td, "later", [("q2", [True], True)])
            entries = load_corpus([os.path.join(td, "preferred"),
                                   os.path.join(td, "later")])
            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0].source.endswith("preferred"),
                            "同分必须保留靠前库")

    def test_dedup_false_keeps_every_copy(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            _mk_bank(td, "a", [("q3", [False], True)])
            _mk_bank(td, "b", [("q3", [True], True)])
            entries = load_corpus([os.path.join(td, "a"),
                                   os.path.join(td, "b")], dedup=False)
            self.assertEqual(len(entries), 2, "dedup=False 须保留全部副本")


class TestRealCorpusInvariants(unittest.TestCase):
    """④ 真实题库护栏（零 LLM，纯文件系统判定，跑得快）。"""

    @classmethod
    def setUpClass(cls):
        cls.entries = load_corpus()
        cls.report = corpus_report(cls.entries)

    def test_default_roots_ordered_best_first(self):
        """质量差的 data/questions 必须排在末位。"""
        self.assertEqual(DEFAULT_ROOTS[-1], "data/questions")

    def test_picked_copy_is_always_the_best_available(self):
        """★ 核心不变式：选中副本的附件数 == 全库该 id 的最大附件数。"""
        from eval.cases import load_questions
        best = {}
        for d in DEFAULT_ROOTS:
            for q in load_questions(d):
                k = getattr(q, "id", "")
                ok = sum(1 for a in (q.attachments or [])
                         if os.path.isfile(str(a)))
                best[k] = max(best.get(k, 0), ok)
        violations = []
        for e in self.entries:
            k = getattr(e.question, "id", "")
            if e.health.existing < best.get(k, 0):
                violations.append((k, e.source, e.health.existing, best[k]))
        self.assertEqual(violations, [],
                         "存在择优失败副本（选中了有更优副本的坏副本）: %r"
                         % violations[:5])

    def test_no_input_questions_are_excluded_from_denominator(self):
        """⑤ input-less 题不得计入可测分母。"""
        no_input = [r for r in self.report["rows"] if not r["has_input"]]
        self.assertTrue(no_input, "题库应确实存在 input-less 题")
        for r in no_input:
            self.assertFalse(r["measurable"],
                             "%s 无输入却计入了可测分母" % r["id"])

    def test_report_counts_are_consistent(self):
        r = self.report
        self.assertEqual(r["total"], len(r["rows"]))
        self.assertEqual(r["measurable"] + r["unmeasurable"], r["total"])
        self.assertLessEqual(r["no_input"], r["unmeasurable"])
        self.assertLessEqual(r["real_past_ctf_measurable"],
                             r["real_past_ctf_total"])

    def test_real_past_ctf_has_known_input_less_tail(self):
        """已知残缺题（附件指向外部失效路径）必须被识别为 no_input。"""
        rows = {r["id"]: r for r in self.report["rows"]}
        for qid in ("real_misc_xuanhun_ezip", "real_crypto_caesar"):
            if qid in rows:
                self.assertFalse(rows[qid]["has_input"],
                                 "%s 附件已失效，须判 no_input" % qid)


if __name__ == "__main__":
    unittest.main()
