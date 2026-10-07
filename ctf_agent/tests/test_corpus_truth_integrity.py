r"""题库真值完整性护栏：裁判必须「看得见」，且同一题不许有两个答案。

为什么需要这个测试（2026-10-08 审计）
────────────────────────────────────
eval/corpus.py 收口后，跑批之前先经可测性闸门（`apply_corpus_gate`）放行题库，
再交给生产裁判（`answer_book()` → run.build_solver）判对错。这两层是**独立**的，
于是存在两种「静默失真」——不出错、不红测试，只是数字悄悄变错：

  ① 能跑但判不出来：某题通过了可测性闸门（会被真跑、进分母），
     但它的真值不在答案表里 → 无论模型解得多好，is_correct 都判不对，
     恒记 0 分。表面看是「模型没解出来」，实际是裁判瞎了。
  ② 同一题两个答案：同一 id 在不同数据集副本上写着不同的明文/不同的 sha256。
     此时「谁是真值」取决于 load_corpus 择优挑到哪份副本 ——
     分数会随无关改动漂移，且无从察觉。

2026-10-08 实测：**两种问题当前都是 0**（语料 210 / 闸门放行 186 / 答案表有真值 210；
明文 id 54 无冲突、sha256 id 162 无冲突）。这个测试是把「当前干净」钉住，
将来谁往题库里塞了冲突真值或漏配真值，立刻红，而不是让分数悄悄失真。

刻意的设计选择
──────────────
- **不锁计数**（54 / 186 / 210 都不写死）：计数会随数据集增删漂移，锁了就得天天改，
  改着改着就变成了「为了让测试通过而改数字」——那正是本项目打了好几轮的假水位。
  这里只锁**不变式**：看得见、不冲突。
- 判定的真值提取口径与 eval.corpus 保持一致：**明文优先**，
  认不出明文的（sha256 占位串）再看 flag_sha256 / expected_sha256。

2026-10-08 实测基线：语料 210 / 闸门放行 186 / 答案表有真值 210；
明文 id 54、sha256 id 162，**两类冲突均 0**。

变异验证（已做，结果如实记录）
────────────────────────────
  M1  answer_book 缩到只读第一个库（裁判半瞎）→ **1 failed**
      （`test_every_admitted_question_is_visible_to_judge`，抓到 94 道题失明）。
  M2  find_conflicts 恒返回空 → **2 failed**，且是被**合成自检用例**抓住的 ——
      这正说明那段自检不是装饰：真实题库当前零冲突，若只跑真数据，
      M2 这种「探测器写坏」的变异体会存活，护栏沦为橡皮图章。
  两个变异体均已还原，grep MUTANT 无残留，eval/corpus.py 已回到 HEAD（diff 为空）。
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.dirname(_HERE)
if _CTF not in sys.path:
    sys.path.insert(0, _CTF)

from eval.corpus import (  # noqa: E402
    DEFAULT_ROOTS,
    answer_book,
    apply_corpus_gate,
    load_corpus,
    load_questions,
    _looks_like_sha256,
)


def _plain_truth(question):
    """明文优先：flag 字段是真明文才认，sha256 占位串不算（与 corpus 同口径）。"""
    f = getattr(question, "flag", None)
    if f and not _looks_like_sha256(f):
        return str(f)
    for attr in ("flag_sha256", "expected_sha256"):
        v = getattr(question, attr, None)
        if v:
            return str(v)
    return None


def index_truths(by_root):
    """把 {root: [question]} 索引成 {id: {root: truth}}，跳过无真值的题。"""
    indexed = {}
    for root, qs in by_root.items():
        for q in qs or []:
            key = str(getattr(q, "id", ""))
            value = _plain_truth(q)
            if value is None:
                continue
            indexed.setdefault(key, {})[root] = value
    return indexed


def find_conflicts(indexed, want_plain):
    """从索引里挑出跨副本真值不一致的 id。独立成纯函数以便用合成数据自检。"""
    out = {}
    for key, per_root in indexed.items():
        values = list(per_root.values())
        if want_plain:
            values = [v for v in values if not _looks_like_sha256(v)]
        else:
            values = [v for v in values if _looks_like_sha256(v)]
        if len(set(values)) > 1:
            out[key] = per_root
    return out


class _FakeQ:
    """够用的假 Question：只需要 id / flag / flag_sha256 / expected_sha256。"""

    def __init__(self, qid, flag=None, flag_sha256=None, expected_sha256=None):
        self.id = qid
        self.flag = flag
        self.flag_sha256 = flag_sha256
        self.expected_sha256 = expected_sha256


class TestJudgeVisibility(unittest.TestCase):
    """① 通过闸门的题，真值必须能被裁判看到。"""

    @classmethod
    def setUpClass(cls):
        entries = load_corpus()
        cls.questions = [e.question for e in entries]
        cls.kept, cls.dropped, cls.raw_n = apply_corpus_gate(cls.questions)
        _answers, cls.answers_q = answer_book()

    def test_gate_admits_questions(self):
        """防护：语料为空时下面的「0 不可见」会假绿，必须先验放行集非空。"""
        self.assertTrue(self.raw_n > 0, "语料为空，无法判定（测试本身失真）")
        self.assertTrue(len(self.kept) > 0,
                        "闸门把所有题都剔除了，无法判定（测试本身失真）")

    def test_every_admitted_question_is_visible_to_judge(self):
        invisible = [str(q.id) for q in self.kept if str(q.id) not in self.answers_q]
        self.assertEqual(
            invisible, [],
            "以下 %d 道题通过了可测性闸门（会进分母、会被真跑），但生产答案表看不见"
            "它们的真值 → 解对了也恒判 0 分（假性缺陷）：%s"
            % (len(invisible), invisible[:10]))


class TestTruthConsistency(unittest.TestCase):
    """② 同一 id 在不同数据集副本上不得有不同真值。"""

    @classmethod
    def setUpClass(cls):
        cls.by_root = {}
        for root in DEFAULT_ROOTS:
            try:
                cls.by_root[root] = load_questions(root)
            except Exception:  # noqa: BLE001 - 单库不可读由 corpus 层负责
                cls.by_root[root] = []
        cls.indexed = index_truths(cls.by_root)

    def _collect(self, want_plain):
        return find_conflicts(self.indexed, want_plain)

    def test_no_conflicting_plaintext_flags(self):
        bad = self._collect(want_plain=True)
        self.assertEqual(bad, {},
                         "同一 id 在不同数据集写着不同的明文 flag → 真值由「择优挑到哪份副本」"
                         "决定，分数会静默漂移：%s" % list(bad)[:10])

    def test_no_conflicting_sha256_truths(self):
        bad = self._collect(want_plain=False)
        self.assertEqual(bad, {},
                         "同一 id 在不同数据集写着不同的 sha256 真值 → 判题基准不自洽：%s"
                         % list(bad)[:10])

    def test_default_roots_not_empty(self):
        """防护：若 DEFAULT_ROOTS 被改小，上面的冲突检测会退化成「永远 0 冲突」。"""
        self.assertTrue(len(DEFAULT_ROOTS) >= 2,
                        "DEFAULT_ROOTS 少于 2 个库，跨库冲突检测已失效")
        loaded = sum(1 for qs in self.by_root.values() if qs)
        self.assertTrue(loaded >= 2,
                        "实际可读的数据集不足 2 个（%d），冲突检测已失效" % loaded)

    def test_indexed_truths_not_empty(self):
        """防护：索引为空时 ①② 会假绿（0 冲突是因为没数据可查，不是因为一致）。"""
        self.assertTrue(self.indexed, "真值索引为空，冲突结论不可信（测试本身失真）")


class TestConflictDetectorSelfCheck(unittest.TestCase):
    """用合成冲突自检探测器本身。

    为什么必须有这一段（诚实边界）：当前真实题库里**没有**真值冲突，于是
    冲突检测无论写得多弱（比如把 True 直接 return 空 dict）在全真数据上都会绿 ——
    那是**杀不死变异体的橡皮图章**。注入一个已知冲突，才能证明探测器真的在工作。
    """

    def test_detects_plaintext_conflict(self):
        by_root = {
            "A": [_FakeQ("dup_1", flag="flag{aaa}")],
            "B": [_FakeQ("dup_1", flag="flag{bbb}")],
        }
        bad = find_conflicts(index_truths(by_root), want_plain=True)
        self.assertEqual(list(bad), ["dup_1"],
                         "注入的明文冲突未被检出 —— 冲突检测形同虚设")

    def test_detects_sha256_conflict(self):
        sha_a = "a" * 64
        sha_b = "b" * 64
        by_root = {
            "A": [_FakeQ("dup_2", flag_sha256=sha_a)],
            "B": [_FakeQ("dup_2", flag_sha256=sha_b)],
        }
        bad = find_conflicts(index_truths(by_root), want_plain=False)
        self.assertEqual(list(bad), ["dup_2"],
                         "注入的 sha256 冲突未被检出 —— 冲突检测形同虚设")

    def test_placeholder_vs_plaintext_is_not_a_conflict(self):
        """占位串 vs 明文是已知的良性组合（占位只作退化），不得报冲突。

        这一条正好对应真实题库里那 7 个 id：questions_real 的 flag 字段是 sha256
        占位、data/questions 才是真明文 —— 明文优先把它们化解了，属正常现象。
        """
        by_root = {
            "A": [_FakeQ("ok_1", flag="f" * 64)],          # 占位串
            "B": [_FakeQ("ok_1", flag="flag{real_one}")],  # 真明文
        }
        self.assertEqual(find_conflicts(index_truths(by_root), want_plain=True), {})
        self.assertEqual(find_conflicts(index_truths(by_root), want_plain=False), {})


if __name__ == "__main__":
    unittest.main()
