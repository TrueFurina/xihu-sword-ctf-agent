"""评测入口题库口径闸门（eval.corpus.apply_corpus_gate + benchmark CLI）回归。

覆盖（2026-10-07 建立）：
① skip_reason：可跑 / input-less / 无真值的三类判定；
② partition_measurable 分组正确性；
③ apply_corpus_gate：默认剔除不可测题，include_unmeasurable=True 须原样保留；
④ applicable_corpus_summary 按 reason 汇总；
⑤ **CLI 端到端**：默认跑 data/questions 必须剔除 input-less 题，
   --include-unmeasurable 必须恢复原始题数（防"开关注册了但逻辑没接上"）。

变异验证（已执行）：
  - M1：apply_corpus_gate 忽略 include_unmeasurable → ③ 的 2 个用例红；
  - M2：skip_reason 把 no_truth 判定删掉 → ① 的 no_truth 用例红；
  - M3：apply_corpus_gate 返回 keep 时忘了重算 raw_n → ③ 的 raw_n 用例红。
"""
import os
import subprocess
import sys
import unittest
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_CTF = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from eval.corpus import (  # noqa: E402
    applicable_corpus_summary, apply_corpus_gate, has_input, has_truth,
    partition_measurable, skip_reason,
)

_EXISTING = __file__  # 必定存在的真实文件


class _Q:
    def __init__(self, attachments=None, flag_sha256=None, flag=None, qid="q"):
        self.id = qid
        self.attachments = list(attachments or [])
        self.flag_sha256 = flag_sha256
        self.flag = flag
        self.description = "d" * 50


class TestSkipReason(unittest.TestCase):
    """① 三类判定。"""

    def test_runnable_returns_none(self):
        self.assertIsNone(skip_reason(_Q([_EXISTING], flag_sha256="a" * 64)))
        # 纯文本题（无附件）但**有真值** → 可跑
        self.assertIsNone(skip_reason(_Q(flag="CTF{x}")))

    def test_input_less_reason(self):
        """附件登记了但全不存在 → no_input（优先级高于 no_truth）。"""
        q = _Q(["/nonexistent/x.bin"])
        self.assertFalse(has_input(q))
        self.assertEqual(skip_reason(q), "no_input")

    def test_no_truth_reason(self):
        """有输入但无真值 → no_truth（解出也无法校验）。"""
        q = _Q([_EXISTING])
        self.assertTrue(has_input(q), "纯文本题/有附件 → 有输入")
        self.assertFalse(has_truth(q))
        self.assertEqual(skip_reason(q), "no_truth")

    def test_input_less_takes_precedence(self):
        """两者皆缺时报告 no_input（缺输入是更根本的缺陷）。"""
        self.assertEqual(skip_reason(_Q(["/nonexistent/x.bin"])), "no_input")


class TestPartition(unittest.TestCase):
    """② 分组正确性。"""

    def test_partition_splits_correctly(self):
        good = _Q([_EXISTING], flag_sha256="a" * 64, qid="good")
        bad = _Q(["/nope.bin"], flag_sha256="a" * 64, qid="bad")
        keep, skipped = partition_measurable([good, bad])
        self.assertEqual([q.id for q in keep], ["good"])
        self.assertEqual([(q.id, r) for q, r in skipped], [("bad", "no_input")])

    def test_empty_input(self):
        keep, skipped = partition_measurable([])
        self.assertEqual((keep, skipped), ([], []))
        self.assertEqual(partition_measurable(None)[0], [])


class TestApplyCorpusGate(unittest.TestCase):
    """③④ 入库闸门语义。"""

    def setUp(self):
        self.good = _Q([_EXISTING], flag_sha256="a" * 64, qid="good")
        self.bad = _Q(["/nope.bin"], flag_sha256="a" * 64, qid="bad")

    def test_default_drops_unmeasurable(self):
        keep, unmeasurable, raw_n = apply_corpus_gate([self.good, self.bad])
        self.assertEqual(raw_n, 2, "raw_n 必须是**过滤前**的原始题数")
        self.assertEqual(len(unmeasurable), 1)
        self.assertEqual([q.id for q in keep], ["good"])

    def test_include_unmeasurable_keeps_everything(self):
        keep, unmeasurable, raw_n = apply_corpus_gate(
            [self.good, self.bad], include_unmeasurable=True)
        self.assertEqual(len(keep), 2, "开关打开时必须原样保留")
        self.assertEqual(raw_n, 2)
        self.assertEqual(len(unmeasurable), 1, "被恢复的题仍应如实列出")

    def test_summary_counts_by_reason(self):
        no_truth = _Q([_EXISTING], qid="nt")
        _, unmeasurable, _ = apply_corpus_gate([self.bad, no_truth])
        self.assertEqual(applicable_corpus_summary(unmeasurable),
                         {"no_input": 1, "no_truth": 1})


class TestBenchmarkCLI(unittest.TestCase):
    """⑤ CLI 端到端：确认开关真的接进了 main()，而非仅仅注册了 argparse。"""

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, "-m", "eval.benchmark", "--mock", "--limit", "1"]
            + list(args),
            cwd=_CTF, capture_output=True, text=True, timeout=180,
            encoding="utf-8", errors="replace")
        return proc.stdout + proc.stderr

    @pytest.mark.local
    def test_default_gate_drops_input_less(self):
        """默认必须打印剔除统计（data/questions 里 27 题 input-less）。"""
        out = self._run()
        self.assertIn("剔除", out, "默认模式必须执行口径闸门")
        self.assertIn("有效分母", out)

    @pytest.mark.local
    def test_include_unmeasurable_restores(self):
        out = self._run("--include-unmeasurable")
        self.assertIn("恢复全部", out,
                      "--include-unmeasurable 必须走恢复分支")

    def test_corpus_switch_uses_cross_corpus(self):
        out = self._run("--corpus")
        self.assertIn("cross-corpus", out, "--corpus 必须走 load_corpus 分支")


if __name__ == "__main__":
    unittest.main()
