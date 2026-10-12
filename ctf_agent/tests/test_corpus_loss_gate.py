"""题库健康门禁「数据丢失」检测回归（2026-10-12）。

背景：原门禁只比对 `broken` 计数，题目定义 JSON 被整体删除时该题不再进入审计
⇒ `total` 下降而 `broken` 不升反降 ⇒ **数据丢失被误读为「改善」或完全无感**。
本文件守护新增的 `detect_corpus_loss()`，并确认 `compare()` 既有契约未被改动。

零外部依赖、零网络、不依赖真实磁盘题库（用构造数据 + 临时基线）。
"""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


health = _load("check_corpus_health")


class TestCorpusLossDetection(unittest.TestCase):
    def test_total_shrink_is_regression(self):
        base = {"p": {"total": 10, "ok": 8, "leaky": 0, "broken": 2}}
        cur = {"p": {"total": 6, "ok": 6, "leaky": 0, "broken": 0}}
        msgs, pools = health.detect_corpus_loss(cur, base)
        self.assertEqual(pools, {"p"})
        self.assertTrue(any("缩水" in m for m in msgs), msgs)

    def test_full_pool_wipe_is_regression(self):
        """整池归零（broken 恒 0）——原门禁完全无感，现必须报警。"""
        base = {"questions_ext_cybench": {"total": 13, "ok": 11, "leaky": 2, "broken": 0}}
        cur = {"questions_ext_cybench": {"total": 0, "ok": 0, "leaky": 0, "broken": 0}}
        msgs, pools = health.detect_corpus_loss(cur, base)
        self.assertEqual(pools, {"questions_ext_cybench"})
        self.assertTrue(msgs)

    def test_ok_drop_without_total_change_is_regression(self):
        base = {"p": {"total": 10, "ok": 8, "leaky": 0, "broken": 2}}
        cur = {"p": {"total": 10, "ok": 5, "leaky": 0, "broken": 5}}
        msgs, pools = health.detect_corpus_loss(cur, base)
        self.assertEqual(pools, {"p"})

    def test_no_loss_when_equal(self):
        base = {"p": {"total": 10, "ok": 8, "leaky": 0, "broken": 2}}
        self.assertEqual(health.detect_corpus_loss(dict(base), base), ([], set()))

    def test_growth_is_not_loss(self):
        base = {"p": {"total": 10, "ok": 8, "leaky": 0, "broken": 2}}
        cur = {"p": {"total": 12, "ok": 10, "leaky": 0, "broken": 2}}
        self.assertEqual(health.detect_corpus_loss(cur, base), ([], set()))

    def test_disappeared_pool_not_double_counted(self):
        """整池消失由 compare() 既有判据覆盖，loss 检测不重复报。"""
        base = {"p1": {"total": 3, "ok": 3, "leaky": 0, "broken": 0},
                "p2": {"total": 5, "ok": 5, "leaky": 0, "broken": 0}}
        cur = {"p1": base["p1"]}
        _, pools = health.detect_corpus_loss(cur, base)
        self.assertNotIn("p2", pools)

    def test_compare_contract_unchanged(self):
        """回归保护：loss 判据不得被塞进 compare()（否则既有测试会红）。"""
        base = {"p": {"total": 10, "ok": 2, "leaky": 1, "broken": 7}}
        worse = {"p": {"total": 10, "ok": 1, "leaky": 1, "broken": 8}}
        self.assertEqual(len(health.compare(worse, base)["regressions"]), 1)


class TestMainEndToEnd(unittest.TestCase):
    def _run_main(self, cur, base_pools, extra=None):
        orig = (health.snapshot, health.benchmark_ok, health.BASELINE, sys.argv)
        try:
            with tempfile.TemporaryDirectory() as td:
                bl = Path(td) / "b.json"
                bl.write_text(json.dumps({"pools": base_pools}), encoding="utf-8")
                health.BASELINE = bl
                health.snapshot = lambda: cur          # noqa: E731
                health.benchmark_ok = lambda: (True, "OK")  # noqa: E731
                sys.argv = ["check_corpus_health.py"] + list(extra or [])
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = health.main()
                return rc, buf.getvalue()
        finally:
            health.snapshot, health.benchmark_ok, health.BASELINE, sys.argv = orig

    def test_shrunk_pool_warns_without_blocking_by_default(self):
        """questions_ext 型场景：坏题 3→0 + total 37→17 ⇒ 不报「改善」，报警告；
        默认**不阻断**（保持既有阻断语义，不引入新的红）。"""
        base = {"questions_ext": {"total": 37, "ok": 33, "leaky": 1, "broken": 3}}
        cur = {"questions_ext": {"total": 17, "ok": 17, "leaky": 0, "broken": 0}}
        rc, out = self._run_main(cur, base)
        self.assertEqual(rc, 0, out)
        self.assertIn("缩水", out)
        self.assertIn("⚠️", out)
        self.assertNotIn("改善", out, "池缩水时不得误报改善")

    def test_strict_loss_blocks(self):
        """--strict-loss：数据丢失转为阻断回归（exit 1）。"""
        base = {"questions_ext": {"total": 37, "ok": 33, "leaky": 1, "broken": 3}}
        cur = {"questions_ext": {"total": 17, "ok": 17, "leaky": 0, "broken": 0}}
        rc, out = self._run_main(cur, base, extra=["--strict-loss"])
        self.assertEqual(rc, 1, out)
        self.assertIn("缩水", out)

    def test_healthy_snapshot_is_green(self):
        base = {"p": {"total": 10, "ok": 8, "leaky": 0, "broken": 2}}
        rc, out = self._run_main({"p": {"total": 10, "ok": 8, "leaky": 0, "broken": 2}}, base)
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
