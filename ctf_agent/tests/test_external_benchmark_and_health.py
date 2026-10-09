"""外部未见题基准构建器 + 题库健康基线门禁 回归（2026-10-10）。

守护两条容易出事的性质：
1. **基准只收干净题**：载荷缺失 / 答案泄漏 / 无真值 / 已解出的题必须被排除；
   且重建时"已解出"集合会变（跑批 solved 记录进排除集）→ 分母缩小是正确行为。
2. **健康门禁只在变坏时红**：`questions_real` 有 77 道历史坏题，若按"坏题>0 即红"
   会天天假红；基线比对必须只报回归，否则护栏会被注释掉。
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


bench = _load("_build_external_benchmark")
health = _load("check_corpus_health")


class TestBenchmarkManifestRules(unittest.TestCase):
    def test_manifest_records_rules_and_ids(self):
        man = json.loads((ROOT / "benchmarks" / "external_unseen" / "MANIFEST.json")
                         .read_text(encoding="utf-8"))
        self.assertEqual(man["schema"], "external_unseen_benchmark/v1")
        self.assertTrue(man["selection_rules"], "选池规则必须落进清单，否则口径不可复现")
        self.assertEqual(man["total"], len(man["question_ids"]))
        self.assertIn("skipped", man)

    def test_no_plaintext_answers_in_benchmark(self):
        """反注水硬门：基准里不得出现明文答案，只有 64 位占位。"""
        import re
        for f in (ROOT / "benchmarks" / "external_unseen" / "questions").glob("*.json"):
            q = json.loads(f.read_text(encoding="utf-8"))
            self.assertRegex(q["flag_sha256"], r"^[0-9a-f]{64}$", f"{f.stem} 真值非法")
            self.assertEqual(q["flag"], q["flag_sha256"],
                             f"{f.stem}: flag 必须承载 sha256 占位而非明文")
            blob = json.dumps(q, ensure_ascii=False).replace("flag_sha256", "")
            self.assertNotRegex(blob, r"flag\{[^\}]{2,}\}", f"{f.stem} 疑似明文答案")

    def test_benchmark_attachments_exist(self):
        for f in (ROOT / "benchmarks" / "external_unseen" / "questions").glob("*.json"):
            q = json.loads(f.read_text(encoding="utf-8"))
            for a in q["attachments"]:
                self.assertTrue((ROOT / a).is_file(), f"{f.stem} 载荷缺失: {a}")

    def test_check_passes_on_current_disk(self):
        ok, problems = bench.check()
        self.assertTrue(ok, problems[:5])


class TestHealthBaselineGate(unittest.TestCase):
    def test_only_regressions_are_red(self):
        base = {"p": {"total": 10, "ok": 2, "leaky": 1, "broken": 7}}
        same = {"p": {"total": 10, "ok": 2, "leaky": 1, "broken": 7}}
        worse = {"p": {"total": 10, "ok": 1, "leaky": 1, "broken": 8}}
        better = {"p": {"total": 10, "ok": 3, "leaky": 1, "broken": 6}}
        self.assertEqual(health.compare(same, base)["regressions"], [])
        self.assertEqual(len(health.compare(worse, base)["regressions"]), 1)
        self.assertEqual(len(health.compare(better, base)["improvements"]), 1)

    def test_disappeared_pool_is_regression(self):
        base = {"p1": {"total": 3, "ok": 3, "leaky": 0, "broken": 0},
                "p2": {"total": 5, "ok": 5, "leaky": 0, "broken": 0}}
        cur = {"p1": base["p1"]}
        self.assertTrue(any("p2" in r for r in health.compare(cur, base)["regressions"]))

    def test_baseline_file_exists_and_covers_tracked_pools(self):
        b = ROOT / "benchmarks" / "corpus_health_baseline.json"
        self.assertTrue(b.is_file(), "缺基线文件，门禁会天天报'基线缺失'")
        pools = json.loads(b.read_text(encoding="utf-8"))["pools"]
        self.assertIn("questions_real", pools)
        # 已知历史坏题必须被基线记住，否则修复后无法体现改善
        self.assertGreater(pools["questions_real"]["broken"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
