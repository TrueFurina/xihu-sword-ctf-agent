"""跨项目审计脚本回归测试（真值源一致性 + LLM 评测池口径）。

守护两件事：
  1. 审计器本身能变红（否则"门禁恒 PASS"等于没有门禁——本项目的历史教训）；
  2. 严重度分级正确：自研题集保留明文答案=提示，外部来源题集明文答案=红线。
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ts = _load("_audit_truth_sources")
pool = _load("_audit_llm_pool")

SHA_A = "a" * 64
SHA_B = "b" * 64


def _bench(root: Path, name: str, problems: dict) -> None:
    d = root / "data" / "ctf_benchmark" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.json").write_text(
        json.dumps({"version": "t", "problems": problems}, ensure_ascii=False), encoding="utf-8")


class TestTruthSourceAudit(unittest.TestCase):
    def test_green_repo(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _bench(root, "clean_bench", {"q1": {"id": "q1", "description": "d",
                                                "flag_sha256": SHA_A}})
            rep = ts.audit(root)
            self.assertTrue(rep["all_green"], rep["checks"])

    def test_missing_truth_is_red(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _bench(root, "bad_bench", {"q1": {"id": "q1", "description": "d"}})
            rep = ts.audit(root)
            self.assertFalse(rep["all_green"])
            self.assertEqual(rep["checks"]["truth_not_verifiable"]["count"], 1)

    def test_plaintext_in_external_source_is_red(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _bench(root, "external_real", {"q1": {"id": "q1", "description": "d",
                                                  "flag_sha256": SHA_A,
                                                  "flag": "flag{leaked}"}})
            rep = ts.audit(root)
            self.assertFalse(rep["all_green"])
            self.assertEqual(rep["checks"]["plaintext_answer_leak_external"]["count"], 1)

    def test_plaintext_in_selfbuilt_is_hint_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _bench(root, "selfmade_bench", {"q1": {"id": "q1", "description": "d",
                                                   "source": "自研",
                                                   "flag_sha256": SHA_A,
                                                   "flag": "flag{selfbuilt}"}})
            rep = ts.audit(root)
            self.assertTrue(rep["all_green"], "自研题集明文答案不应判红线")
            self.assertEqual(rep["hints"]["selfbuilt_plaintext_answers"]["count"], 1)

    def test_truth_source_divergence_is_red(self):
        """真值源分裂：同 id 在两个文件里答案不同（2026-09-19 事故的近亲形态）。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _bench(root, "bench_a", {"q1": {"id": "q1", "description": "d", "flag_sha256": SHA_A}})
            _bench(root, "bench_b", {"q1": {"id": "q1", "description": "d", "flag_sha256": SHA_B}})
            rep = ts.audit(root)
            self.assertFalse(rep["all_green"])
            self.assertEqual(rep["checks"]["truth_source_divergence"]["count"], 1)

    def test_external_manifest_mismatch_is_red(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            d = root / "data" / "ctf_benchmark" / "external_x"
            d.mkdir(parents=True)
            (d / "benchmark.json").write_text(json.dumps(
                {"problems": {"q1": {"id": "q1", "flag_sha256": SHA_A}}}), encoding="utf-8")
            (d / "export_manifest.json").write_text(json.dumps({"included_count": 99}),
                                                    encoding="utf-8")
            rep = ts.audit(root)
            self.assertFalse(rep["all_green"])
            self.assertEqual(rep["checks"]["external_manifest_mismatch"]["count"], 1)


class TestLLMPoolAudit(unittest.TestCase):
    def _repo(self, td: str, cases: str, bench: dict | None) -> Path:
        root = Path(td)
        f = root / pool.POOL_FILE
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(cases, encoding="utf-8")
        if bench is not None:
            _bench(root, "bench", bench)
        return root

    def test_parses_pool_and_classifies_selfbuilt(self):
        cases = ('func newLiveCases() []liveCase { return []liveCase{'
                 '{id: "2001", title: "WEB-01", flag: "flag{live_a_ok}", handler: h},'
                 '{id: "2002", title: "WEB-02", flag: "flag{live_b_ok}", handler: h},} }')
        with tempfile.TemporaryDirectory() as td:
            root = self._repo(td, cases, None)
            rep = pool.audit(root)
            self.assertEqual(rep["pool_size"], 2)
            self.assertEqual(rep["overlap_with_benchmarks"], 0)
            self.assertTrue(rep["all_green"])
            self.assertFalse(rep["verdict"]["denominator_is_external_truth"],
                             "自建池不得被判为外部真题口径")

    def test_overlap_with_external_benchmark_is_red(self):
        import hashlib
        truth = hashlib.sha256(b"flag{live_a_ok}").hexdigest()
        cases = ('func newLiveCases() []liveCase { return []liveCase{'
                 f'{{id: "2001", title: "WEB-01", flag: "flag{{live_a_ok}}", handler: h}},}}')
        with tempfile.TemporaryDirectory() as td:
            root = self._repo(td, cases,
                              {"same": {"id": "same", "description": "d", "flag_sha256": truth}})
            rep = pool.audit(root)
            self.assertFalse(rep["all_green"], "评测池与外部基准重叠必须变红")
            self.assertEqual(rep["overlap_with_benchmarks"], 1)

    def test_duplicate_flag_is_red(self):
        cases = ('func newLiveCases() []liveCase { return []liveCase{'
                 '{id: "1", title: "A", flag: "flag{same}", handler: h},'
                 '{id: "2", title: "B", flag: "flag{same}", handler: h},} }')
        with tempfile.TemporaryDirectory() as td:
            root = self._repo(td, cases, None)
            rep = pool.audit(root)
            self.assertFalse(rep["all_green"])
            self.assertEqual(rep["duplicate_flags"], ["2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
