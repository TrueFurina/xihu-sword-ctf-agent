"""跑批有效性门禁回归（2026-10-10）。

这个门禁的诞生源于两次真实的口径污染：
  1. deepseek 中途 402 余额不足 → 39/69 题死于熔断，解出率会被误读成模型能力；
  2. xfyun 235 步 0 次工具调用 → 0 解出，这是"模型用不了 agent 循环"，不是"密码弱"。

守护三条：基础设施失败超阈值 → 判不可用；解出全来自确定性兜底 → 判不可用并提示虚高；
provider 快照读取必须按真实 schema（llm_pool_probe/v1 的 providers.*.ok）。
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("guard", ROOT / "scripts" / "_run_validity_guard.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def _report(results: list) -> str:
    return json.dumps({"results": results, "summary": {}}, ensure_ascii=False)


class TestAssess(unittest.TestCase):
    def test_clean_run_is_valid(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td); (d / "benchmark_report.json").write_text(_report([
                {"question_id": "a", "solved": True, "solved_by": "main_agent_llm"},
                {"question_id": "b", "solved": False, "error": "wrong_direction"},
            ]), encoding="utf-8")
            rep = g.assess(d)
            self.assertTrue(rep["valid"], rep["reasons"])
            self.assertEqual(rep["stats"]["llm_independent_solved"], 1)

    def test_circuit_open_heavy_run_is_invalid(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            res = [{"question_id": f"q{i}", "solved": False, "error": "provider_circuit_open"}
                   for i in range(9)]
            res.append({"question_id": "ok", "solved": True, "solved_by": "main_agent_llm"})
            (d / "benchmark_report.json").write_text(_report(res), encoding="utf-8")
            rep = g.assess(d)
            self.assertFalse(rep["valid"])
            self.assertTrue(any("基础设施" in r for r in rep["reasons"]))

    def test_deterministic_only_solves_flag_inflation(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td); (d / "benchmark_report.json").write_text(_report([
                {"question_id": "a", "solved": True, "solved_by": "presolve"},
                {"question_id": "b", "solved": True, "solved_by": "presolve"},
            ]), encoding="utf-8")
            rep = g.assess(d)
            self.assertFalse(rep["valid"], "确定性兜底独扛必须判不可用")
            self.assertTrue(any("虚高" in r for r in rep["reasons"]))

    def test_split_caliber_numbers(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td); (d / "benchmark_report.json").write_text(_report([
                {"question_id": "a", "solved": True, "solved_by": "presolve"},
                {"question_id": "b", "solved": True, "solved_by": "main_agent_llm"},
                {"question_id": "c", "solved": False, "error": "unresolved"},
            ]), encoding="utf-8")
            st = g.assess(d)["stats"]
            self.assertEqual(st["solved"], 2)
            self.assertEqual(st["deterministic_fallback_solved"], 1)
            self.assertEqual(st["llm_independent_solved"], 1)


class TestProviderLive(unittest.TestCase):
    def test_reads_real_probe_schema(self):
        """回归点：初版读 alive/available 顶层键 → 永远假红。真实 schema 是 providers.*.ok。"""
        import time
        snap_dir = ROOT / "logs" / "llm_probe"
        if not snap_dir.is_dir() or not list(snap_dir.glob("*.json")):
            self.skipTest("无探测快照")
        newest = max(snap_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        data = json.loads(newest.read_text(encoding="utf-8"))
        provs = data.get("providers") or {}
        if not provs:
            self.skipTest("快照无 providers 段")
        alive = {k for k, v in provs.items() if v.get("ok")}
        ok, detail = g.provider_live(next(iter(provs)))
        self.assertEqual(ok, provs[next(iter(provs))].get("ok", False) is True,
                         f"判定与快照不符: {detail}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
