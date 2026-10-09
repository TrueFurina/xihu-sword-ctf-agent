"""provider 能力档案 · 归档聚合器 回归（2026-10-10）。

这个聚合器替代了"单题现跑"探针：单样本探针首测显示 glm 与 xfyun 在同一道题上
都是 0 解析失败，说明单样本不足以支撑 provider 选型。本测试守护四条性质：

1. **`unknown` 桶绝不参与推荐**——2026-10-10 实测踩坑：靠目录名猜 provider 时，
   最大的两个 run（69 题/78 题）目录名里没有 provider 字样，全部落进 unknown 桶
   （253 题=最大桶），聚合器一度把"归属不明"的最大桶当推荐对象（它的 LLM 独立率
   0.107 恰好是全场最高，数字最漂亮、实际无归属）——这是最坏的一种错。
2. **legacy 引擎轮不进 provider 汇总**（引擎有已知 P0 bug 的历史版本，混算等于
   把一个失效版本的能力算进 provider 表现）。
3. **基础设施失败不算能力**：provider_circuit_open 等不计入有效测量分母。
4. **引擎整体解出率与 LLM 独立解出率必须分开**（确定性兜底会把 LLM 能力虚高数倍：
   10-10 实测 53.3% vs 2/30=6.7%）。
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "arch", ROOT / "scripts" / "_provider_capability_archive.py")
arch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arch)


def _write_run(d: Path, name: str, results: list, tokens: dict | None = None) -> None:
    rd = d / name
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "benchmark_report.json").write_text(json.dumps({
        "results": results,
        "summary": {"total": len(results),
                    "solved": sum(1 for r in results if r.get("solved")),
                    "tokens": {"global_total": 1000,
                               "per_question": tokens or {}}},
    }, ensure_ascii=False), encoding="utf-8")


class TestProviderAttribution(unittest.TestCase):
    def test_explicit_override_wins_over_name_guess(self):
        """目录名没有 provider 字样时，靠显式映射归桶。"""
        self.assertEqual(arch.infer_provider("unseen86_pure_llm_20261010"), "deepseek")
        self.assertEqual(arch.infer_provider("L2_pure_llm_20261006"), "deepseek")

    def test_name_guess_as_fallback(self):
        self.assertEqual(arch.infer_provider("unseen69_xfyun_20261010"), "xfyun")
        self.assertEqual(arch.infer_provider("heldout_a5_glm47_paid"), "glm")

    def test_unknown_when_no_evidence(self):
        """无法归因时返回 unknown 而不是瞎猜一个。"""
        self.assertEqual(arch.infer_provider("some_random_dir_20260101"), "unknown")


class TestAggregation(unittest.TestCase):
    def _agg(self, runs):
        return arch.aggregate(runs)

    def test_unknown_bucket_excluded_from_recommendation(self):
        """🔴 回归点（2026-10-10 变异 M1 存活后重写）。

        初版这条测试造了个 unknown run + 一个 3 题的 glm run，指望"glm 样本不足自然不入选"
        来反证 unknown 不会成为推荐。实测**变异 M1（放开 unknown 参与推荐）后 12 例仍全绿**
        ——因为 confidence 门槛先一步把 glm 挡住了，断言根本没咬到 exclude 那条分支，
        等于给了一条永远为真的假护栏（㉚ 铁律第三例）。

        现在改成**唯一候选就是 unknown**：把它抬到 high confidence + 零基础设施失败 +
        全场最高的 LLM 独立率，若 exclude 规则失效，它必然成为推荐。
        """
        runs = [
            {"run": "mystery_run", "provider": "unknown", "total": 100,
             "valid_measured": 100, "infra_failed": 0, "solved": 30,
             "llm_independent_solved": 30, "deterministic_fallback_solved": 0,
             "tokens_total": 10, "tokens_per_solved_mean": 1.0,
             "tokens_per_valid_mean": 100.0},
        ]
        agg, _ = self._agg(runs)
        unk = next(e for e in agg if e["provider"] == "unknown")
        # 数字漂亮到"任何排序都会选它"，唯一拦住它的只能是 exclude 规则
        self.assertEqual(unk["llm_independent_rate"], 0.3)
        self.assertEqual(unk["infra_failure_rate"], 0.0)
        self.assertTrue(unk["excluded_from_recommendation"])
        rec = arch.recommend(agg)
        self.assertIsNone(rec["recommended"],
                          "归属不明的桶即使数字最漂亮也不得成为推荐")

    def test_unknown_confidence_label_is_unattributed(self):
        runs = [{"run": "mystery_run", "provider": "unknown", "total": 100,
                 "valid_measured": 100, "infra_failed": 0, "solved": 30,
                 "llm_independent_solved": 30, "deterministic_fallback_solved": 0,
                 "tokens_total": 10, "tokens_per_solved_mean": 1.0,
                 "tokens_per_valid_mean": 100.0}]
        agg, _ = self._agg(runs)
        # 不能标成 high：它连 provider 归属都不确定，凭什么有"高置信"
        self.assertEqual(agg[0]["confidence"], "unattributed")

    def test_legacy_runs_excluded_from_provider_totals(self):
        runs = [
            {"run": "heldout_rerun20260919_deepseek_full", "provider": "deepseek",
             "total": 10, "valid_measured": 10, "infra_failed": 0, "solved": 1,
             "llm_independent_solved": 0, "deterministic_fallback_solved": 1,
             "tokens_total": 1, "tokens_per_solved_mean": 1.0,
             "tokens_per_valid_mean": 1.0},
            {"run": "unseen86_pure_llm_20261010", "provider": "deepseek",
             "total": 69, "valid_measured": 30, "infra_failed": 39, "solved": 16,
             "llm_independent_solved": 2, "deterministic_fallback_solved": 14,
             "tokens_total": 1, "tokens_per_solved_mean": 500.0,
             "tokens_per_valid_mean": 3000.0},
        ]
        agg, legacy = self._agg(runs)
        self.assertEqual([r["run"] for r in legacy],
                         ["heldout_rerun20260919_deepseek_full"])
        ds = next(e for e in agg if e["provider"] == "deepseek")
        self.assertEqual(ds["questions_measured"], 69, "legacy 轮不得计入汇总")

    def test_infra_failures_excluded_from_valid_denominator(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write_run(d, "unseen86_pure_llm_20261010", [
                {"question_id": "a", "solved": True, "solved_by": "main_agent_llm"},
                {"question_id": "b", "solved": False, "error": "provider_circuit_open"},
                {"question_id": "c", "solved": False, "error": "provider_circuit_open"},
                {"question_id": "d", "solved": False, "error": "wrong_direction"},
            ], {"a": 600, "d": 1800})
            runs = arch.collect(d)
            r = runs[0]
            self.assertEqual(r["total"], 4)
            self.assertEqual(r["infra_failed"], 2)
            self.assertEqual(r["valid_measured"], 2)
            self.assertAlmostEqual(r["infra_failed"] / r["total"], 0.5)

    def test_engine_and_llm_rates_are_separate(self):
        """确定性兜底解出不得计入 LLM 独立解出（否则虚高数倍）。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write_run(d, "unseen86_pure_llm_20261010", [
                {"question_id": f"q{i}", "solved": True, "solved_by": "presolve"}
                for i in range(3)
            ] + [{"question_id": "x", "solved": True, "solved_by": "main_agent_llm"}])
            r = arch.collect(d)[0]
            self.assertEqual(r["solved"], 4)
            self.assertEqual(r["llm_independent_solved"], 1)
            self.assertEqual(r["deterministic_fallback_solved"], 3)


class TestRecommend(unittest.TestCase):
    def test_refuses_when_all_providers_dirty(self):
        agg = [{"provider": "a", "confidence": "high", "questions_measured": 50,
                "runs": 3, "infra_failure_rate": 0.8, "llm_independent_rate": 0.1,
                "tokens_per_valid_mean": 100, "valid_measured": 50,
                "excluded_from_recommendation": False}]
        rec = arch.recommend(agg)
        self.assertIsNone(rec["recommended"])
        self.assertIn("充值", rec["why"])

    def test_low_confidence_never_recommended(self):
        agg = [{"provider": "a", "confidence": "low", "questions_measured": 2,
                "runs": 1, "infra_failure_rate": 0.0, "llm_independent_rate": 0.5,
                "tokens_per_valid_mean": 10, "valid_measured": 2,
                "excluded_from_recommendation": False}]
        self.assertIsNone(arch.recommend(agg)["recommended"])

    def test_prefers_high_llm_rate_then_cheaper(self):
        agg = [
            {"provider": "cheap0", "confidence": "high", "questions_measured": 60,
             "runs": 3, "infra_failure_rate": 0.0, "llm_independent_rate": 0.0,
             "tokens_per_valid_mean": 1000, "valid_measured": 60,
             "excluded_from_recommendation": False},
            {"provider": "good", "confidence": "high", "questions_measured": 200,
             "runs": 10, "infra_failure_rate": 0.18, "llm_independent_rate": 0.11,
             "tokens_per_valid_mean": 58000, "valid_measured": 174,
             "excluded_from_recommendation": False},
        ]
        self.assertEqual(arch.recommend(agg)["recommended"], "good")


class TestSchemaGuardBlocksHeterogeneousOverwrite(unittest.TestCase):
    """🔴 回归点（2026-10-10 数据丢失事故）：v2 覆盖 v1 档案。

    v1 单题探针档案与 v2 归档档案曾**共用** `benchmarks/provider_capability.json`。
    v2 跑一次就把 v1 的探针数据（解析失败数/兜底次数/步数）整段覆盖掉——
    工作树上无声丢数据，只在 git 历史里还找得回来。这是"交付物静默腐烂"的同型：
    两种 schema 挤在一个文件名里，后跑的永远是赢家，先跑的结论无声消失。

    守护两条：①写前 schema 不一致必须拒绝覆盖（退出码非 0 /抛 SystemExit）
    ②同 schema 刷新才允许（档案要能更新，不能一次写死就不许再写）。
    """

    def _run_agg_into(self, path: Path, existing_schema: str | None) -> int:
        if existing_schema is not None:
            path.write_text(json.dumps({"schema": existing_schema,
                                        "old": True}), encoding="utf-8")
        import subprocess
        import sys
        r = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "_provider_capability_archive.py"),
             "--results-dir", str(path.parent), "--out", str(path)],
            capture_output=True, text=True)
        return r.returncode

    def test_refuses_to_overwrite_foreign_schema(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "provider_capability.json"
            out.write_text(json.dumps({"schema": "provider_capability/v1",
                                       "profiles": ["keepme"]}), encoding="utf-8")
            rc = self._run_agg_into(out, None)
            # 拒绝覆盖：档案内容必须原封不动
            data = json.loads(out.read_text(encoding="utf-8"))
            # 整个文件必须原封不动（含旧字段），一个字节都没被改写
            self.assertEqual(data, {"schema": "provider_capability/v1",
                                    "profiles": ["keepme"]})
            # 🔴 专属退出码 4：不能只断言"非 0"——"目录无 run 产物"也是非 0，
            # 那样删掉守卫后断言照样通过（变异存活）。必须精确咬住 4。
            self.assertEqual(rc, 4, "拒绝覆盖必须用专属退出码 4（与其它失败原因区分）")

    def test_guard_fires_even_when_no_runs_found(self):
        """🔴 回归点（2026-10-10 变异 M2 存活后补）：守卫必须**先于**产物收集。

        初版把守卫放在 collect() 之后，于是"目录里没有 run 产物"时脚本提前 return 1，
        永远走不到守卫——守卫看起来存在，在真实调用路径上却不会触发。
        本用例构造「有异构档案 + 空产物目录」：这正是最容易绕过守卫的组合，
        守卫必须仍然拒绝覆盖（rc=4），而不是返回 1（"无产物"）后放行。
        """
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "provider_capability.json"
            out.write_text(json.dumps({"schema": "provider_capability/v1",
                                       "old": True}), encoding="utf-8")
            rc = self._run_agg_into(out, None)
            self.assertEqual(rc, 4,
                             "空产物目录也必须先触发 schema 守卫，而不是被'无产物'提前返回绕过")
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["schema"],
                             "provider_capability/v1")

    def test_same_schema_refresh_is_allowed(self):
        """同 schema 必须允许刷新——否则档案一次写死就再也不能更新，
        "守卫"会退化成"冻结"（另一个方向的假门禁）。"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "provider_capability.json"
            out.write_text(json.dumps({"schema": "provider_capability_archive/v2"}),
                           encoding="utf-8")
            rc = self._run_agg_into(out, None)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], "provider_capability_archive/v2")
            # 临时目录里没有 run 产物 → 脚本提前退出（rc=1）且不写档案，
            # 这里的断言是"旧档案未被异构内容污染"，而不是"新档案已生成"。
            self.assertEqual(data, {"schema": "provider_capability_archive/v2"})
            self.assertNotEqual(rc, 4, "同 schema 刷新不得触发守卫（否则守卫退化成冻结）")


class TestProbeAndArchiveUseDistinctFiles(unittest.TestCase):
    """两个 provider 档案必须落在**不同文件**，否则重演覆盖事故。"""

    def test_output_paths_differ(self):
        probe_src = (ROOT / "scripts" / "_provider_toolcap_probe.py").read_text(
            encoding="utf-8")
        arch_src = (ROOT / "scripts" / "_provider_capability_archive.py").read_text(
            encoding="utf-8")
        self.assertIn("provider_probe.json", probe_src)
        self.assertNotIn('OUT = ROOT / "benchmarks" / "provider_capability.json"',
                         probe_src, "探针不得再写归档器的文件名")
        self.assertIn("provider_capability.json", arch_src)

    def test_both_archives_exist_with_distinct_schemas(self):
        pb = ROOT / "benchmarks" / "provider_probe.json"
        pc = ROOT / "benchmarks" / "provider_capability.json"
        self.assertTrue(pb.is_file(), "缺 v1 探针档案（曾被 v2 覆盖丢失）")
        self.assertTrue(pc.is_file(), "缺 v2 归档档案")
        s1 = json.loads(pb.read_text(encoding="utf-8"))["schema"]
        s2 = json.loads(pc.read_text(encoding="utf-8"))["schema"]
        self.assertNotEqual(s1, s2, "两份档案的 schema 必须不同，否则是同一份东西")


class TestZeroFailureRateNotTreatedAsTotal(unittest.TestCase):
    """🔴 回归点（2026-10-10 生产 bug）：`(x or 1)` 的 falsy 陷阱。

    原实现 `(e["infra_failure_rate"] or 1) <= 0.2`——当失败率恰为 **0.0** 时，
    `0.0 or 1` → 1，"零基础设施失败"被当成 100% 失败，于是**所有 provider 全被拒**、
    推荐恒为 None。这是"看起来在保守、实际是恒不推荐"的假保守。
    本测试用「零失败 + 高 LLM 解出率」的单候选构造：修好后必须能推出它。
    """

    def test_zero_failure_rate_provider_is_recommendable(self):
        agg = [{"provider": "clean", "confidence": "high", "questions_measured": 70,
                "runs": 2, "infra_failure_rate": 0.0, "llm_independent_rate": 0.2,
                "tokens_per_valid_mean": 500, "valid_measured": 70,
                "excluded_from_recommendation": False}]
        rec = arch.recommend(agg)
        self.assertEqual(rec["recommended"], "clean",
                         "零基础设施失败必须算'通过门槛'，不能被 or 1 陷阱误杀")

    def test_none_failure_rate_is_treated_as_unknown(self):
        agg = [{"provider": "unknownrate", "confidence": "high",
                "questions_measured": 70, "runs": 2, "infra_failure_rate": None,
                "llm_independent_rate": 0.2, "tokens_per_valid_mean": 500,
                "valid_measured": 70, "excluded_from_recommendation": False}]
        self.assertIsNone(arch.recommend(agg)["recommended"],
                          "None（未测量）必须当未知并排除，不得当 0 处理")


class TestConfidenceGrading(unittest.TestCase):
    def test_small_sample_is_low_confidence(self):
        runs = [{"run": f"glm_x{i}", "provider": "glm", "total": 2,
                 "valid_measured": 2, "infra_failed": 0, "solved": 0,
                 "llm_independent_solved": 0, "deterministic_fallback_solved": 0,
                 "tokens_total": 1, "tokens_per_solved_mean": None,
                 "tokens_per_valid_mean": 500.0} for i in range(1)]
        agg, _ = arch.aggregate(runs)
        self.assertEqual(agg[0]["confidence"], "low")

    def test_multi_run_and_enough_questions_is_high(self):
        runs = [{"run": f"glm_x{i}", "provider": "glm", "total": 3,
                 "valid_measured": 3, "infra_failed": 0, "solved": 1,
                 "llm_independent_solved": 1, "deterministic_fallback_solved": 0,
                 "tokens_total": 1, "tokens_per_solved_mean": 100.0,
                 "tokens_per_valid_mean": 500.0} for i in range(3)]
        agg, _ = arch.aggregate(runs)
        self.assertEqual(agg[0]["confidence"], "high")


if __name__ == "__main__":
    unittest.main(verbosity=2)