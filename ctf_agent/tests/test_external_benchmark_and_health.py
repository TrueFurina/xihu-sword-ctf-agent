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


# ── 「题库是否落地」判据（2026-10-17） ────────────────────────────────────
#
# 背景：题目清单只记录载荷**引用**，载荷本体在 `data/questions_ext*/_attachments/`
# 下，而该目录按池策略由 .gitignore 排除（`git ls-files` 0 个、历史上从未提交）。
# 因此干净克隆 / CI 上这些载荷必然一个都不在 —— 那是「题库未落地」，不是数据丢失。
#
# 判据刻意是「**一个都不在**」而不是「附件目录为空」：
#   · 一个都不在   ⇒ 未落地 ⇒ skip（理由可读，`pytest -rs` 可审计）
#   · 部分在、部分缺 ⇒ 真实丢失形态 ⇒ **照常判红**，不被 skip 掩盖
#
# 用 `unittest.skipIf` 而非 `@pytest.mark.local`：local 是 *deselected*（连收集都不
# 收集），会让护栏从门禁视野里消失；skipIf 是 *skipped*，可审计。
# 同 `tests/test_capability_ledger_guard.py:109` 的既有取舍。
def _declared_attachments() -> tuple[str, ...]:
    """清单里声明的全部载荷路径（去重并保持清单顺序）。"""
    out: list[str] = []
    for f in sorted((ROOT / "benchmarks" / "external_unseen" / "questions").glob("*.json")):
        q = json.loads(f.read_text(encoding="utf-8"))
        out.extend(q.get("attachments") or [])
    return tuple(dict.fromkeys(out))


DECLARED_ATTACHMENTS = _declared_attachments()
PRESENT_ATTACHMENTS = [a for a in DECLARED_ATTACHMENTS if (ROOT / a).is_file()]
POOL_NOT_INSTALLED = bool(DECLARED_ATTACHMENTS) and not PRESENT_ATTACHMENTS
POOL_NOT_INSTALLED_REASON = (
    f"外部基准题库未落地：{len(DECLARED_ATTACHMENTS)} 个声明载荷全部不在磁盘"
    "（data/ 下的载荷按池策略由 .gitignore 排除，干净克隆与 CI 上必然如此）。"
    "题库齐备的机器上本用例照跑；若载荷**部分**缺失仍会判红。"
)


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
        for f in (ROOT / "benchmarks" / "external_unseen" / "questions").glob("*.json"):
            q = json.loads(f.read_text(encoding="utf-8"))
            self.assertRegex(q["flag_sha256"], r"^[0-9a-f]{64}$", f"{f.stem} 真值非法")
            self.assertEqual(q["flag"], q["flag_sha256"],
                             f"{f.stem}: flag 必须承载 sha256 占位而非明文")
            blob = json.dumps(q, ensure_ascii=False).replace("flag_sha256", "")
            self.assertNotRegex(blob, r"flag\{[^\}]{2,}\}", f"{f.stem} 疑似明文答案")

    @unittest.skipIf(POOL_NOT_INSTALLED, POOL_NOT_INSTALLED_REASON)
    def test_benchmark_attachments_exist(self):
        for f in (ROOT / "benchmarks" / "external_unseen" / "questions").glob("*.json"):
            q = json.loads(f.read_text(encoding="utf-8"))
            for a in q["attachments"]:
                self.assertTrue((ROOT / a).is_file(), f"{f.stem} 载荷缺失: {a}")

    @unittest.skipIf(POOL_NOT_INSTALLED, POOL_NOT_INSTALLED_REASON)
    def test_check_passes_on_current_disk(self):
        ok, problems = bench.check()
        self.assertTrue(ok, problems[:5])


class TestLedgerExclusionSource(unittest.TestCase):
    """选池规则 4 的「已解出 ledger」排除源必须是活路径（2026-10-13 死路径事故守卫）。

    事故形态：`_seen_ids()` 曾写 `ROOT.parent / "REAL_SOLVES_LEDGER.md"`（仓库根），
    而台账实际在 `ctf_agent/` 下、git 历史从未存在于根 → `is_file()` 恒 False →
    ledger 排除源静默空转，规则 4 的三个来源里有一个从来没执行过，
    且磁盘上的题池看起来完全正常（无任何报错）。
    """

    def test_ledger_path_points_inside_ctf_agent(self):
        """路径常量必须锚在 ctf_agent/ 内——ROOT.parent 那类指错层级直接红。"""
        self.assertEqual(bench.LEDGER, ROOT / "REAL_SOLVES_LEDGER.md")

    def test_ledger_file_is_tracked_and_present(self):
        """台账受 git 跟踪（HEAD 树内），任何 checkout 都应存在；缺失即环境异常。"""
        self.assertTrue(bench.LEDGER.is_file(),
                        f"台账不在预期路径: {bench.LEDGER}——排除源会静默失效")

    def test_ledger_ids_flow_into_seen_set(self):
        """活路径 + 真接线：台账提取的题 id 必须实际进入 _seen_ids() 排除集。"""
        led_ids = bench._ledger_ids()
        self.assertTrue(led_ids, "台账里提取不到任何题 id——正则或读取又坏了")
        self.assertTrue(led_ids <= bench._seen_ids(),
                        "台账题 id 没进排除集——_seen_ids() 的 ledger 源又是死的")


class TestPoolShrinkTransparency(unittest.TestCase):
    """池缩小必须逐题有据可查（2026-10-15 ext_gctf2022_ocr 数据丢失事故护栏）。

    事故链：源 JSON 位于 gitignore 的 data/ 下 → 10-12 删除事件永久丢失 →
    10-13 重建时该题静默离开池子（53→51），全仓仅提交信息里一句"源 JSON
    磁盘失踪"，没有任何机器可检的痕迹。本次经 HEAD benchmark 旧副本恢复
    该题（载荷 sha256 逐字节比对上游 google-ctf misc-ocr 证实完好）后立此
    护栏：池子每缩小一题，MANIFEST.dropped 必须记录离开原因；"源 JSON
    失踪"类数据损失必须显式登记 KNOWN_DATA_LOSS，未登记即红（与合并闸门
    LOST_PAYLOAD 同型的登记放行模式）。
    """

    def test_classify_dropped_records_reason_per_id(self):
        dropped = bench.classify_dropped(
            previous_ids={"a", "b", "c", "d"},
            picked_ids={"a"},
            seen={"b"},
            skip_reasons={"c": "not_ok:leaky"},
        )
        self.assertEqual(dropped, {
            "b": "already_solved_or_authorized",
            "c": "failed_selection:not_ok:leaky",
            "d": "source_json_missing",
        })

    def test_manifest_dropped_all_explained(self):
        man = json.loads((ROOT / "benchmarks" / "external_unseen" / "MANIFEST.json")
                         .read_text(encoding="utf-8"))
        self.assertIn("dropped", man, "MANIFEST 必须记录 dropped（池缩小逐题明细）")
        self.assertEqual(bench.dropped_problems(man["dropped"]), [],
                         "存在无原因或未登记的数据损失")

    def test_unregistered_data_loss_is_red(self):
        problems = bench.dropped_problems({"x": "source_json_missing"})
        self.assertTrue(problems, "未登记 KNOWN_DATA_LOSS 的 source_json_missing 必须判红")

    def test_registered_data_loss_passes(self):
        self.assertEqual(
            bench.dropped_problems({"x": "source_json_missing"},
                                   known_loss=bench.KNOWN_DATA_LOSS | {"x"}), [])


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
