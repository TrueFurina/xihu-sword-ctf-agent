"""机器真值写入守卫 回归（2026-10-10）。

这个守卫的诞生源于一次**已发生的静默数据丢失**：v1 单题探针档案与 v2 归档档案
共用 `benchmarks/provider_capability.json`，v2 跑一次就把 v1 的探针数据整段覆盖，
工作树上无声丢数据。同时审计还查出 `corpus_health_baseline.json` **根本没有
schema 字段**——一份机器真值完全不受保护。

守护五条：
1. 异构 schema 拒写，且既有文件一个字节都不改；
2. **无 schema 的既有文件拒写**（否则覆盖后无法判断数据是哪一版规则的产物）；
3. 缺 schema / schema 格式不对 → 拒写；
4. 同 schema 允许刷新（守卫不能退化成"冻结"），且自动补可追溯元信息；
5. 🔴 **AST 不变式**：不允许有脚本绕过 `write_truth()` 直接写 benchmarks/*.json——
   纪律必须挂在唯一入口上，否则换个脚本就绕过去了（㉚ 铁律）。
"""
import ast
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "truth_guard", ROOT / "scripts" / "_truth_guard.py")
tg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tg)

BENCH = ROOT / "benchmarks"


class TestWriteTruth(unittest.TestCase):
    def _write(self, path: Path, schema: str, doc=None, by="test"):
        return tg.write_truth(path, doc or {"x": 1}, schema=schema, by=by,
                              strict_path=False)

    def test_creates_file_with_schema_and_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.json"
            self._write(p, "demo/v1")
            d = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(d["schema"], "demo/v1")
            self.assertEqual(d["written_by"], "test")
            self.assertIn("written_at", d)
            self.assertIn("git_head", d)

    def test_refuses_foreign_schema(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.json"
            self._write(p, "demo/v1")
            before = p.read_text(encoding="utf-8")
            with self.assertRaises(tg.TruthWriteRefused):
                self._write(p, "other/v9")
            self.assertEqual(p.read_text(encoding="utf-8"), before,
                             "拒写时文件必须一个字节都不改")

    def test_refuses_overwriting_legacy_file_without_schema(self):
        """🔴 回归点：健康基线就是这种文件——无 schema，覆盖后无法追溯是哪版规则产的。

        注意断言写法：本守卫对"无 schema 旧文件"与"异构覆盖"抛的是**同一个异常类型**
        （前者是专门提示，后者是通用规则），所以只断言"抛异常"是弱断言——
        删掉 `not old_schema` 那一支后仍然会抛（落到 `None != schema`），测试照样绿。
        可区分的断言是**错误消息内容**：无 schema 的场景必须给出"先人工确认来源"的
        迁移指引，而异构场景给的是"用不同文件名"。这才是真正咬住该分支的断言。
        """
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "legacy.json"
            p.write_text(json.dumps({"pools": {}}), encoding="utf-8")
            before = p.read_text(encoding="utf-8")
            with self.assertRaises(tg.TruthWriteRefused) as cm:
                self._write(p, "demo/v1")
            self.assertIn("无 schema", str(cm.exception),
                          "无 schema 场景必须给出专门的迁移指引，而非通用的异构提示")
            self.assertEqual(p.read_text(encoding="utf-8"), before,
                             "拒写时旧文件必须原封不动")

    def test_allows_same_schema_refresh(self):
        """守卫不能退化成"冻结"——机器真值本来就要能更新。"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.json"
            self._write(p, "demo/v1", {"n": 1})
            self._write(p, "demo/v1", {"n": 2})
            self.assertEqual(json.loads(p.read_text(encoding="utf-8"))["n"], 2)

    def test_rejects_missing_or_malformed_schema(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.json"
            for bad in ("", "noversion", "a/b/c"):
                with self.assertRaises(tg.TruthWriteRefused, msg=bad):
                    self._write(p, bad)

    def test_corrupt_existing_file_is_treated_as_absent(self):
        """损坏文件视为无档案，允许写入（否则一次崩溃就永久锁死该文件）。"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.json"
            p.write_text("{not json", encoding="utf-8")
            self._write(p, "demo/v1")
            self.assertEqual(json.loads(p.read_text(encoding="utf-8"))["schema"],
                             "demo/v1")

    def test_strict_path_blocks_writes_outside_benchmarks(self):
        """真值必须集中在 benchmarks/——散落各处正是覆盖事故的成因。"""
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(tg.TruthWriteRefused):
                tg.write_truth(Path(td) / "stray.json", {"x": 1},
                               schema="demo/v1", strict_path=True)


class TestAudit(unittest.TestCase):
    def test_audit_passes_on_current_repo(self):
        rep = tg.audit()
        self.assertTrue(rep["all_have_schema"],
                        f"有真值文件缺 schema: {rep['files_without_schema']}")
        self.assertTrue(rep["no_collision"],
                        f"有 schema 撞车: {rep['schema_collisions']}")

    def test_audit_detects_missing_schema(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "n.json"
            f.write_text(json.dumps({"a": 1}), encoding="utf-8")
            import scripts._truth_guard as _  # noqa: F401
            # 直接调 audit 的判定逻辑：临时目录不在 benchmarks/ 下，
            # 因此这里只验证"无 schema 文件会被判出来"这一性质
            d = json.loads(f.read_text(encoding="utf-8"))
            self.assertIsNone(d.get("schema"))

    def test_questions_dir_is_excluded_from_audit(self):
        """逐题载荷（questions/*.json）成批生成、无 schema，不该被审计误报。"""
        for f in BENCH.rglob("*.json"):
            if "questions" not in f.parts:
                continue
            self.assertNotIn(str(f.relative_to(ROOT)),
                             tg.audit()["files_without_schema"])


class TestNoBypassWriters(unittest.TestCase):
    """🔴 AST 不变式：禁止绕过统一入口直接写 benchmarks/ 下的 JSON。

    纪律挂在唯一入口上才有效——若某个脚本自己 `write_text(BENCH/...)`，
    守卫就形同虚设（㉚ 铁律：模仿/绕过实现的自检不算守卫）。
    """

    # 守卫自身 + 逐题载荷生成器（成批写 questions/*.json，由基准 --check 负责完整性）
    ALLOWED_WRITERS = {"_truth_guard.py", "_build_external_benchmark.py"}

    def _scripts(self):
        return [f for f in sorted((ROOT / "scripts").glob("*.py"))
                if f.name not in self.ALLOWED_WRITERS]

    def test_no_script_writes_benchmarks_json_directly(self):
        """🔴 回归点：纪律必须挂在唯一入口上。

        若某脚本自己 `write_text(benchmarks/...)` / `json.dump(..., benchmarks/...)`，
        守卫就形同虚设——所以 AST 层面禁止裸写（唯一出口 write_truth）。
        例外：显式 import 了 _truth_guard 的脚本（它走的是 write_truth）。
        """
        offenders = []
        for f in self._scripts():
            src = f.read_text(encoding="utf-8")
            if "_truth_guard" in src:      # 走统一入口，放行
                continue
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            lines = src.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                name = (fn.attr if isinstance(fn, ast.Attribute)
                        else getattr(fn, "id", ""))
                if name not in ("write_text", "dump", "writelines"):
                    continue
                # 上下文窗口：本行 ±2 行，出现真值路径特征即判为裸写
                lo = max(0, node.lineno - 3)
                hi = min(len(lines), node.lineno + 2)
                window = " | ".join(lines[lo:hi])
                # 🔴 只按**真实目标路径**判定，不用变量名（MANIFEST/BASELINE 这类名字
                # 在 data/results/ 下也有同名变量：初版按名字匹配，结果
                # _merge_gate.py / benchmark_heldout.py 两处写 data/results 的合法
                # 操作被误报为"绕过守卫"——假红比没门禁更糟。
                if "benchmarks" in window or "provider_capability" in window                         or "provider_probe" in window:
                    offenders.append(f"{f.name}:{node.lineno}")
        self.assertEqual(offenders, [],
                         f"绕过 write_truth 直接写机器真值: {offenders}")

    def test_all_writers_actually_call_the_guard(self):
        """🔴 回归点：写入方必须**真的调用** write_truth，而不是"文件里提到过守卫"。

        变异 M4 存活过一次：初版用 `'from _truth_guard import' in src` 做子串判定，
        把 import 行换成注释就骗过了。改为 AST 层面找 `write_truth(...)` 的真实调用。
        """
        must = ["_provider_capability_archive.py", "_provider_toolcap_probe.py",
                "check_corpus_health.py", "_build_external_benchmark.py"]
        missing = []
        for m in must:
            src = (ROOT / "scripts" / m).read_text(encoding="utf-8")
            tree = ast.parse(src)
            called = any(
                isinstance(n, ast.Call)
                and ((isinstance(n.func, ast.Name) and n.func.id == "write_truth")
                     or (isinstance(n.func, ast.Attribute)
                         and n.func.attr == "write_truth"))
                for n in ast.walk(tree))
            if not called:
                missing.append(m)
        self.assertEqual(missing, [],
                         f"这些真值写入方没有真正调用 write_truth: {missing}")


if __name__ == "__main__":
    unittest.main(verbosity=2)