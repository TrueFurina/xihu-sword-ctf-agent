"""门禁聚合器 回归（2026-10-10）。

这个聚合器补的是一个**真实缺口**：三道数据类门禁（机器真值 schema 审计 / 正式基准
清单 vs 磁盘 / 题库健康基线）此前**一道都没接进 pre-commit**，只能靠人记得手动跑——
每道门禁自己都能发现问题，但"记得跑"是最弱的一环，纸面门禁等于没有门禁。

守护三条：
1. **聚合器真被钩子调用**（AST 不变式）——钩子注释里写了不算，必须真有调用；
2. **失败必须传播**（rc=1），且门禁自身崩溃要 fail-closed（rc=2）而非静默放行；
3. **题库健康门禁只在回归时红**——`questions_real` 有 77 道已知历史坏题，
   按"坏题>0 即红"会天天假红，而天天假红的护栏最终一定被整段注释掉。
"""
import ast
import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "gates", ROOT / "scripts" / "_run_all_gates.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

HOOKS = [ROOT / "git_hooks" / "pre-commit", ROOT / "scripts" / "hooks" / "pre-commit"]


class TestHookWiring(unittest.TestCase):
    """🔴 回归点：钩子里必须**真的调用**聚合器。"""

    def test_both_hook_files_call_aggregator(self):
        """git_hooks/ 是激活位、scripts/hooks/ 是源，两份都要接（否则 setup.sh 同步会抹掉）。"""
        for h in HOOKS:
            self.assertTrue(h.is_file(), f"缺钩子文件: {h}")
            src = h.read_text(encoding="utf-8")
            self.assertIn("_run_all_gates.py", src, f"{h.name} 未接聚合器")

    def test_hook_gate_call_is_not_commented_out(self):
        """必须存在**真正执行**聚合器的命令行。

        两次误报都源于同一类错误：**判定条件把"提到脚本名的行"当成"调用"**：
        ① 说明性注释（"...聚合器 scripts/_run_all_gates.py：0.85s 跑全..."）；
        ② 失败分支里的诊断提示（`echo "诊断：... scripts/_run_all_gates.py --verbose"`）。
        这两行都不是调用。正确判定：行首必须是可执行前缀（`"$PY"` / `python`）。
        """
        cmd_lines, other_lines = [], []
        for h in HOOKS:
            for line in h.read_text(encoding="utf-8").splitlines():
                st = line.strip()
                if "_run_all_gates.py" not in st:
                    continue
                if st.startswith('"$PY"') or st.startswith("python"):
                    cmd_lines.append((h.name, st))
                else:
                    other_lines.append((h.name, st))
        self.assertTrue(cmd_lines, "两份钩子里都没有真正执行聚合器的命令行")
        for name, st in cmd_lines:
            self.assertIn("scripts/_run_all_gates.py", st)
            self.assertTrue(st.startswith('"$PY"') or st.startswith("python"),
                            f"{name} 的命令前缀异常: {st[:60]}")
        _ = other_lines

    def test_hook_call_must_block_on_failure(self):
        """🔴 回归点（变异 M1 首轮存活）：调用被注释掉时测试仍全绿。

        初版只查"存在命令行"，而把调用改成注释后，另一条"两份钩子块一致"的用例
        照样通过（两边都被同样改坏 → 仍一致）→ 变异存活。补上**执行语义**要求：
        调用必须带失败分支（`||`）且 `exit 1`——只跑不管等于没接门禁。
        """
        for h in HOOKS:
            src = h.read_text(encoding="utf-8")
            call_idx = [i for i, l in enumerate(src.splitlines())
                        if '"$PY" scripts/_run_all_gates.py' in l]
            self.assertTrue(call_idx, f"{h.name} 没有真实调用行")
            for i in call_idx:
                # 调用行必须在 `||` 失败链里，且其后 6 行内有 exit 1
                line = src.splitlines()[i]
                self.assertIn("||", line,
                              f"{h.name}:{i+1} 调用未接失败分支（只跑不管=没接门禁）")
                tail = " | ".join(src.splitlines()[i:i + 8])
                self.assertIn("exit 1", tail,
                              f"{h.name}:{i+1} 失败链里没有 exit 1，不会阻断提交")

    def test_hook_both_files_have_identical_gate_block(self):
        """两份钩子的门禁块必须一致，否则同步方向不对时会单边失效。"""
        blocks = []
        for h in HOOKS:
            src = h.read_text(encoding="utf-8")
            i = src.find("⑫ 数据真值")
            blocks.append(src[i:i + 200] if i >= 0 else "")
        self.assertTrue(all(blocks), "有一份钩子缺 ⑫ 门禁块")
        self.assertEqual(blocks[0], blocks[1],
                         "两份钩子的 ⑫ 门禁块不一致（同步会抹掉其中一份）")


class TestExitCodes(unittest.TestCase):
    def test_passes_now(self):
        rep = g.run_gates()
        self.assertTrue(rep["passed"],
                        f"当前应全过: {[(r['key'], r['rc'], r['tail']) for r in rep['results'] if not r['ok']]}")

    def test_unknown_gate_returns_2(self):
        """无法判定 → fail-closed（rc=2），不放行。"""
        import subprocess as sp
        r = sp.run([sys.executable, str(ROOT / "scripts" / "_run_all_gates.py"),
                    "--only", "nope"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_gate_failure_propagates_as_nonzero(self):
        """造一个缺 schema 的真值文件 → 聚合器必须非 0 退出。"""
        import tempfile
        bad = ROOT / "benchmarks" / "_tmp_gate_test.json"
        before = set(ROOT.glob("benchmarks/_tmp_gate_test.json"))
        self.assertEqual(before, set())
        try:
            bad.write_text(json.dumps({"no_schema": 1}), encoding="utf-8")
            r = subprocess.run([sys.executable,
                                str(ROOT / "scripts" / "_run_all_gates.py"),
                                "--only", "truth"], cwd=ROOT, capture_output=True,
                               text=True)
            self.assertNotEqual(r.returncode, 0,
                                "有真值文件缺 schema 时聚合器必须失败")
            self.assertIn("_tmp_gate_test", r.stdout + r.stderr)
        finally:
            bad.unlink(missing_ok=True)
        # 清理后必须恢复通过（证明上一步的失败确实来自这个文件）
        rep = g.run_gates(["truth"])
        self.assertTrue(rep["passed"])


class TestResultShape(unittest.TestCase):
    def test_reports_all_three_data_gates(self):
        rep = g.run_gates()
        keys = {r["key"] for r in rep["results"]}
        self.assertEqual(keys, {"truth", "bench", "health"})

    def test_each_result_has_diagnostics(self):
        """失败时必须能看出是哪道门禁、什么输出——静默红是不可诊断的。"""
        for r in g.run_gates()["results"]:
            self.assertIn("title", r)
            self.assertIn("rc", r)
            self.assertIn("seconds", r)
            self.assertIsInstance(r["tail"], list)

    def test_crashed_gate_is_marked_and_blocking(self):
        """门禁自身崩溃（无法执行）必须标 crashed 并判失败，不能当通过。

        实现注记：GATES 的命令列表在模块加载时就用 sys.executable 固化了，
        所以不能在测试里改 g.PY（无效）。改为临时把 GATES 换成一条不存在的可执行文件。
        """
        orig = list(g.GATES)
        try:
            g.GATES[:] = [("broken", "故意崩溃的门禁",
                           ["definitely_not_a_real_binary_xyz"], True)]
            rep = g.run_gates()
            self.assertFalse(rep["passed"], "门禁无法执行时必须判失败（fail-closed）")
            self.assertTrue(rep["results"][0]["crashed"])
            self.assertTrue(rep["results"][0]["tail"], "崩溃必须留下可诊断输出")
        finally:
            g.GATES[:] = orig

    def test_only_filter_selects_subset(self):
        rep = g.run_gates(["truth"])
        self.assertEqual([r["key"] for r in rep["results"]], ["truth"])


if __name__ == "__main__":
    unittest.main(verbosity=2)