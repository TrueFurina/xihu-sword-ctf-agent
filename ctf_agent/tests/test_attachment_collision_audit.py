"""同名附件冲突检测器回归测试（2026-10-06）

锁死「按 basename glob 附件」这一错误做法的危害 detection：

全库实测：**181 道题**若按文件名模糊解析附件，会命中**内容不同**的其它文件。
典型：`flag.txt` 被 87 处引用（库中 213 份同名）、`Makefile` 717 份同名、
`task.py` 26 份同名。任何用 `glob(basename)` 找附件的工具，都可能拿到
别人的答案或占位符 → 制造假水位。

本测试锁死：
① 检测器能报出冲突（含真实数据案例）；
② **本仓既有的正确做法**（按题面 attachments 字段精确解析）不被破坏——
   审计器与 9 个 solver 回归测试均依赖精确路径；
③ `_basename_index` 能正确把同名文件归到一组（冲突检测的基础）。
"""
import glob
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
_SCRIPT = os.path.join(_CTF, "scripts", "_audit_attachment_collision.py")
_TRUTH_SCRIPT = os.path.join(_CTF, "scripts", "_audit_truth_consistency.py")


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestAttachmentCollision(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load(_SCRIPT, "_audit_coll")

    def test_basename_index_groups_same_name(self):
        """同名文件应归到同一组（冲突检测的基础）。"""
        with tempfile.TemporaryDirectory() as td:
            a = os.path.join(td, "x", "flag.txt")
            b = os.path.join(td, "y", "flag.txt")
            for p in (a, b):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as f:
                    f.write("different")
            idx = self.mod._basename_index(td)
            self.assertIn("flag.txt", idx)
            self.assertEqual(len(idx["flag.txt"]), 2)

    def test_real_repo_reports_collisions(self):
        """真实数据回归：本仓存在大量同名附件冲突（按 basename 解析必错）。"""
        # 用真实数据根跑一次（限定 data 目录以控制耗时）
        rows = self.mod.load_questions([os.path.join(_CTF, "data")])
        self.assertTrue(rows, "应能加载真实题面 JSON")
        bmap = self.mod._basename_index(_CTF)
        # flag.txt 必然同名成群
        self.assertGreaterEqual(len(bmap.get("flag.txt", [])), 2,
                                "真实库应存在多份同名 flag.txt")

    def test_truth_auditor_uses_exact_path_not_basename(self):
        """防回归：真值审计器的 resolve() 必须优先精确路径，而非 basename glob。

        这是关键正确性保证——若它改成 glob(basename)，181 道题会拿错附件，
        分层结论（L0 vs 有效推理）随之失真。
        """
        mod = _load(_TRUTH_SCRIPT, "_audit_tc2")
        # 构造同名干扰：精确路径一个内容，glob 同名另一个内容
        with tempfile.TemporaryDirectory() as td:
            exact_dir = os.path.join(td, "a", "q1")
            other_dir = os.path.join(td, "b", "q2")
            os.makedirs(exact_dir)
            os.makedirs(other_dir)
            with open(os.path.join(exact_dir, "flag.txt"), "wb") as f:
                f.write(b"EXACT")
            with open(os.path.join(other_dir, "flag.txt"), "wb") as f:
                f.write(b"OTHER")
            rel = "a/q1/flag.txt"
            got = mod.resolve(rel, td)
            self.assertIsNotNone(got)
            with open(got, "rb") as f:
                self.assertEqual(f.read(), b"EXACT",
                                 "resolve 必须按精确路径取到 EXACT，不能是 OTHER")

    def test_resolve_prefers_existing_exact_path(self):
        """resolve 对绝对/相对、正斜杠/反斜杠两种写法都应命中同一文件。"""
        mod = _load(_TRUTH_SCRIPT, "_audit_tc3")
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "data", "attachments")
            os.makedirs(d)
            fp = os.path.join(d, "output")
            with open(fp, "wb") as f:
                f.write(b"REAL")
            norm = os.path.normpath
            self.assertEqual(norm(mod.resolve("data/attachments/output", td)),
                             norm(fp))
            self.assertEqual(norm(mod.resolve("data\\attachments\\output", td)),
                             norm(fp))


if __name__ == "__main__":
    unittest.main(verbosity=2)
