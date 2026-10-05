"""外部基准导出器（scripts/_export_external_benchmark.py）选择规则回归测试。

守护的是反注水口径：只有"真值可机器判定 + 载荷已落盘 + 无污染"的题才能外送。
任何一条规则被改坏（例如漏掉载荷硬门），本测试必须变红。
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import _export_external_benchmark as ex  # noqa: E402

TRUTH = "a" * 64


class TestExportSelection(unittest.TestCase):
    def _corpus(self, tmp: Path) -> Path:
        src = tmp / "questions_real"
        src.mkdir()

        def w(name, obj):
            (src / f"{name}.json").write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")

        # ① 正常题：真值 + 题面 + 已落盘附件
        att = tmp / "att.bin"
        att.write_bytes(b"payload")
        w("good1", {"id": "good1", "category": "crypto", "description": "d",
                    "flag_sha256": TRUTH, "attachments": ["att.bin"],
                    "provenance": "real_past_ctf"})
        # ② 无真值（不可机器判定）→ 必须排除
        w("no_truth", {"id": "no_truth", "category": "misc", "description": "d",
                       "attachments": []})
        # ③ 附件未落盘（缺载荷）→ 必须排除，避免"必然 0"的假 miss
        w("missing_att", {"id": "missing_att", "category": "misc", "description": "d",
                          "flag_sha256": "b" * 64, "attachments": ["nope.bin"]})
        # ④ 题面自带明文答案 → 必须排除（污染题）
        w("disclosed", {"id": "disclosed", "category": "web", "description": "d",
                        "flag_sha256": "c" * 64, "answer_disclosed": True, "attachments": []})
        # ⑤ 自产训练题 → 必须排除
        w("selftrain", {"id": "selftrain", "category": "reverse", "description": "d",
                        "flag_sha256": "d" * 64, "provenance": "self_authored_training",
                        "attachments": []})
        # ⑥ 无附件且真值合法 → 纳入（payload_status=no_attachment_needed）
        w("pure_text", {"id": "pure_text", "category": "crypto", "description": "d",
                        "flag_sha256": "e" * 64, "attachments": []})
        return src

    def test_selection_rules(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = self._corpus(tmp)
            bench, manifest = ex.collect(src=src, att_root=tmp)
            ids = set(bench["problems"])
            self.assertEqual(ids, {"good1", "pure_text"})
            reasons = {e.get("id") or e["file"] for e in manifest["excluded"]}
            self.assertTrue({"no_truth", "missing_att", "disclosed", "selftrain"} <= reasons)
            self.assertEqual(manifest["included_count"], 2)
            self.assertEqual(manifest["excluded_count"], 4)

    def test_truth_must_be_64hex(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = tmp / "q"
            src.mkdir()
            (src / "bad_hex.json").write_text(
                json.dumps({"id": "bad_hex", "description": "d", "flag_sha256": "abc123"}),
                encoding="utf-8")
            bench, manifest = ex.collect(src=src, att_root=tmp)
            self.assertEqual(bench["problems"], {})
            self.assertEqual(manifest["excluded"][0]["reason"], "no_verifiable_truth")

    def test_no_plaintext_flag_leaks(self):
        """反注水硬门：导出物里不得出现明文 flag 字段。"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = self._corpus(tmp)
            bench, _ = ex.collect(src=src, att_root=tmp)
            for qid, p in bench["problems"].items():
                self.assertNotIn("flag", p, f"{qid} 泄露了明文 flag 字段")
                blob = json.dumps(p, ensure_ascii=False)
                self.assertNotIn("flag{", blob.replace("flag_sha256", ""),
                                 f"{qid} 题面文本里出现明文 flag 形态")

    def test_trained_flag_shape(self):
        """trained_in_westlake 只能为 True（真值源不可得时宁可不标）。"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = self._corpus(tmp)
            bench, _ = ex.collect(src=src, att_root=tmp)
            for p in bench["problems"].values():
                if "trained_in_westlake" in p:
                    self.assertIs(p["trained_in_westlake"], True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
