"""外部基准静态分层脚本回归（2026-10-06）。

重点防一个已发生的静默失效：初版拿 sha256 摘要去比原始真值字节，恒不相等 →
L0（附件直含答案）永不触发，分层表看着"干净"其实失真——而这正是分层脚本存在的意义。
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "strat", ROOT / "scripts" / "_stratify_external_benchmark.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class TestMatchesTruth(unittest.TestCase):
    def test_full_and_inner_forms(self):
        """回归点：真值只能拿到摘要，必须对候选算摘要比对（初版反向计算导致 L0 永不触发）。"""
        flag = b"flag{AbC_123}"
        full = m.sha256_hex(flag)
        self.assertTrue(m.matches_truth(flag, full))
        self.assertTrue(m.matches_truth(b"AbC_123", m.sha256_hex(b"AbC_123")))
        self.assertFalse(m.matches_truth(b"flag{other}", full))
        self.assertFalse(m.matches_truth(flag, ""))

    def test_direction_of_comparison(self):
        """反向（拿真值算摘要）恒不相等——显式钉死这个坑不再出现。"""
        truth = m.sha256_hex(b"flag{Zz9}")
        self.assertNotEqual(truth, m.sha256_hex(truth.encode()))
        self.assertTrue(m.matches_truth(b"flag{Zz9}", truth))


class TestStratifyLevels(unittest.TestCase):
    def _bench(self, root: Path, att_rel: str, truth_flag: str) -> Path:
        att = root / att_rel
        att.parent.mkdir(parents=True, exist_ok=True)
        att.write_bytes(b"binary\x00" + truth_flag.encode() + b"\x00end")
        import json
        bp = root / "b.json"
        bp.write_text(json.dumps({"problems": {"q1": {
            "id": "q1", "category": "misc", "flag_sha256": m.sha256_hex(truth_flag.encode()),
            "attachments": [att_rel]}}}), encoding="utf-8")
        return bp

    def test_direct_read_level_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bp = self._bench(root, "a/flag.txt", "flag{DirectReadMe}")
            rep = m.stratify(bp, root)
            self.assertEqual(rep["by_level"].get("L0_direct_read"), 1,
                             f"应判 L0，实际 {rep['by_level']}")

    def test_absent_attachment_not_counted_as_no_payload(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bp = root / "b.json"
            bp.write_text(json.dumps({"problems": {"q2": {
                "id": "q2", "category": "web",
                "flag_sha256": "a" * 64, "attachments": ["missing/x.bin"]}}}),
                encoding="utf-8")
            rep = m.stratify(bp, root)
            self.assertEqual(rep["by_level"].get("LX_attachment_unavailable"), 1)
            self.assertNotIn("L3_no_payload", rep["by_level"])

    def test_bare_plaintext_answer_detected_as_direct_read(self):
        """锁死 2026-10-06 核心修复：裸明文答案（无花括号，如 `Cisc0`/`80`/hex）
        必须被判 L0，否则会被整题漏掉 -> 误标 L2 纯推理层，污染能力分母。"""
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            truth = "Cisc0"  # 无花括号的纯明文答案
            att = root / "flag.txt"
            att.write_text(truth, encoding="utf-8")
            bp = root / "b.json"
            bp.write_text(json.dumps({"problems": {"q9": {
                "id": "q9", "category": "misc",
                "flag_sha256": m.sha256_hex(truth.encode()),
                "attachments": ["flag.txt"]}}}), encoding="utf-8")
            rep = m.stratify(bp, root)
            self.assertEqual(rep["by_level"].get("L0_direct_read"), 1,
                             f"裸明文答案应判 L0，实际 {rep['by_level']}")

    def test_bare_plaintext_non_answer_not_false_positive(self):
        """负向：附件里只有非真值的裸明文串，不应误判 L0（仍落 L2 纯推理层）。"""
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            att = root / "data.txt"
            att.write_text("decoy", encoding="utf-8")  # 非真值裸串
            bp = root / "b.json"
            bp.write_text(json.dumps({"problems": {"q10": {
                "id": "q10", "category": "misc",
                "flag_sha256": m.sha256_hex(b"flag{real}"),
                "attachments": ["data.txt"]}}}), encoding="utf-8")
            rep = m.stratify(bp, root)
            self.assertNotIn("L0_direct_read", rep["by_level"])
            self.assertEqual(rep["by_level"].get("L2_pure_reasoning"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
