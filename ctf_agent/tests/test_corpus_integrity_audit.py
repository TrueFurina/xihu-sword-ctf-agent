"""题库完整性审计器回归（2026-10-10）。

审计器自身踩过的两个坑都在这里钉死：
1. 附件路径解析按题库目录拼接 → 93 题全报 payload_missing（假阳性）。
   真实附件路径是相对**仓库根**的，必须多候选探测。
2. 门禁假红等于没门禁（项目历史教训：天天假红的护栏会被整段注释掉）。
   故用四类合成夹具分别钉死 ok / answer_key_only / payload_missing / answer_leak。
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("aci", ROOT / "scripts" / "_audit_corpus_integrity.py")
aci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aci)

FLAG = "flag{AbCd_1234}"


def _truth(v: str) -> str:
    import hashlib
    return hashlib.sha256(v.encode()).hexdigest()


class TestCorpusIntegrityAudit(unittest.TestCase):
    def _mk(self, td: str, q: dict, att_rel: str, content: bytes):
        root = Path(td) / "data" / "questions_real"
        root.mkdir(parents=True)
        (Path(td) / att_rel).parent.mkdir(parents=True, exist_ok=True)
        (Path(td) / att_rel).write_bytes(content)
        q.setdefault("id", Path(att_rel).parent.name)
        # 夹具必须把附件路径写进题目——漏了这步会得到 attachments=0，
        # 断言"坏题"却拿到"无附件=ok"，白红一轮（本次首轮即此因）。
        q.setdefault("attachments", [att_rel])
        (root / "q.json").write_text(json.dumps(q, ensure_ascii=False), encoding="utf-8")
        # 附件路径按仓库根写，与真实题库一致（回归点 1）；显式传 att_root，
        # 不用 chdir——临时目录先于 tearDown 删除会让 Windows 报 WinError 32。
        self._att_root = Path(td)
        return root

    def test_clean_question_is_ok(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._mk(td, {"flag_sha256": _truth(FLAG)},
                            "data/questions_real/_attachments/a/task.py", b"print('hi')\n")
            rep = aci.audit(root, getattr(self, "_att_root", None))
            self.assertEqual(rep["by_level"], {"ok": 1})
            self.assertEqual(rep["usable_for_reasoning"], 1)

    def test_answer_key_only_is_broken(self):
        """附件只有 flag.txt（内容=答案裸值）→ 坏题，必须判 broken。"""
        with tempfile.TemporaryDirectory() as td:
            root = self._mk(td, {"flag_sha256": _truth("AbCd_1234")},
                            "data/questions_real/_attachments/a/flag.txt", b"AbCd_1234")
            rep = aci.audit(root, getattr(self, "_att_root", None))
            row = rep["rows"][0]
            self.assertEqual(row["level"], "broken")
            self.assertIn("answer_key_only", row["issues"])

    def test_missing_payload_is_broken(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "data" / "questions_real"
            root.mkdir(parents=True)
            (root / "q.json").write_text(json.dumps({
                "id": "q", "flag_sha256": _truth(FLAG),
                "attachments": ["data/questions_real/_attachments/q/gone.bin"]}),
                encoding="utf-8")
            self._att_root = Path(td)
            rep = aci.audit(root, getattr(self, "_att_root", None))
            self.assertEqual(rep["rows"][0]["level"], "broken")
            self.assertIn("payload_missing", rep["rows"][0]["issues"])

    def test_answer_leak_beside_real_payload_is_leaky(self):
        """有真实载荷但附件里同时含真值 → leaky（可测工程链路，不可算推理分母）。"""
        with tempfile.TemporaryDirectory() as td:
            root = self._mk(td, {"flag_sha256": _truth(FLAG)},
                            "data/questions_real/_attachments/a/data.bin",
                            b"noise\n" + FLAG.encode() + b"\n")
            rep = aci.audit(root, getattr(self, "_att_root", None))
            self.assertEqual(rep["rows"][0]["level"], "leaky")

    def test_no_truth_is_broken(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._mk(td, {}, "data/questions_real/_attachments/a/task.py", b"x = 1\n")
            rep = aci.audit(root, getattr(self, "_att_root", None))
            self.assertIn("no_truth", rep["rows"][0]["issues"])

    def test_flag_placeholder_counts_as_truth(self):
        """flag 字段本身是 64 位 sha256 占位时，应视为有真值（与题库约定一致）。"""
        with tempfile.TemporaryDirectory() as td:
            root = self._mk(td, {"flag": _truth(FLAG)},
                            "data/questions_real/_attachments/a/task.py", b"x = 1\n")
            rep = aci.audit(root, getattr(self, "_att_root", None))
            self.assertNotIn("no_truth", rep["rows"][0]["issues"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
