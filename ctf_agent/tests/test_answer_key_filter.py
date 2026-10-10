"""ITEM4-A 答案密钥隔离过滤器（core.answer_key_filter）的单位测试。

锁死的不变式
────────────
① 明文答案附件（内容与 flag_sha256 归一化后匹配）→ 必须被剔除（防读答案注水）。
② 改名答案附件（如 out.txt 内嵌明文 flag）→ 内容级命中也必须被剔除（防改名绕过）。
③ 合法输入附件（即使命名为 flag.txt，内容并非答案，如 anwang 八进制密文）→ 必须保留。
④ 无真值可比对 / 文件缺失时：文件名命中答案词干才保守剔除，否则保留（宁漏不误删）。
⑤ fail-closed：异常不得让过滤器崩溃，且默认按「非答案密钥」处理。

变异验证（写完手动跑，预期行为）
──────────────────────────────
M1  把 _content_verdict 改成恒 False（禁用内容判定）→ anwang 类 octal 输入仍被
    文件名兜底剔除 → ③ 失败。当前实现内容级证伪后直接 return False，M1 下会回归。
M2  把归一化哈希改为原始字节（去掉 .strip()）→ 带 \\r\\n 的明文答案 sha256 失配
    → ① 失败（漏删答案）。当前实现保留 .strip() 分支。
"""

import hashlib
import os
import tempfile
import unittest

from core.answer_key_filter import (
    filter_answer_key_attachments,
    is_answer_key_attachment,
)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class _Q:
    """最小化 Question 替身：仅暴露过滤器读取的属性。"""
    def __init__(self, flag_sha256=None, expected_sha256=None, extra=None):
        self.flag = None
        self.flag_sha256 = flag_sha256
        self.expected_sha256 = expected_sha256
        self.extra = extra or {}


class TestAnswerKeyFilter(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, name, content_bytes):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(content_bytes)
        return p

    # ── ① 明文答案附件（flag.txt，带 \\r\\n）应被剔除 ──
    def test_plaintext_answer_flagtxt_stripped(self):
        flag = "flag{27033a89-55dd-46dc-82b9-cd89a4da957d}"
        fs = _sha256(flag)
        path = self._write("flag.txt", (flag + "\r\n").encode())
        q = _Q(flag_sha256=fs)
        self.assertTrue(is_answer_key_attachment(q, path))
        self.assertEqual(filter_answer_key_attachments(q, [path]), [])

    # ── ② 改名答案（out.txt 内嵌明文 flag）应被内容级命中剔除 ──
    def test_renamed_answer_caught_by_content(self):
        flag = "flag{deadbeef-cafe-1234-5678-90abcdef1234}"
        fs = _sha256(flag)
        path = self._write("out.txt", (flag + "\n").encode())
        q = _Q(flag_sha256=fs)
        # 文件名 out.txt 不在答案词干集，纯靠内容级命中
        self.assertTrue(is_answer_key_attachment(q, path))
        self.assertEqual(filter_answer_key_attachments(q, [path]), [])

    # ── ③ anwang 八进制密文输入（命名为 flag.txt，内容≠答案）必须保留 ──
    def test_anwang_octal_input_preserved(self):
        # 八进制序列解码文本身不是答案 → flag_sha256 与之不匹配
        octal_txt = "153 145 171 72 106 114 141 147 104 145 143 157\n"
        fs = _sha256("flag{this-is-the-real-answer-not-the-octal}")
        path = self._write("flag.txt", octal_txt.encode())
        q = _Q(flag_sha256=fs)
        self.assertFalse(is_answer_key_attachment(q, path),
                         "合法八进制输入（即使叫 flag.txt）不得被误删")
        self.assertEqual(filter_answer_key_attachments(q, [path]), [path])

    # ── ④ 合法非答案输入（内容不同，文件名普通）保留 ──
    def test_legit_input_preserved(self):
        fs = _sha256("flag{answer-xyz}")
        path = self._write("cipher.bin", b"\x01\x02\x03some ciphertext not the flag")
        q = _Q(flag_sha256=fs)
        self.assertFalse(is_answer_key_attachment(q, path))
        self.assertEqual(filter_answer_key_attachments(q, [path]), [path])

    # ── ⑤ 无真值可比对 + 文件名命中答案词干 → 保守剔除 ──
    def test_no_sha256_name_hit_strips(self):
        path = self._write("flag.txt", b"unknown no sha256 to compare")
        q = _Q(flag_sha256=None)
        self.assertTrue(is_answer_key_attachment(q, path))

    # ── ⑤b 无真值 + 文件名非答案词干 → 保留（宁漏不误删）──
    def test_no_sha256_name_miss_keeps(self):
        path = self._write("input.txt", b"just some input")
        q = _Q(flag_sha256=None)
        self.assertFalse(is_answer_key_attachment(q, path))

    # ── ⑥ fail-closed：异常路径不崩溃且默认非答案密钥 ──
    def test_fail_closed_on_bad_question(self):
        class _Bad:
            def __getattr__(self, item):
                raise RuntimeError("boom")
        bad = _Bad()
        # 不应抛异常，且默认按「非答案密钥」返回 False
        self.assertFalse(is_answer_key_attachment(bad, os.path.join(self.tmp, "x.txt")))
        self.assertEqual(filter_answer_key_attachments(bad, ["a", "b"]), ["a", "b"])

    # ── ⑥b 缺失文件不崩溃 ──
    def test_missing_file_no_crash(self):
        q = _Q(flag_sha256=_sha256("flag{x}"))
        self.assertFalse(is_answer_key_attachment(q, os.path.join(self.tmp, "nope.txt")))

    # ── ⑦ 混合：答案 + 合法输入 → 仅答案被剔 ──
    def test_mixed_answer_and_input(self):
        flag = "flag{mixed-answer}"
        fs = _sha256(flag)
        ans = self._write("flag.txt", (flag + "\n").encode())
        inp = self._write("data.bin", b"real input bytes")
        q = _Q(flag_sha256=fs)
        out = filter_answer_key_attachments(q, [ans, inp])
        self.assertEqual(out, [inp])

    # ── ⑧ 集成：presolve 单一入口 _attachments 实际剔除答案密钥 ──
    def test_presolve_attachments_entry_strips_answer(self):
        # presolve 约 50 处消费者都经 _attachments 单一入口，锁死它即覆盖全部 presolve 路径
        from core.presolve import _attachments
        flag = "flag{presolve-entry-strip}"
        fs = _sha256(flag)
        ans = self._write("flag.txt", (flag + "\r\n").encode())
        inp = self._write("real_input.py", b"print('real challenge input')")

        class _P:
            id = "demo"
            category = "misc"
            attachments = [ans, inp]
            extra = {}

        q = _P()
        # _attachments 读 question.attachments（原始含答案），应返回剔除后的真实输入
        out = _attachments(q)
        self.assertEqual(out, [inp],
                         "presolve._attachments 必须将答案密钥挡在 solver 之外")


if __name__ == "__main__":
    unittest.main()
