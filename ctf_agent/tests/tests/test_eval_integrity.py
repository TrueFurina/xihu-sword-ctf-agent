# -*- coding: utf-8 -*-
"""评测完整性与离线能力测试（2026-08-21 锐评收尾轮）。

四组不变量：
A. 数据集卫生：附件存在、无答案键文件混入 attachments 目录、flag 键统一放 data/answers
B. 评测护栏：answer_disclosed 题默认排除、附件名含 flag 的条目被剔除
C. 提示词不泄题：to_prompt_text() 不得包含 flag 值本体
D. 离线工具链能力：toolkit 内容嗅探脚本在沙盒中真跑，
   对全部「有附件且未泄题」的 crypto/misc 题统计可解数——诚实水位的数据来源
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
QUESTIONS_DIR = ROOT / "data" / "questions"
ATTACH_DIR = ROOT / "data" / "attachments"
ANSWERS_DIR = ROOT / "data" / "answers"

# 2026-08-24 车道方案适配：data/attachments（91M）+ data/answers 按 .gitignore 设计
# 本地保留、不入版本库（题库 questions 已入库）。合并闸门在合并发生地（主树，数据全）
# 真跑这些测试；在无数据的车道/克隆环境显式跳过并说明原因，避免假失败。
_DATA_AVAILABLE = ATTACH_DIR.is_dir() and ANSWERS_DIR.is_dir()
DATA_SKIP_REASON = "data/attachments 或 data/answers 不在版本库（本地保留），无数据环境跳过"

from eval.cases import Question, load_questions  # noqa: E402


class TestDatasetHygiene(unittest.TestCase):
    """A. 数据集卫生。"""

    @unittest.skipUnless(_DATA_AVAILABLE, DATA_SKIP_REASON)
    def test_attachments_exist_and_no_answer_keys(self):
        """每道题的附件必须存在；答案键目录（data/answers）不得被引用；
        自有数据集目录（data/attachments）内不得出现 *flag*.txt 答案键文件。"""
        for jf in sorted(QUESTIONS_DIR.rglob("*.json")):
            data = json.loads(jf.read_text(encoding="utf-8"))
            for att in data.get("attachments", []):
                p = ROOT / att if not os.path.isabs(att) else Path(att)
                self.assertTrue(p.exists(), f"{jf.name} 引用的附件不存在: {att}")
                norm = str(att).replace("\\", "/").lower()
                self.assertNotIn("data/answers/", norm,
                                 f"{jf.name} 引用了答案键目录下的文件: {att}")
                if norm.startswith("data/attachments/"):
                    self.assertNotIn("flag", Path(att).name.lower(),
                                     f"{jf.name} 自有数据集混入答案键: {att}")

    @unittest.skipUnless(_DATA_AVAILABLE, DATA_SKIP_REASON)
    def test_attachments_dir_has_no_answer_keys(self):
        """attachments 目录不得存放 *flag*.txt 答案键（应统一在 data/answers）。"""
        leaked = [p.name for p in ATTACH_DIR.iterdir()
                  if p.is_file() and "flag" in p.name.lower()]
        self.assertEqual(leaked, [], f"答案键泄漏到 attachments 目录: {leaked}")

    @unittest.skipUnless(_DATA_AVAILABLE, DATA_SKIP_REASON)
    def test_answers_dir_exists(self):
        self.assertTrue(ANSWERS_DIR.is_dir(), "data/answers 目录应存在（答案键统一存放）")


class TestEvalGuard(unittest.TestCase):
    """B. 评测护栏。"""

    def test_answer_disclosed_excluded_by_default(self):
        default = {q.id for q in load_questions(str(QUESTIONS_DIR))}
        allq = {q.id for q in load_questions(str(QUESTIONS_DIR), include_disclosed=True)}
        disclosed = allq - default
        self.assertTrue(disclosed, "应至少有 1 道 answer_disclosed 题被默认排除")
        for jf in QUESTIONS_DIR.rglob("*.json"):
            data = json.loads(jf.read_text(encoding="utf-8"))
            if data.get("answer_disclosed"):
                self.assertIn(data["id"], disclosed)
        # 泄题题不得出现在默认评测集
        self.assertNotIn("crypto-009", default)
        self.assertNotIn("crypto-010", default)

    def test_attachment_name_guard(self):
        """data/answers 下的附件必须被剔除；真题自带的 flag.txt 挑战文件必须保留。"""
        with tempfile.TemporaryDirectory() as td:
            qd = Path(td) / "q"
            qd.mkdir()
            (qd / "t.json").write_text(json.dumps({
                "id": "t-001", "category": "misc", "title": "t",
                "flag": "flag{x}", "answer_disclosed": False,
                "attachments": ["data/attachments/misc-003-dns.txt",
                                "data/answers/t-001-flag.txt"],
            }), encoding="utf-8")
            qs = load_questions(str(qd))
            self.assertEqual(len(qs), 1)
            self.assertEqual(qs[0].attachments, ["data/attachments/misc-003-dns.txt"])


class TestPromptNoLeak(unittest.TestCase):
    """C. 提示词不泄题。"""

    def test_prompt_text_excludes_flag(self):
        for jf in sorted(QUESTIONS_DIR.rglob("*.json")):
            data = json.loads(jf.read_text(encoding="utf-8"))
            if not data.get("flag"):
                continue
            q = Question.from_dict(data)
            prompt = q.to_prompt_text()
            self.assertNotIn(data["flag"], prompt,
                             f"{jf.name} 的 to_prompt_text 泄漏了 flag 本体")


class TestOfflineTriageCapability(unittest.TestCase):
    """D. 离线工具链能力：内容嗅探脚本真跑（无 LLM、无网络）。

    这是「工具链水位」的诚实数据：跳过 LLM，只验证 toolkit 生成的
    通用解题脚本能否从附件解出 flag。范围限定自有数据集（data/attachments），
    真题（外部绝对路径）由 scripts/_offline_triage.py 全量盘点——
    真题难度真实，不应拉低工具链回归下限。
    """

    #: 需要写临时文件的题型（zip 修复会产 .fixed.zip，先拷贝再跑，不污染数据集）
    _COPY_FIRST = {".zip"}

    def _local_qs(self, with_flag: bool):
        out = []
        for q in load_questions(str(QUESTIONS_DIR)):
            if q.category not in ("crypto", "misc") or not q.attachments:
                continue
            if not str(q.attachments[0]).replace("\\", "/").startswith("data/attachments/"):
                continue
            if with_flag and not q.flag:
                continue
            out.append(q)
        return out

    def _build_and_run(self, q: Question):
        from agents.crypto_toolkit import CryptoToolkit
        from agents.misc_toolkit import MiscToolkit
        from sandbox.subprocess_executor import SubprocessExecutor

        builder = {"crypto": CryptoToolkit, "misc": MiscToolkit}.get(q.category)
        if builder is None:
            return None, None
        att = ROOT / q.attachments[0]
        if att.suffix.lower() in self._COPY_FIRST:
            tmp = Path(tempfile.mkdtemp())
            att = Path(shutil.copy(att, tmp / att.name))
        script = builder.build_fallback_script(str(att))
        if not script:
            return None, None
        out = asyncio.run(SubprocessExecutor(default_timeout=60).run(f"python: {script}"))
        return script, (out.stdout + "\n" + out.stderr)

    @unittest.skipUnless(_DATA_AVAILABLE, DATA_SKIP_REASON)
    def test_triage_generates_and_runs(self):
        """全部本地可测题的脚本都能生成并在沙盒中执行（不崩溃、不被安全拦截）。"""
        qs = self._local_qs(with_flag=False)
        self.assertGreaterEqual(len(qs), 8, "可测题样本过少，题库可能损坏")
        ran = 0
        for q in qs:
            script, output = self._build_and_run(q)
            if script is None:
                continue
            self.assertNotIn("安全拦截", output or "", f"[{q.id}] 脚本被沙盒拦截")
            ran += 1
        self.assertGreaterEqual(ran, 8)

    @unittest.skipUnless(_DATA_AVAILABLE, DATA_SKIP_REASON)
    def test_triage_solves_floor(self):
        """离线 triage 至少解出本地可测题的一半（flag 出现在脚本输出中）。"""
        qs = self._local_qs(with_flag=True)
        solved = []
        for q in qs:
            script, output = self._build_and_run(q)
            if script is None:
                continue
            if q.flag in (output or ""):
                solved.append(q.id)
        self.assertGreaterEqual(
            len(solved), len(qs) // 2,
            f"离线工具链水位跌破下限: 解出 {len(solved)}/{len(qs)} → {solved}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
