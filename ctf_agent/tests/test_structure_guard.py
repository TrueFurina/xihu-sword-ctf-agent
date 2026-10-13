# -*- coding: utf-8 -*-
"""目录结构守卫回归（2026-10-13）。

守护两条性质：
1. **路径列举必须仓库根相对**：`all_tracked_and_untracked()` 用的 `git ls-files`
   在子目录 cwd 下默认输出 cwd 相对路径——`ctf_agent/REAL_SOLVES_LEDGER.md`
   会显示成无斜杠的 `REAL_SOLVES_LEDGER.md`，被规则 1 误判「根目录禁止平铺」。
   假阳不止是噪音：它会诱导把正确归位于 ctf_agent/ 的受跟踪文件挪去别的目录。
   修复 = ls-files 加 `--full-name`。
2. **根级白名单不含解题台账**：ledger 实际位于 `ctf_agent/REAL_SOLVES_LEDGER.md`
   （git 跟踪、HEAD 树内），根级白名单曾列该项——与事实不符，且诱导「在根级
   另建一份」形成双真值源。2026-10-13 移除。
"""
import importlib.util
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


guard = _load("_structure_guard")


class TestStructureGuardPaths(unittest.TestCase):
    def test_listing_is_repo_root_relative_from_subdir(self):
        """子目录 cwd 下列举不得产出 cwd 相对路径（假阳之源，2026-10-13 事故形态）。"""
        prev = os.getcwd()
        os.chdir(ROOT)  # ctf_agent/ 下跑守卫即复现事故
        try:
            files = set(guard.all_tracked_and_untracked())
        finally:
            os.chdir(prev)
        self.assertIn("ctf_agent/REAL_SOLVES_LEDGER.md", files,
                      "列举漏掉了受跟踪的台账——--full-name 行为不对")
        self.assertNotIn("REAL_SOLVES_LEDGER.md", files,
                         "出现 cwd 相对路径：会被规则 1 误判为根级散落文件")

    def test_root_allow_excludes_ledger(self):
        """台账归位 ctf_agent/，根级白名单不得再列（防双真值源）。"""
        self.assertNotIn("REAL_SOLVES_LEDGER.md", guard.ROOT_ALLOW)
        self.assertTrue((ROOT / "REAL_SOLVES_LEDGER.md").is_file(),
                        "台账不在 ctf_agent/ 下——先查它去哪了再改白名单")

    def test_no_violation_when_run_from_subdir(self):
        """从子目录跑 --all 口径的检查：当前树不得报任何散落（假阳清零）。"""
        prev = os.getcwd()
        os.chdir(ROOT)
        try:
            files = guard.all_tracked_and_untracked() + guard.filesystem_strays()
        finally:
            os.chdir(prev)
        violations = [p for p in files if guard.check_path(p)]
        self.assertEqual(violations, [],
                         f"子目录口径下出现散落误报: {violations[:3]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
