"""事实黑板 presolve 缓存指纹守卫（core/blackboard.py）。

背景（2026-10-13，承接 preset_answers 装配层 P0）：
    `Blackboard._presolve_fingerprint()` 原**只指纹 core/presolve.py**，
    而真值判定横跨两层——core/presolve.py（判分：`_passes_answer_check`）
    + eval/cases.py（装配：`preset_answers` 答案表）。只指纹前者时，
    装配层修复后旧缓存仍命中：**修复前在无闸状态下写入的诱饵条目会绕过
    新 sha256 闸**（实测 10-12 备份的 109 条旧缓存全部会命中）。

修复：指纹改为 presolve.py + eval/cases.py 联合哈希。
本文件锁定：任一层源码变更都必须换指纹 → 旧条目自动失效（防脏命中）。
"""
from __future__ import annotations

import ast
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.blackboard import Blackboard  # noqa: E402


def _mk_blackboard(tmp_path, cache: dict) -> Blackboard:
    p = tmp_path / "bb.json"
    p.write_text(json.dumps({"presolve_cache": cache, "known_failures": {}}),
                 encoding="utf-8")
    return Blackboard(path=str(p))


# ---------------------------------------------------------------- 指纹覆盖两层
class TestFingerprintCoversBothLayers:
    def test_presolve_src_change_changes_fingerprint(self, tmp_path, monkeypatch):
        """回归锁：presolve.py 变更仍换指纹（既有行为不回退）。"""
        base = Blackboard._presolve_fingerprint()
        other = tmp_path / "presolve_variant.py"
        other.write_text("# variant\n", encoding="utf-8")
        monkeypatch.setattr(Blackboard, "_PRESOLVE_SRC", str(other))
        assert Blackboard._presolve_fingerprint() != base

    def test_answer_assembly_src_change_changes_fingerprint(self, tmp_path, monkeypatch):
        """修复点：eval/cases.py（装配层）变更必须换指纹。"""
        base = Blackboard._presolve_fingerprint()
        other = tmp_path / "cases_variant.py"
        other.write_text("# variant\n", encoding="utf-8")
        monkeypatch.setattr(Blackboard, "_ANSWER_ASSEMBLY_SRC", str(other))
        assert Blackboard._presolve_fingerprint() != base

    def test_fingerprint_is_stable_within_same_sources(self):
        """同源码两次计算必须一致（否则缓存永远不命中）。"""
        assert Blackboard._presolve_fingerprint() == Blackboard._presolve_fingerprint()

    def test_missing_source_yields_unknown_not_crash(self, tmp_path, monkeypatch):
        """源码缺失 → 'unknown'（fail-closed：不伪装成有效指纹）。"""
        monkeypatch.setattr(Blackboard, "_PRESOLVE_SRC", str(tmp_path / "nope.py"))
        assert Blackboard._presolve_fingerprint() == "unknown"


# ---------------------------------------------------------------- 脏缓存失效
class TestStaleCacheEvicted:
    def test_entry_with_old_fingerprint_not_returned(self, tmp_path):
        """核心守卫：旧指纹条目（修复前写入，可能含诱饵）读不到。"""
        bb = _mk_blackboard(tmp_path, {
            "q1": {"flag": "CTF{decoy_from_old_code}", "source": "presolve",
                   "fp": "0000000000000000", "ts": 0},
        })
        assert bb.get_presolve("q1") is None

    def test_entry_with_current_fingerprint_returned(self, tmp_path):
        """回归锁：当前指纹条目仍正常命中（不误伤加速路径）。"""
        cur = Blackboard._presolve_fingerprint()
        bb = _mk_blackboard(tmp_path, {
            "q1": {"flag": "CTF{truth}", "source": "presolve", "fp": cur, "ts": 0},
        })
        got = bb.get_presolve("q1")
        assert got is not None and got[0] == "CTF{truth}"

    def test_unknown_entry_not_returned(self, tmp_path):
        bb = _mk_blackboard(tmp_path, {})
        assert bb.get_presolve("missing") is None


# ---------------------------------------------------------------- AST 不变式
class TestAssemblyLayerNotDroppedFromFingerprint:
    """防删回：_presolve_fingerprint 体内必须真用到 _ANSWER_ASSEMBLY_SRC。"""

    def _src(self) -> str:
        p = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "core", "blackboard.py",
        )
        with open(p, encoding="utf-8") as fh:
            return fh.read()

    def test_assembly_src_is_referenced_in_fingerprint_body(self):
        tree = ast.parse(self._src())
        fn = next(
            (n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == "_presolve_fingerprint"),
            None,
        )
        assert fn is not None, "_presolve_fingerprint 未定义"
        seg = ast.get_source_segment(self._src(), fn) or ""
        assert "_ANSWER_ASSEMBLY_SRC" in seg, (
            "_presolve_fingerprint 未引用 _ANSWER_ASSEMBLY_SRC：装配层（eval/cases.py）"
            " 变更将不再换指纹，旧诱饵缓存可绕过 sha256 闸（2026-10-13 P0 复发）"
        )

    def test_assembly_src_points_to_eval_cases(self):
        assert Blackboard._ANSWER_ASSEMBLY_SRC.replace("\\", "/").endswith("eval/cases.py")
