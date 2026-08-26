"""路由表完整性回归测试（2026-08-22 锐评整改）。

覆盖三条约束：
1. skill_map 无重复键（Python dict 字面量重复键会静默覆盖，前面的映射成死代码）
2. skill_map 所有 value 必须指向 skills/ 目录真实存在的 skill（防悬空引用）
3. infer_skill_require 不再返回 need_download（锁死：只允许加载本地已验证 skill）
"""

import ast
import inspect
import os
from pathlib import Path

import pytest

from core.prompts import infer_skill_require

_SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"


def _extract_skill_map() -> dict:
    """用 ast 从 infer_skill_require 源码中提取 skill_map 字面量。"""
    src = inspect.getsource(infer_skill_require)
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "skill_map" for t in node.targets)
            and isinstance(node.value, ast.Dict)
        ):
            result = {}
            for k, v in zip(node.value.keys, node.value.values):
                if isinstance(k, ast.Constant) and isinstance(v, ast.Constant):
                    result[k.value] = v.value
            return result
    raise AssertionError("未找到 skill_map 字面量")


def _real_skill_names() -> set[str]:
    return {p.stem for p in _SKILLS_DIR.glob("*.py") if p.stem != "__init__"}


def test_skill_map_no_duplicate_keys():
    """约束1：无重复键。"""
    skill_map = _extract_skill_map()
    assert skill_map, "skill_map 不应为空"
    keys = list(skill_map)
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, f"重复键（静默覆盖死代码）: {dupes}"


def test_skill_map_all_targets_exist():
    """约束2：所有 value 指向 skills/ 真实存在的 skill。"""
    skill_map = _extract_skill_map()
    real = _real_skill_names()
    missing = sorted(set(skill_map.values()) - real)
    assert not missing, f"映射到不存在的 skill: {missing}"


def test_skill_map_no_brainfuck_misroute():
    """约束3（回归）：brainfuck 不再映射到 base64_multilayer。"""
    skill_map = _extract_skill_map()
    assert "brainfuck" not in skill_map, "brainfuck 无专用 skill，不应出现在路由表"


def test_infer_skill_require_never_requests_download():
    """约束4：锁死——本地无 skill 时返回 None，不请求下载。"""

    class _EmptyMgr:
        def list_loaded(self):
            return []

        def list_available(self):
            return []

    class _Q:
        category = "crypto"
        description = "RSA 共模攻击 wiener hastad"
        candidate_flag = None

    class _Ctx:
        question = _Q()

    result = infer_skill_require(_Ctx(), {"ability_gap": ["缺少有效攻击路径"]}, _EmptyMgr())
    assert result is None, "本地无已验证 skill 时应锁死返回 None，不得请求下载"


def test_infer_skill_require_loads_local_skill():
    """约束5：本地有 skill 时自动加载（正常路径不被破坏）。"""

    class _Mgr:
        def __init__(self):
            self.loaded = []

        def list_loaded(self):
            return self.loaded

        def list_available(self):
            return ["morse_decoder", "rsa_fermat_factor"]

        def load(self, name):
            self.loaded.append(name)

    class _Q:
        category = "crypto"
        description = "摩斯密码 decode"
        candidate_flag = None

    class _Ctx:
        question = _Q()

    mgr = _Mgr()
    result = infer_skill_require(_Ctx(), {"ability_gap": ["缺少有效攻击路径"]}, mgr)
    assert result is None
    assert "morse_decoder" in mgr.loaded, "本地存在的 skill 应自动加载"
