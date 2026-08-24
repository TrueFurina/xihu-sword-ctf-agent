"""skill 实证分档回归测试（2026-08-22 锐评第三节整改）。

覆盖：
1. 已实证名单里的 skill 都能在 skills/ 目录找到（名单真实）
2. unverified_skills() 返回的都不在已实证名单
3. 已实证与未实证集合无重叠
4. 未实证 skill 加载会打警告（captured log）
"""

import os

import pytest

from tools.skill_manager import VERIFIED_IN_RACE_SKILLS, SkillManager

_SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills")


@pytest.fixture()
def manager():
    m = SkillManager(skills_dir=_SKILLS_DIR)
    m.discover()
    return m


def test_verified_skills_all_exist(manager):
    """已实证名单的 skill 必须真实存在于 skills/ 目录。"""
    real = set(manager.list_available())
    missing = VERIFIED_IN_RACE_SKILLS - real
    assert not missing, f"已实证名单引用不存在的 skill: {missing}"


def test_unverified_skills_complement(manager):
    """未实证 = 发现总数 - 已实证（无重叠、无遗漏）。"""
    verified = VERIFIED_IN_RACE_SKILLS
    unverified = set(manager.unverified_skills())
    real = set(manager.list_available())
    assert verified & unverified == set(), "同一 skill 不能既实证又未实证"
    assert verified | unverified == real, "实证+未实证应覆盖全部 skill"


def test_verified_skills_count_reasonable(manager):
    """已实证 skill 是少数（多数 skill 确实未上场——与锐评"47 个未验证"一致）。"""
    real = set(manager.list_available())
    verified = VERIFIED_IN_RACE_SKILLS & real
    assert 0 < len(verified) < len(real), "已实证应为真子集（多数未上场）"


def test_unverified_load_logs_warning(manager, caplog):
    """未实证 skill 加载时打 ⚠️ 警告。"""
    import logging

    with caplog.at_level(logging.WARNING, logger="tools.skill_manager"):
        unverified = manager.unverified_skills()
        assert unverified, "应有未实证 skill"
        manager.load(unverified[0])
    assert any("未实证" in r.message for r in caplog.records), \
        f"加载 {unverified[0]} 应打未实证警告"
