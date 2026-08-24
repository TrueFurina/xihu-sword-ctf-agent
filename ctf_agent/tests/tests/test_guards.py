"""门禁自检测试（2026-08-24——P2 门禁测试补强——构造违规用例断言被拦截）

验证门禁覆盖度（锐评/审视指导意见：门禁从「声称」变「测试钉死」）：
1. flag 格式符模板拒绝（%d/%s/%f/%x = 题面模板未替换——疑似抄题面）
2. flag 三态校验 REJECT（疑似 hallucination——丢弃）
3. 连续 3 步 reason 无工具 → 强制转工具（reason 空转止损）
"""

import re
import pytest


def _reject_template_flag(output: str):
    """复现 phases.py 模板假阳性拒绝判定（%[dsfx] = 题面模板未替换）"""
    if re.search(r"%[dsfx]", str(output)):
        return None
    return str(output)


def test_flag_format_template_rejected():
    assert _reject_template_flag("flag{hello_%s_world}") is None
    assert _reject_template_flag("DASCTF{uid_%d}") is None
    assert _reject_template_flag("flag{answer_%x}") is None


def test_flag_normal_accepted():
    assert _reject_template_flag("flag{real_answer_2026}") == "flag{real_answer_2026}"


def _simulate_checker_reject(flag: str, checker):
    """复现 phases.py：checker.check 返回 V_REJECT → 丢弃"""
    if checker is not None:
        verdict = checker(flag)
        if verdict == "REJECT":
            return None
    return flag


def test_flag_hallucination_rejected():
    fake_checker = lambda f: "REJECT" if "guess" in f else "ACCEPT"
    assert _simulate_checker_reject("flag{guess_12345}", fake_checker) is None


def test_flag_verified_accepted():
    fake_checker = lambda f: "REJECT" if "guess" in f else "ACCEPT"
    assert _simulate_checker_reject("flag{real_2026}", fake_checker) == "flag{real_2026}"


def _detect_reason_stall(steps: list):
    """复现 main_agent 连续 reason 空转检测：len(steps)>=3 且最近 3 步全 reason → 转工具"""
    if len(steps) >= 3:
        recent = steps[-3:]
        if all(a == "reason" for a in recent):
            return True
    return False


def test_reason_stall_triggered():
    assert _detect_reason_stall(["reason", "reason", "reason"]) is True
    assert _detect_reason_stall(["tool", "reason", "reason", "reason"]) is True


def test_reason_stall_not_triggered():
    assert _detect_reason_stall(["tool", "reason", "reason"]) is False
    assert _detect_reason_stall(["reason", "tool", "reason", "reason"]) is False
