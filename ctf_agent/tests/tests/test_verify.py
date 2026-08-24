# -*- coding: utf-8 -*-
"""verify/ 模块冒烟测试（FlagChecker 三态门 + ErrorClassifier 分类）——锐评 P0 整改。"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace
from verify.flag_checker import FlagChecker, V_ACCEPT, V_WARN, V_REJECT
from verify.error_classifier import (ErrorClassifier, ERR_STUCK_LOOP, ERR_TOOL_FAILURE,
                                     ERR_HALLUCINATION)

def test_flag_checker_states():
    fc = FlagChecker()
    # ACCEPT：合法 flag（本地 + 平台前缀）
    assert fc.check("flag{abc123}") == V_ACCEPT
    assert fc.check("DASCTF{abc-123-def}") == V_ACCEPT
    assert fc.check("flag{rsa_small_e_2026}") == V_ACCEPT
    # REJECT：空/未闭合/控制字符/非法字符
    assert fc.check("") == V_REJECT
    assert fc.check(None) == V_REJECT
    assert fc.check("flag{abc") == V_REJECT          # 未闭合
    assert fc.check("flag{ab}cd}") == V_REJECT        # 双右括号
    assert fc.check("flag{a\nbc}") == V_REJECT        # 控制字符
    assert fc.check('flag{ab"c}') == V_REJECT         # 引号
    assert fc.check("flag{}") == V_REJECT             # 空内容
    assert fc.check("abc{123}") == V_REJECT           # 前缀不符
    # WARN：长度临界 / 占位符
    assert fc.check("flag{xx}") == V_WARN             # 内容过短
    w = fc.check("flag{placeholder_value_here}")
    assert w == V_WARN or w == V_ACCEPT               # 含 placeholder → WARN
    print("✓ test_flag_checker_states")

def test_flag_checker_extract():
    fc = FlagChecker()
    assert fc.extract("恭喜！flag{hello_world_2026} 提交成功") == "flag{hello_world_2026}"
    assert fc.extract("答案: DASCTF{uuid-1234-5678}") == "DASCTF{uuid-1234-5678}"
    assert fc.extract("没有 flag 的文本") is None
    print("✓ test_flag_checker_extract")

def test_error_classifier():
    ec = ErrorClassifier()
    # 死循环：连续 3 步相同 action
    steps = [SimpleNamespace(action="reason", error_category=None)] * 3
    cat, _ = ec.classify(steps)
    assert cat == ERR_STUCK_LOOP
    # 工具失败 ≥2（action 不同避免先命中 stuck_loop）
    steps2 = [SimpleNamespace(action="reason", error_category=ERR_TOOL_FAILURE),
              SimpleNamespace(action="script", error_category=ERR_TOOL_FAILURE),
              SimpleNamespace(action="reason", error_category=None)]
    cat2, _ = ec.classify(steps2)
    assert cat2 == ERR_TOOL_FAILURE
    # 幻觉
    steps3 = [SimpleNamespace(action="flag", error_category=ERR_HALLUCINATION)]
    cat3, _ = ec.classify(steps3)
    assert cat3 == ERR_HALLUCINATION
    # 空输入
    assert ec.classify([]) == (None, "")
    print("✓ test_error_classifier")

if __name__ == "__main__":
    test_flag_checker_states()
    test_flag_checker_extract()
    test_error_classifier()
    print("=== verify 冒烟测试全部通过 ===")
