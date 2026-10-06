"""_extract_json_object / _balanced_brace_end 鲁棒性测试。

目标：弱模型（glm-4-flash 等）常把动作 JSON 裹在 markdown 围栏或 prose 里，
旧实现只认「以 ``` 开头」的围栏 + 粗暴 find/rfind 截取，导致大量
`LLM 返回内容无法解析为 JSON 对象` → 主链空转超时。本测试锁死新实现的
围栏任意位置 / 嵌套 / 平衡扫描 / repair 兜底行为，且对强模型干净 JSON 不回归。
"""

import sys
from pathlib import Path

import pytest

# 允许以模块方式直接 import（与 test_llm_client_contract 一致）
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from llm.client import _balanced_brace_end, _extract_json_object  # noqa: E402


# ── 不回归：强模型干净输出 ──
def test_clean_json_no_regression():
    assert _extract_json_object('{"action": "run", "cmd": "ls"}') == {
        "action": "run",
        "cmd": "ls",
    }


def test_clean_json_nested_no_regression():
    text = '{"action": "solve", "steps": [{"x": 1}, {"y": 2}]}'
    out = _extract_json_object(text)
    assert out == {"action": "solve", "steps": [{"x": 1}, {"y": 2}]}


def test_non_dict_json_returns_none():
    # 顶层是数组而非对象 → 返回 None（agent 要的是动作对象）
    assert _extract_json_object("[1, 2, 3]") is None


# ── 围栏：任意位置 / 任意语言标签 ──
def test_fenced_json_at_start():
    assert _extract_json_object('```json\n{"action": "run"}\n```') == {"action": "run"}


def test_fenced_json_with_prose_before_after():
    text = 'Here is your action:\n```json\n{"action": "run", "cmd": "ls"}\n```\nLet me know if needed.'
    assert _extract_json_object(text) == {"action": "run", "cmd": "ls"}


def test_fenced_json_uppercase_tag():
    assert _extract_json_object('```JSON\n{"action": "run"}\n```') == {"action": "run"}


def test_fenced_python_tag():
    assert _extract_json_object('```python\n{"action": "run"}\n```') == {"action": "run"}


def test_fenced_no_lang_tag():
    assert _extract_json_object('```\n{"action": "run"}\n```') == {"action": "run"}


# ── prose 包裹、无围栏（弱模型常见）──
def test_prose_wrapped_no_fence():
    text = 'I think the next step is to run it.\n{"action": "run", "cmd": "ls"}\nThat should work.'
    assert _extract_json_object(text) == {"action": "run", "cmd": "ls"}


def test_nested_object_in_prose():
    text = 'analysis...\n{"action": "solve", "payload": {"a": {"b": 1}}}\ndone'
    assert _extract_json_object(text) == {
        "action": "solve",
        "payload": {"a": {"b": 1}},
    }


def test_stray_braces_in_prose():
    # prose 里出现孤立花括号（如 LaTeX / 伪代码），不能误截
    text = 'We have f(x) = {1,2} and the action:\n{"action": "run", "cmd": "ls"}'
    assert _extract_json_object(text) == {"action": "run", "cmd": "ls"}


# ── repair 兜底 ──
def test_trailing_comma_repaired():
    assert _extract_json_object('{"action": "run",}') == {"action": "run"}


def test_single_quote_keys_repaired():
    assert _extract_json_object("{'action': 'run', 'cmd': 'ls'}") == {
        "action": "run",
        "cmd": "ls",
    }


def test_fenced_with_trailing_comma_repaired():
    text = '```json\n{"action": "run", "cmd": "ls",}\n```'
    assert _extract_json_object(text) == {"action": "run", "cmd": "ls"}


# ── 多个 JSON 片段：挑能解析的那个 ──
def test_multiple_fragments_picks_valid():
    # 第一个 { 是残缺思考片段，第二个才是合法动作
    text = 'plan: {"thought": incomplete\n{"action": "run", "cmd": "ls"}'
    assert _extract_json_object(text) == {"action": "run", "cmd": "ls"}


# ── 边界 ──
def test_empty_returns_none():
    assert _extract_json_object("") is None
    assert _extract_json_object("   ") is None


def test_none_returns_none():
    assert _extract_json_object(None) is None


def test_pure_prose_no_json_returns_none():
    assert _extract_json_object("I cannot determine the next step.") is None


# ── _balanced_brace_end 单测 ──
def test_balanced_brace_end_nested():
    text = 'x {"a": {"b": 1}} y'
    assert _balanced_brace_end(text, text.index("{")) == text.rindex("}")


def test_balanced_brace_end_ignores_braces_in_string():
    text = '{"k": "a}b{c"}'
    assert _balanced_brace_end(text, 0) == len(text) - 1


def test_balanced_brace_end_unmatched():
    assert _balanced_brace_end('{"a": 1', 0) == -1


def test_balanced_brace_end_wrong_start():
    assert _balanced_brace_end("no brace here", 0) == -1
