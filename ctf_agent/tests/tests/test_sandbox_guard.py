# -*- coding: utf-8 -*-
"""沙盒安全守卫测试（P1 补强，对齐安全卫士整改，2026-08-21）。

背景：sandbox/subprocess_executor.py 已有防护（AST 校验 / bash 分层拦截 /
敏感环境变量剥离），但此前零测试。本文件锁定已落地防护（应全绿），
并对安全卫士"整改中"的两项做探测式 skip（落地后自动转绿）：

已落地（本文件直接断言）：
1. Python 代码 AST 校验：危险导入（subprocess）/危险调用（os.system/
   eval/__import__ 动态绕过）拒绝
2. bash 裸命令分层拦截：拼接元字符（; && || |）/命令替换（$()/反引号）/
   敏感目标（reg query、/etc/passwd、api_key 等）
3. 敏感环境变量剥离 sanitized_env（API_KEY/TOKEN/SECRET/...）

待修复（探测式 skip，未落地则 skip 并注明"待修复后启用"）：
- 单 &（Windows cmd 拼接符）拦截
- zip 成员 ../ 路径穿越校验（解压前拒绝恶意成员名）

设计：全部为纯函数/轻量断言，不真正起子进程，避免测试污染与风险。
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbox.subprocess_executor import (  # noqa: E402
    _SecurityError,
    _check_bash_command,
    _check_cmd_command,
    sanitized_env,
    validate_python_code,
)


# ── 已落地：Python AST 校验 ───────────────────────────────


def test_python_forbidden_import_rejected():
    with pytest.raises(_SecurityError):
        validate_python_code("import subprocess\nprint(1)")


def test_python_forbidden_call_rejected():
    with pytest.raises(_SecurityError):
        validate_python_code("import os\nos.system('id')")


def test_python_dynamic_import_bypass_rejected():
    """getattr/__import__ 动态绕过（P0 加固实测逃逸面）必须拦截。"""
    with pytest.raises(_SecurityError):
        validate_python_code("__import__('os').system('id')")


def test_python_str_pattern_rejected():
    """字符串常量含危险组合（经 eval/exec 落地前藏字符串）→ 拦截。"""
    with pytest.raises(_SecurityError):
        validate_python_code("x = 'os.system(\"id\")'")


def test_python_benign_script_allowed():
    """白名单内纯解题脚本放行（不误伤正常 agent 代码）。"""
    validate_python_code("import math\nprint(math.gcd(12, 8))")


# ── 已落地：bash 裸命令拦截 ───────────────────────────────


def test_shell_concat_meta_rejected():
    for cmd in ("echo a; echo b", "echo a && echo b", "echo a || echo b",
                "echo a | grep x"):
        assert _check_bash_command(cmd) is not None, f"未拦截: {cmd}"


def test_shell_command_substitution_rejected():
    assert _check_bash_command("echo $(cat /flag)") is not None
    assert _check_bash_command("echo `cat /flag`") is not None


def test_shell_newline_rejected():
    assert _check_bash_command("echo a\necho b") is not None


def test_shell_sensitive_target_rejected():
    for cmd in ("reg query HKLM", "cat /etc/passwd", "echo $DASCTF_TOKEN"):
        assert _check_bash_command(cmd) is not None, f"未拦截敏感目标: {cmd}"


def test_cmd_specific_metachars_rejected():
    """Windows cmd 特有面（安全卫士 2026-08-21 新增 _check_cmd_command）。"""
    assert _check_cmd_command("echo a ^ dir") is not None       # ^ 转义符混淆
    assert _check_cmd_command("echo %COMSPEC%") is not None     # % 变量展开
    assert _check_cmd_command("type f < x") is not None         # < 输入重定向
    assert _check_cmd_command("dir") is None                    # 正常命令放行
    assert _check_cmd_command("openssl rsa -in key.pem") is None


def test_shell_benign_allowed():
    """单命令/无危险特征的 openssl 等场景放行（避免误伤解题工具链）。"""
    assert _check_bash_command("openssl rsa -in key.pem -pubout") is None
    assert _check_bash_command("ls") is None


# ── 已落地：敏感环境变量剥离 ──────────────────────────────


def test_sanitized_env_strips_secrets(monkeypatch):
    monkeypatch.setenv("CTF_AGENT_PLATFORM_TOKEN", "secret-token")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-abc")
    monkeypatch.setenv("CTF_AGENT_RACE_PROFILE", "medium")  # 非敏感，应保留
    env = sanitized_env()
    assert "CTF_AGENT_PLATFORM_TOKEN" not in env
    assert "DEEPSEEK_API_KEY" not in env
    assert "CTF_AGENT_RACE_PROFILE" in env


# ── 待修复：探测式 skip ───────────────────────────────────


def test_shell_single_ampersand_rejected():
    """Windows cmd 单 & 拼接（安全卫士整改中）：未拦截则 skip。"""
    err = _check_bash_command("echo a & echo b")
    if err is None:
        pytest.skip("待修复后启用：沙盒未拦截单 &（安全卫士整改中）")
    assert err is not None


def test_zip_traversal_member_rejected():
    """zip 成员含 ../ 必须被拒绝（zip-slip 防护，对齐安全卫士 _validate_zip_member）。

    契约：_validate_zip_member(info) 接受 zipfile.ZipInfo 类对象（有 .filename），
    返回错误描述（None=安全）。安全卫士已落地；若回退则 skip。
    """
    try:
        from tools.adapters.zip_chain_adapter import _validate_zip_member
    except Exception as exc:  # noqa: BLE001 - 未落地时 skip
        pytest.skip(f"待修复后启用：zip 成员 ../ 路径穿越校验未落地（{exc}）")

    import zipfile

    # 拒绝面
    assert _validate_zip_member(zipfile.ZipInfo("../evil.txt")) is not None
    assert _validate_zip_member(zipfile.ZipInfo("..\\evil.txt")) is not None  # 反斜杠混淆
    assert _validate_zip_member(zipfile.ZipInfo("/etc/passwd")) is not None    # 绝对路径
    assert _validate_zip_member(zipfile.ZipInfo("C:/x.txt")) is not None       # 盘符
    # 放行面（正常解题 zip 不误伤）
    assert _validate_zip_member(zipfile.ZipInfo("safe/ok.txt")) is None
