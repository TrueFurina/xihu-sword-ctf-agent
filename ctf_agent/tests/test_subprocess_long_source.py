"""回归测试：沙盒超长源码落临时文件执行（Windows 命令行长度上限）。

背景（2026-10-07）：crypto 兜底脚本随 triage 增长已到 ~33KB，而沙盒经
`python -c <src>` 执行；Windows CreateProcess 命令行上限 ~32767 字符，超限即
抛 FileNotFoundError → 兜底脚本**静默失效**（实测 33000 字符必失败）。
修复：源码超阈值（SubprocessExecutor._CMD_LINE_SRC_LIMIT）时落临时文件执行，
语义等价（同一解释器 + 同一 AST 校验），执行后清理临时文件。
"""
import asyncio
import glob
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbox.subprocess_executor import SubprocessExecutor  # noqa: E402


def _run(code: str):
    return asyncio.run(SubprocessExecutor().run(code, timeout=30))


def test_short_source_still_runs():
    """小源码（走 -c 快路径）正常执行。"""
    r = _run("python: print(6 * 7)")
    assert r.exit_code == 0, r.stderr
    assert "42" in (r.stdout or "")


def test_long_source_exceeds_cmdline_limit_but_runs():
    """超阈值源码（落临时文件）仍能正确执行——修复前此处必失败。"""
    limit = SubprocessExecutor._CMD_LINE_SRC_LIMIT
    pad = "#" + ("x" * (limit + 20000))
    r = _run("python: print(6 * 7)\n" + pad)
    assert r.exit_code == 0, f"超长源码执行失败: {r.stderr!r}"
    assert "42" in (r.stdout or "")


def test_long_source_temp_file_cleaned():
    """超长源码执行后临时文件须被清理。"""
    limit = SubprocessExecutor._CMD_LINE_SRC_LIMIT
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "ctf_sbx_*.py")))
    r = _run("python: print(1 + 1)\n" + "#" + ("y" * (limit + 20000)))
    assert r.exit_code == 0, r.stderr
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "ctf_sbx_*.py")))
    assert after <= before, f"临时文件未清理: {after - before}"


def test_cmdline_limit_constant_is_sane():
    """阈值须低于 Windows 上限（~32767），留足余量。"""
    assert 0 < SubprocessExecutor._CMD_LINE_SRC_LIMIT < 32000
