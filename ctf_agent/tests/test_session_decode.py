"""工作区 shell 输出解码的回归测试（P0：中文 Windows 上输出被解崩成 None）。

真实故障（2026-10-01 实测）：
    `Session._exec` 用 `subprocess.run(..., text=True)`，Python 按 **utf-8 严格**解码。
    中文路径工作区里跑 `dir` / `type`（cmd 内置命令输出 GBK）→ 解码线程抛
    UnicodeDecodeError → **`proc.stdout` 变成 None** → 上层拿到「命令返回 0 但没有输出」。

    它不是报错，是**静默空输出**：agent 以为命令跑了却读不到内容，于是一遍遍重试
    recon，整题预算空烧光。A 档 5 题抬到单题 20 万 token 仍 0/5，日志里
    「工作区 shell 持续不可用…无法读取脚本内容」就是这个。

变异验证：把 `_decode_out` 换成恒返回空串，本文件必须 FAIL。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import session as sess  # noqa: E402
from core.session import Session, _decode_out  # noqa: E402


# ---------------------------------------------------------------- 纯函数

def test_utf8_bytes_passthrough():
    assert _decode_out("flag{ok}".encode("utf-8")) == "flag{ok}"


def test_gbk_bytes_fallback_not_empty():
    """GBK 字节串：utf-8 严格解码必失败，必须回退本地编码而不是变空。"""
    raw = "驱动器 E 中的卷".encode("gbk")
    out = _decode_out(raw)
    assert isinstance(out, str)
    assert out, "GBK 输出被解成了空串（旧故障回归）"
    assert len(out) >= 3


def test_none_and_empty_are_safe():
    assert _decode_out(None) == ""
    assert _decode_out(b"") == ""


def test_arbitrary_binary_never_crashes():
    """任意字节都不得抛异常——命令输出可能是任何编码。"""
    for raw in (b"\xc7\xd0\xff\xfe", b"\x00\x01\x02", b"\x80" * 10,
                b"\xe4\xb8\xad\xe6\x96\x87"):
        out = _decode_out(raw)
        assert isinstance(out, str)


# ---------------------------------------------------------------- Session 集成

def test_session_run_returns_str_not_none(tmp_path):
    """核心回归：`rec.stdout` 必须是 str，绝不能是 None。"""
    ws = tmp_path / "工作区"
    ws.mkdir()
    (ws / "附件.py").write_text("x = 1\n", encoding="utf-8")
    s = Session(str(ws), session_id="t")
    rec = s.run("echo probe", timeout=30)
    assert rec.stdout is not None, "rec.stdout 是 None（旧故障回归）"
    assert isinstance(rec.stdout, str)


def test_session_dir_in_cjk_workspace_has_output(tmp_path):
    """中文工作区跑 `dir`：旧行为会因 GBK 解码崩溃丢掉全部输出。

    仅在 Windows 断言「非空」（cmd 才有 `dir`）；其它平台只断言类型。
    """
    ws = tmp_path / "中文工作区"
    ws.mkdir()
    (ws / "附件.py").write_text("x = 1\n", encoding="utf-8")
    s = Session(str(ws), session_id="t2")
    rec = s.run("dir", timeout=30)
    assert isinstance(rec.stdout, str)
    if sys.platform.startswith("win"):
        assert rec.stdout.strip(), \
            "中文工作区 `dir` 输出为空 —— GBK 解码崩溃回归了"


# ---------------------------------------------------------------- 变异验证

def test_mutation_decode_disabled():
    """变异：让 `_decode_out` 恒返回空串 → 正确行为必须消失（证明判据真在生效）。"""
    raw = "驱动器 E".encode("gbk")
    assert _decode_out(raw) != ""
    orig = sess._decode_out
    sess._decode_out = lambda b: ""
    try:
        assert sess._decode_out(raw) == "", \
            "变异失败：替换后仍返回非空，说明测试没真正走 _decode_out"
    finally:
        sess._decode_out = orig
    assert _decode_out(raw) != ""
