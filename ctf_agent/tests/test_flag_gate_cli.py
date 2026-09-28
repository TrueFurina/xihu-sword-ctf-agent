"""解出闸门 CLI 测试（scripts/flag_gate_cli.py）。

锁死：退出码 0 = 通过校验（可记解出）；1 = 未通过/不可核验；2 = 用法错误。
成败必须看退出码，不能只看 stdout（项目铁律）。
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

CTF = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(CTF, "scripts", "flag_gate_cli.py")
REAL = "flag{REAL_CLI_2026}"
REAL_SHA = hashlib.sha256(REAL.encode()).hexdigest()


def run(args, expect_code):
    p = subprocess.run([sys.executable, CLI] + args, cwd=CTF,
                       capture_output=True, text=True)
    assert p.returncode == expect_code, f"exit={p.returncode} out={p.stdout} err={p.stderr}"
    return p.stdout


def test_pass_when_real_flag_present(tmp_path):
    f = tmp_path / "hits.json"
    f.write_text(json.dumps(["flag{...}", REAL]), encoding="utf-8")
    out = run(["--sha256", REAL_SHA, "--candidates-file", str(f)], 0)
    assert "PASS" in out and REAL in out


def test_fail_on_placeholder_only(tmp_path):
    """复现真机假成功场景：只有占位符 → 必须 FAIL。"""
    f = tmp_path / "hits.json"
    f.write_text(json.dumps(["flag{...}", "flag{}"]), encoding="utf-8")
    out = run(["--sha256", REAL_SHA, "--candidates-file", str(f)], 1)
    assert "FAIL" in out


def test_fail_without_baseline(tmp_path):
    """无答案基准 → 不可核验，绝不记为解出（fail-closed 核心）。"""
    f = tmp_path / "hits.json"
    f.write_text(json.dumps([REAL]), encoding="utf-8")
    out = run(["--candidates-file", str(f)], 1)
    assert "FAIL" in out and "不可核验" in out


def test_text_mode_picks_real(tmp_path):
    out = run(["--sha256", REAL_SHA, "--text", f"noise flag{{...}} {REAL}"], 0)
    assert "PASS" in out


def test_usage_error_when_no_input():
    p = subprocess.run([sys.executable, CLI, "--sha256", REAL_SHA],
                       cwd=CTF, capture_output=True, text=True)
    assert p.returncode == 2


def test_json_output_machine_readable(tmp_path):
    f = tmp_path / "hits.json"
    f.write_text(json.dumps([REAL]), encoding="utf-8")
    out = run(["--sha256", REAL_SHA, "--candidates-file", str(f), "--json"], 0)
    data = json.loads(out)
    assert data["verified"] is True and data["flag"] == REAL
