# -*- coding: utf-8 -*-
"""UPX 脱壳通道回归（2026-10-20）。

背景：加壳样本的静态分析只能看到解压存根。实测 UPX 压过的 108 KB Python
console script，`decompile_batch` 只导出 **3 个函数**；同一文件脱壳后是
**274 个函数**。此前适配器只能诚实报 degraded —— 等于把「壳」这一层最常见
的第一道门挡在门外，而 upx -d 本身是确定性操作，没有理由不做。

这里守四条线（每条都对应一种真的会错的方式）：
1. 原文件字节不变（脱壳只在副本上做）。
2. 成功要复核节名，不能只信退出码。
3. 非 UPX 载荷必须失败得诚实（rc != 0 → 保留存根层 + degraded）。
4. 脱壳确实扩大了覆盖（3 → 274），不是「跑了一跳但什么都没变」。
"""
import asyncio
import hashlib
import os
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.adapters import rea_probe as rp  # noqa: E402


def _sha(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _candidate_exes() -> list[str]:
    """优先挑同目录下的小 PE（venv 的 console script 最容易被 UPX 打包）。"""
    d = os.path.dirname(sys.executable)
    out: list[tuple[int, str]] = []
    try:
        names = os.listdir(d)
    except OSError:
        return []
    for name in names:
        if not name.lower().endswith(".exe"):
            continue
        p = os.path.join(d, name)
        try:
            out.append((os.path.getsize(p), p))
        except OSError:
            continue
    return [p for _, p in sorted(out)]


def _make_packed(tmp_path) -> str:
    """现场压一个真实样本；本机无 upx 或无可打包 PE 时跳过。"""
    upx = rp._upx_exe()
    if not upx:
        pytest.skip("upx 不可用（设 REA_UPX 或加入 PATH）")
    for cand in _candidate_exes()[:15]:
        dst = str(tmp_path / ("packed_" + os.path.basename(cand)))
        try:
            shutil.copyfile(cand, dst)
            r = subprocess.run([upx, "-q", "-9", dst], capture_output=True,
                               text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0 and rp._packer_hint_file(dst) == "UPX":
            return dst
    pytest.skip("本机找不到可被 UPX 打包的 PE 样本")


# ── 工具缺失：必须说清楚，不能假装脱过 ──────────────────────────

def test_upx_missing_is_reported(tmp_path, monkeypatch):
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ" + b"\x00" * 64)
    monkeypatch.setattr(rp, "_DEFAULT_UPX", str(tmp_path / "nope" / "upx.exe"))
    monkeypatch.setattr(rp.shutil, "which", lambda _n: None)

    out, ev = rp._unpack_upx(str(f))

    assert out is None
    assert ev["ok"] is False
    assert "未找到 upx" in ev["reason"]


# ── 成功路径：副本脱壳、原文件不动、节名复核 ─────────────────────

@pytest.mark.local
def test_unpack_leaves_original_untouched(tmp_path):
    p = _make_packed(tmp_path)
    before, size_before = _sha(p), os.path.getsize(p)

    unpacked, ev = rp._unpack_upx(p)

    assert ev["ok"] is True and unpacked and os.path.isfile(unpacked)
    assert _sha(p) == before, "原文件被改了 —— 用户题目文件必须字节不变"
    assert os.path.getsize(p) == size_before
    assert os.path.getsize(unpacked) > ev["sizeBefore"], "脱壳后反而更小，说明没真脱"
    assert rp._packer_hint_file(unpacked) is None, "节名仍见 UPX 签名，复核没生效"
    assert ev["rc"] == 0 and ev["ms"] >= 0
    assert unpacked != p


def test_unknown_unpack_value_is_rejected(tmp_path):
    """拼错的开关必须报错 —— 静默按默认值跑会让调用方以为自己关掉了脱壳。"""
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ" + b"\x00" * 64)

    out = asyncio.run(rp.ReaProbeAdapter().run({"path": str(f), "unpack": "offf"}))

    assert out.ok is False
    assert "未知 unpack" in out.text and "auto|off" in out.text


@pytest.mark.local
def test_unpack_refuses_non_upx_payload(tmp_path):
    """把已脱净的文件再脱一次：必须 rc!=0 且返回 None（不许当成成功）。"""
    p = _make_packed(tmp_path)
    unpacked, _ = rp._unpack_upx(p)
    if not unpacked:
        pytest.skip("首次脱壳未成功，跳过")

    again, ev = rp._unpack_upx(unpacked)

    assert again is None
    assert ev["ok"] is False
    assert "rc=" in ev["reason"] and ev["rc"] != 0


# ── 端到端：脱壳确实扩大覆盖（3 → 274 函数的那个实测）─────────────

@pytest.mark.slow
@pytest.mark.local
def test_run_analyzes_unpacked_copy(tmp_path):
    """unpack=off 只看到存根；unpack=auto 必须把函数数拉开量级。"""
    import json

    p = _make_packed(tmp_path)
    a = rp.ReaProbeAdapter()

    off = asyncio.run(a.run({"path": p, "lane": "decompile_batch", "unpack": "off"}))
    auto = asyncio.run(a.run({"path": p, "lane": "decompile_batch"}))

    n_off = int(re.search(r"导出 (\d+) 个函数", off.text).group(1))
    n_auto = int(re.search(r"导出 (\d+) 个函数", auto.text).group(1))

    assert n_auto > n_off * 5, f"脱壳后覆盖没拉开：{n_off} → {n_auto}"
    assert "壳已脱" in auto.text
    c_auto = json.loads(auto.raw)
    assert c_auto["evidence"]["unpack"]["ok"] is True
    assert c_auto["degraded"] is False, "脱壳成功不该再背「存根层」的 degraded"

    c_off = json.loads(off.raw)
    assert c_off["degraded"] is True, "unpack=off 只看到存根，必须降级"
    assert any("加壳" in x for x in c_off["limitations"])
