# -*- coding: utf-8 -*-
"""本地真值基准的回归锁（适配器级，无 LLM）。

锁的是「工件 → 适配器 → flag 进上下文」这条链。三个工件都满足
**flag 不以明文躺在容器里**（br 压缩 / UPX 压缩节 / wasm 数据段），
所以命中只能来自真实能力，不是 strings 撞大运。

⚠️ 这是**合成工件**（self_authored_training）：证明机制与召回，不代表竞赛真题难度。
   真题口径需要 real_past_ctf 附件，盘上目前 0/50（见报告）。

依赖外部工具（upx / wabt / 一份宿主 PE），故标 local：
    .venv/Scripts/python.exe -m pytest tests/test_local_real_bench.py -q -m local
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BENCH = os.path.join(_ROOT, "benchmarks", "local_real")
_BUILD = os.path.join(_BENCH, "build_artifacts.py")
_RUN = os.path.join(_BENCH, "run_e2e.py")
_MANIFEST = os.path.join(_BENCH, "manifest.json")

pytestmark = pytest.mark.local


def _needs_tools() -> None:
    from tools.adapters.rea_probe import _upx_exe
    if not os.path.isfile(_upx_exe()):
        pytest.skip(f"upx 不在盘：{_upx_exe()}")
    from tools.adapters.wasm_probe import _exe
    if not os.path.isfile(_exe("wat2wasm")):
        pytest.skip("wat2wasm 不在盘（设 WABT_BIN）")
    from benchmarks.local_real.build_artifacts import _HOST_PE
    if not os.path.isfile(_HOST_PE):
        pytest.skip(f"宿主 PE 不存在：{_HOST_PE}")


def test_artifacts_build_and_recall():
    """生成三份工件 + 适配器级召回必须 3/3。"""
    _needs_tools()
    r = subprocess.run([sys.executable, _BUILD], capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, f"生成失败：{r.stdout[-800:]}{r.stderr[-800:]}"

    manifest = json.load(open(_MANIFEST, encoding="utf-8"))
    assert len(manifest["cases"]) == 3
    for cid, case in manifest["cases"].items():
        assert os.path.isfile(case["artifact"]), f"{cid} 工件缺失"
        # 红线：清单只存 sha256，不存明文
        assert len(case["flagSha256"]) == 64 and "{" not in case["flagSha256"]

    r = subprocess.run([sys.executable, _RUN, "--mode", "adapter"],
                       capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, f"召回未满：{r.stdout[-1500:]}"
    assert "3/3" in r.stdout, r.stdout[-1500:]


def test_packed_artifact_is_actually_hidden():
    """工件前提自检：打包态扫不到、脱壳后扫得到。

    这条比「3/3 命中」更要紧——如果打包后 flag 仍是明文，那 3/3 就退化成
    strings 级别的假命中，整个基准失去意义。
    """
    _needs_tools()
    from benchmarks.local_real.build_artifacts import _SEEDS, synth_flag
    from tools.adapters.rea_probe import _rawscan, _unpack_upx

    manifest = json.load(open(_MANIFEST, encoding="utf-8"))
    if "pe_upx" not in manifest["cases"]:
        pytest.skip("先跑 build_artifacts.py")
    path = manifest["cases"]["pe_upx"]["artifact"]
    flag = synth_flag(_SEEDS["pe_upx"])

    packed = [h["value"] for h in _rawscan(path)[0]]
    assert not any(flag in v for v in packed), "打包态就能扫到 flag → 工件没被压缩，基准无效"

    unpacked, ev = _unpack_upx(path)
    assert unpacked and ev.get("ok"), f"脱壳失败：{ev}"
    assert any(flag in h["value"] for h in _rawscan(unpacked)[0]), "脱壳后仍扫不到"
