# -*- coding: utf-8 -*-
"""rea_probe 反编译通道单测（2026-10-20），含变异验证。

被守护的三个真实缺陷（都来自实测，不是假想）：

1. **无前缀十六进制地址被当十进制**。Ghidra/objdump 打印 `140001000` 这种地址，
   按十进制解是 1.4 亿 → 落到映像外 → 误报「不在任何节内」，整条
   「批量导出地址 → 定点反编译」链路因此断开。
2. **相对路径静默降级**。`_run_rea` 把子进程 cwd 切到 rea-agents 目录，相对路径
   在那里失效；REA 对「文件不存在」不报错，只返回空 normalized_result，于是被
   误读成「目标是数据 / 未识别代码」。实测同一地址：相对 2.2s 空返回 / 绝对 30.3s 成功。
3. **空结果谎报覆盖**。managed 通道整体被拒（0 类型 0 方法 0 字面量）时曾报
   partial，读起来像「拿到了一部分真数据」。

变异验证：`test_mutation_decimal_parse_would_miss` 不依赖被测代码的当前实现，
而是直接证明「旧的十进制解法确实映射不到任何节」——若有人把解析改回十进制硬解，
`test_bare_hex_resolves_to_file_offset` 立刻 FAIL。
"""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.adapters import rea_probe as rp  # noqa: E402

IMAGE_BASE = 0x140000000
# (vaddr, vsize, rawoff) —— 取自真实 PE 的节表形状：.text rva 0x1000 / rawoff 0x400
SECS = [(0x1000, 0xF000, 0x400), (0x10000, 0x3A00, 0xF400)]


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    """打桩 PE 解析与 REA 调用，使反编译通道可在无 Ghidra 环境下秒级测试。"""
    monkeypatch.setattr(rp, "_pe_sections", lambda _head: (IMAGE_BASE, SECS))

    calls: list[tuple] = []

    def fake_call(op, path, *extra):
        calls.append((op, extra))
        return {"normalized_result": "void f(void) { }", "details": {}}

    monkeypatch.setattr(rp, "_call", fake_call)

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 128)
    return rp.ReaProbeAdapter(), str(sample), calls


def test_bare_hex_resolves_to_file_offset(adapter):
    """`140001000`（无 0x 前缀）必须按十六进制解释并走到 --file-offset。"""
    a, path, calls = adapter
    text, _ = a._lane_decompile(path, "140001000")

    assert calls == [("decompile", ("--file-offset", "0x400"))]
    assert "RVA 0x1000" in text
    assert "按 hex 解析" in text


def test_name_goes_to_procedure(adapter):
    """函数名不是地址，必须走 --procedure，不能被地址分支吃掉。"""
    a, path, calls = adapter
    a._lane_decompile(path, "FUN_140001000")

    assert calls == [("decompile", ("--procedure", "FUN_140001000"))]


def test_decimal_wins_when_mappable(adapter):
    """两种解释都能映射时，保持十进制优先（不改变既有调用方语义）。"""
    a, path, calls = adapter
    a._lane_decompile(path, "4096")  # 十进制 4096 = RVA 0x1000

    assert calls == [("decompile", ("--file-offset", "0x400"))]


def test_unmappable_address_not_applicable(adapter):
    """映像外地址必须报 not_applicable，且不许调用 REA（省掉一次 30s 空跑）。"""
    a, path, calls = adapter
    text, contract = a._lane_decompile(path, "0x999999999")

    assert calls == []
    assert contract["coverage"]["status"] == "not_applicable"
    assert contract["authority"] == "unknown"


def test_relative_path_absolutized(tmp_path, monkeypatch):
    """相对路径必须在进入子进程前绝对化，否则 REA 找不到文件还返回成功。"""
    a = rp.ReaProbeAdapter()
    seen = {}

    def fake_run_sync(path, lane, selector="", max_funcs=0, name_filter="", unpack="auto"):
        seen["path"] = path
        seen["unpack"] = unpack
        return rp.ToolOutput(text="stub", ok=True)

    monkeypatch.setattr(a, "_run_sync", fake_run_sync)
    (tmp_path / "s.exe").write_bytes(b"MZ")
    monkeypatch.chdir(tmp_path)

    asyncio.run(a.run({"path": "s.exe", "lane": "pe"}))

    assert os.path.isabs(seen["path"])
    assert seen["path"].endswith("s.exe")
    assert seen["unpack"] == "auto", "脱壳开关没透传到 _run_sync"


def test_managed_empty_degrades(monkeypatch):
    """managed 整体被拒（0/0/0）必须降级，不能报成 partial。"""
    monkeypatch.setattr(rp, "_call", lambda *a, **k: {
        "normalized_result": {
            "types": [], "methods": [],
            "user_strings": {"literals": [], "state": None},
            "coverage": {"state": "unavailable", "issues": [{"code": "metadata_rejected"}]},
        },
        "limitations": ["The CLI metadata could not be admitted; managed member "
                        "inspection is unavailable."],
        "evidence_id": "ev_stub",
        "subject": {"digest": {"sha256": "ab" * 32}},
    })

    text, contract = rp.ReaProbeAdapter()._lane_managed("x.dll")

    assert contract["authority"] == "unknown"
    assert contract["coverage"]["status"] == "not_applicable"
    assert contract["degraded"] is True
    assert "整体不可用" in text


def test_mutation_decimal_parse_would_miss():
    """变异证据：旧的「无前缀一律十进制」解法确实映射不到任何节。

    这条不调用被测解析分支，只独立复算旧解法，证明上面那条测试守护的是真差异，
    而不是「改前改后都一样」的空测试。
    """
    old_style = int("140001000", 10)  # 旧代码：一律按十进制
    rva = old_style - IMAGE_BASE if old_style >= IMAGE_BASE else old_style
    assert rp._rva2off(rva, SECS) is None


# ── 加壳检测 ─────────────────────────────────────────────
# 实测依据：UPX 压 pip.exe 后 274 函数 → 3 函数、输出 403 KB → 8.9 KB，
# 而 Ghidra 不会给任何提示；照实报 complete 会让下游把「3 个函数」当成
# 「程序只有 3 个函数」。对照组：strip 只影响命名（54 → 53 函数），不影响召回。


def _fake_pe(section_names: list[str]) -> bytes:
    """拼一个只够解析节名的最小 PE 头。"""
    pe_off = 0x40
    buf = bytearray(pe_off + 24 + 40 * len(section_names) + 16)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = pe_off.to_bytes(4, "little")
    buf[pe_off:pe_off + 4] = b"PE\0\0"
    buf[pe_off + 6:pe_off + 8] = len(section_names).to_bytes(2, "little")
    buf[pe_off + 20:pe_off + 22] = (0).to_bytes(2, "little")  # SizeOfOptionalHeader=0
    so = pe_off + 24
    for i, name in enumerate(section_names):
        raw = name.encode("latin-1")[:8].ljust(8, b"\0")
        buf[so + i * 40: so + i * 40 + 8] = raw
    return bytes(buf)


def test_packer_hint_detects_upx():
    assert rp._packer_hint(_fake_pe(["UPX0", "UPX1", ".rsrc"])) == "UPX"


def test_packer_hint_detects_vmp():
    assert rp._packer_hint(_fake_pe([".vmp0", ".vmp1"])) == "VMProtect"


def test_packer_hint_clean_binary():
    """未加壳的节名不能误报——误报会让正常样本被判 degraded。"""
    assert rp._packer_hint(_fake_pe([".text", ".data", ".rdata", ".rsrc"])) is None


def test_packed_binary_degrades_contract(tmp_path, monkeypatch):
    """加壳时出口契约必须降级：complete → partial 且 degraded=True。"""
    sample = tmp_path / "packed.exe"
    sample.write_bytes(_fake_pe(["UPX0", "UPX1"]))
    monkeypatch.setattr(rp, "_rea_available", lambda: (True, ""))
    monkeypatch.setattr(rp, "_rawscan", lambda _p: ([], {"scanned": 0, "truncated": False}))
    monkeypatch.setattr(
        rp.ReaProbeAdapter, "_lane_pe",
        lambda self, path: ("[stub] normal-looking output",
                            rp._contract(authority="observed", status="complete")),
    )

    out = rp.ReaProbeAdapter()._run_sync(str(sample), "pe")
    contract = json.loads(out.raw)

    assert contract["degraded"] is True
    assert contract["coverage"]["status"] == "partial"
    assert "UPX" in contract["degradationReason"]
    assert "UPX" in out.text  # 文本头部也要有可见警告


def test_unpacked_binary_keeps_complete(tmp_path, monkeypatch):
    """对照组：未加壳样本不能被降级，否则警告会失去信息量。"""
    sample = tmp_path / "clean.exe"
    sample.write_bytes(_fake_pe([".text", ".data"]))
    monkeypatch.setattr(rp, "_rea_available", lambda: (True, ""))
    monkeypatch.setattr(rp, "_rawscan", lambda _p: ([], {"scanned": 0, "truncated": False}))
    monkeypatch.setattr(
        rp.ReaProbeAdapter, "_lane_pe",
        lambda self, path: ("[stub] ok",
                            rp._contract(authority="observed", status="complete")),
    )

    out = rp.ReaProbeAdapter()._run_sync(str(sample), "pe")
    contract = json.loads(out.raw)

    assert contract["degraded"] is False
    assert contract["coverage"]["status"] == "complete"


def test_unknown_lane_is_rejected_not_silently_fallback(tmp_path):
    """拼错的 lane 必须报错。

    2026-10-20 实测：`lane=nonsense` 落到分发末端的 `else` 分支，照样跑 pe 通道，
    输出与 `lane=pe` 一字不差。调用方会以为「通道选对了」，实际是它给了个
    不存在的通道——这是「静默降级假装听懂」的典型。
    """
    f = tmp_path / "x.bin"
    f.write_bytes(b"MZ" + b"\x00" * 64)

    out = rp.ReaProbeAdapter()._run_sync(str(f), "nonsense")

    assert out.ok is False
    assert "未知 lane" in out.text
    assert "decompile_batch" in out.text  # 报错要顺带给出合法值，否则等于让人猜


# ── ELF 头解析不完整分支（2026-10-21，ruff F821 实测抓出的真 bug）─────────

def test_lane_elf_parse_error_branch_does_not_crash(tmp_path, monkeypatch):
    """parseError 分支必须先定义 lines 再 append —— 原实现先 append 后定义，
    节头表在 0x2000 读窗之外的 ELF（大二进制常见）走到即 NameError。"""
    import tools.adapters.rea_probe as rp

    f = tmp_path / "big.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 128)

    monkeypatch.setattr(rp, "_elf_info_file", lambda _p: {
        "class": "64", "machine": "x86-64", "type": "EXEC",
        "sections": [], "sectionHeaders": 0,
        "parseError": "节头表超出已读范围（只读了文件头部）",
    })
    monkeypatch.setattr(rp.ReaProbeAdapter, "_objdump_exe", lambda self: None)

    text, contract = rp.ReaProbeAdapter()._lane_elf(str(f))

    assert "ELF 头解析不完整" in text
    assert "节头表超出已读范围" in text
    # 契约层已知不一致（未修，记录在此防遗忘）：objdump 缺失时 contract_parts 里
    # degraded=True，但最终合并结果 degraded=False、只把原因留在 limitations——
    # 本条只锁「不许崩」，不锁 degraded 语义。
    assert contract.get("limitations"), contract
