"""能力信封分档的判定测试。

每条判据都对应一个**真实踩过的坑**，不是凭空造的：
  - ciphertext 纯文本曾被「无扩展名即可执行」误判 D1（初版报告的错误）；
  - stage-2.bin 裸 x86 码曾因「只信魔数」被漏判成 A；
  - bdos.tar.gz / challenge.zip 内部藏着可执行文件，不窥探就会误判 A。

变异验证：把 `_looks_binary` 的 NUL 阈值改松、或删掉归档窥探分支，本文件必须 FAIL。
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import _envelope_band as eb  # noqa: E402


def _mk(d: Path, name: str, data: bytes) -> str:
    p = d / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return str(p)


# ---------------------------------------------------------------- 分档判据

def test_elf_magic_is_d1(tmp_path):
    att = _mk(tmp_path, "tablez", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40)
    band, reason = eb.classify([att], "reverse me", "rev", base=tmp_path)
    assert band == "D1"
    assert "tablez" in reason


def test_plaintext_no_ext_stays_a(tmp_path):
    """防回归：`ciphertext` 这种无扩展名纯文本绝不能落 D1。"""
    att = _mk(tmp_path, "ciphertext", b"1c494c4f5645" * 20)
    band, _ = eb.classify([att], "almost xor", "crypto", base=tmp_path)
    assert band == "A"


def test_raw_x86_binary_is_d1(tmp_path):
    """`stage-2.bin` 是裸 x86 机器码（\xf4=hlt），没有 ELF 魔数但内容非文本。"""
    att = _mk(tmp_path, "stage-2.bin", b"\xf4\xe4\x92\x0c\x02\xe6\x921\xc0\x8e\xd0\xbc\x01`\x8e\xd8\x8e\xc0\x8e\xe0")
    band, reason = eb.classify([att], "Open stage2 in disassembler", "rev", base=tmp_path)
    assert band == "D1"
    assert "裸二进制" in reason


def test_pcap_is_b(tmp_path):
    att = _mk(tmp_path, "cap.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    band, _ = eb.classify([att], "find the flag", "forensics", base=tmp_path)
    assert band == "B"


def test_image_is_c(tmp_path):
    att = _mk(tmp_path, "short-circuit.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 40)
    band, _ = eb.classify([att], "what is this", "misc", base=tmp_path)
    assert band == "C"


def test_qemu_keyword_is_d2(tmp_path):
    att = _mk(tmp_path, "main.bin", b"\xfa\xfc" + b"\x00" * 40)
    band, reason = eb.classify([att], "run with qemu-system-i386 -drive file=main.bin", "rev", base=tmp_path)
    assert band == "D2"


def test_archive_hiding_exec_is_d1(tmp_path):
    """bdos.tar.gz / challenge.zip 的情况：外层是归档，里面是可执行形状文件。"""
    zp = tmp_path / "challenge.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("emu/emu", b"\x7fELF" + b"\x00" * 20)
        zf.writestr("readme.txt", b"run emu")
    band, reason = eb.classify([str(zp)], "run it", "rev", base=tmp_path)
    assert band == "D1"
    assert "emu" in reason


def test_archive_all_text_stays_a(tmp_path):
    zp = tmp_path / "handout.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("gen.py", b"print('hi')")
        zf.writestr("notes.md", b"# task")
    band, _ = eb.classify([str(zp)], "break this", "crypto", base=tmp_path)
    assert band == "A"


def test_no_attachment_is_a(tmp_path):
    band, reason = eb.classify([], "pure math puzzle", "crypto", base=tmp_path)
    assert band == "A"
    assert "无附件" in reason


def test_missing_file_falls_back_to_a(tmp_path):
    band, reason = eb.classify(["data/questions_ext/_attachments/x/nope.bin"],
                               "desc", "crypto", base=tmp_path)
    assert band == "A"
    assert "读不到" in reason


# ---------------------------------------------------------------- 汇总结构

def test_summary_counts_static_envelope(tmp_path):
    (tmp_path / "pool").mkdir()
    import json
    doc = {"id": "q1", "category": "crypto", "description": "d",
           "attachments": [_mk(tmp_path, "c.txt", b"hello")]}
    (tmp_path / "pool" / "q1.json").write_text(json.dumps(doc), encoding="utf-8")
    rows = eb.classify_pool(tmp_path / "pool", base=tmp_path)
    s = eb.summary(rows)
    assert s["total"] == 1
    assert s["static_envelope"] == 1
    assert s["by_band"]["A"] == 1


def test_pool_skips_attachments_dir(tmp_path):
    import json
    (tmp_path / "pool" / "_attachments").mkdir(parents=True)
    (tmp_path / "pool" / "_attachments" / "inp.json").write_text("{}", encoding="utf-8")
    (tmp_path / "pool" / "q1.json").write_text(
        json.dumps({"id": "q1", "category": "crypto"}), encoding="utf-8")
    rows = eb.classify_pool(tmp_path / "pool", base=tmp_path)
    assert len(rows) == 1 and rows[0]["id"] == "q1"


# ---------------------------------------------------------------- 变异验证

def test_mutation_disable_binary_heuristic():
    """变异：把 `_looks_binary` 恒判「非二进制」，裸 x86 码应掉回 A → 证明该判据真在生效。"""
    import tempfile
    raw = b"\xf4\xe4\x92\x0c\x02\xe6\x921\xc0\x8e\xd0\xbc\x01`\x8e\xd8\x8e\xc0\x8e\xe0"
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "stage-2.bin"
        p.write_bytes(raw)
        assert eb.classify([str(p)], "Open in disassembler", "rev", base=d)[0] == "D1"
        orig = eb._looks_binary
        eb._looks_binary = lambda h: False
        try:
            assert eb.classify([str(p)], "Open in disassembler", "rev", base=d)[0] == "A", \
                "变异失败：禁用二进制启发式后仍判 D1，说明该判据没真正生效"
        finally:
            eb._looks_binary = orig
        assert eb.classify([str(p)], "Open in disassembler", "rev", base=d)[0] == "D1"


def test_mutation_disable_archive_peek():
    """变异：禁用归档窥探（内含纯文本的 zip）应保守掉到 D1 → 证明归档判据真在生效。"""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        zp = Path(d) / "handout.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("gen.py", b"print('hi')")
        assert eb.classify([str(zp)], "break this", "crypto", base=d)[0] == "A"
        orig = eb._peek_archive_names
        eb._peek_archive_names = lambda p: None
        try:
            assert eb.classify([str(zp)], "break this", "crypto", base=d)[0] == "D1", \
                "变异失败：禁用归档窥探后仍判 A，说明归档判据没真正生效"
        finally:
            eb._peek_archive_names = orig
        assert eb.classify([str(zp)], "break this", "crypto", base=d)[0] == "A"


def test_archive_own_binary_header_not_mistaken_for_raw(tmp_path):
    """防回归：zip 自身头 PK\\x03\\x04 是二进制，但不能因此判成「裸二进制需反汇编」。"""
    zp = tmp_path / "handout.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("notes.md", b"# task")
    band, reason = eb.classify([str(zp)], "read the notes", "misc", base=tmp_path)
    assert band == "A", reason
