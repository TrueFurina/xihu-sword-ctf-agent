# -*- coding: utf-8 -*-
"""PR #37 测试：presolve zip 文件名链快速通道（击败并发竞速「浅层诱饵抢答」）。

背景：presolve 主循环是 30+ 路并发「先完成且命中者即返回」，浅层文本诱饵
（如第一层 flag.txt 的 `flag{ni_cai?}`）会抢跑深层结构性真解。本测试验证在并发
启动**之前**串行的 `_zip_chain_quick_flag` 能拿到真 flag，且对各类非目标输入零误报。

随仓库 conftest 自动隔离黑板，本测试额外用 id="" 规避任何黑板写入。
"""
import base64
import os
import zipfile

import pytest

from core import presolve
import skills.zip_filename_chain_decode as chain_skill


def _build_nested_zip(real_flag: str, decoy: str, tmp: str) -> str:
    """构造 outer.zip -> <S>.zip -> flag.txt(decoy)，S=base32(real_flag)。

    zip_filename_chain_decode 把每层 .zip 文件名（去扩展名）收集进 chain，
    从尾到头拼成 reversed_chain 再 base32 解码 == S == real_flag。最内层
    flag.txt 放诱饵，验证「结构性证据优先于浅层文本扫描」。
    """
    S = base64.b32encode(real_flag.encode()).decode().rstrip("=")
    inner = os.path.join(tmp, "inner.zip")
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("flag.txt", decoy)
    outer = os.path.join(tmp, "outer.zip")
    with zipfile.ZipFile(outer, "w") as z:
        z.write(inner, arcname=f"{S}.zip")
    return outer


def _q(attachments=(), expected_sha256=None, **kw):
    return type(
        "Q",
        (),
        {
            "id": "",  # 空 id ⇒ 不写黑板
            "attachments": list(attachments),
            "expected_sha256": expected_sha256,
            "flag_pattern": kw.get("flag_pattern", ""),
            "category": kw.get("category", "misc"),
            "extra": {},
        },
    )()


def test_zip_chain_returns_real_flag_not_decoy(tmp_path):
    real = "flag{REAL_10663_STRUCTURAL_CHAIN}"
    decoy = "flag{ni_cai?}"
    outer = _build_nested_zip(real, decoy, str(tmp_path))
    got = presolve._zip_chain_quick_flag(_q(attachments=[outer]), None)
    assert got == real, f"期望真 flag，实际={got!r}（诱饵抢答未修复？）"


def test_non_zip_attachment_is_none(tmp_path):
    note = tmp_path / "note.txt"
    note.write_text("flag{SHOULD_NOT_APPEAR}")
    assert presolve._zip_chain_quick_flag(_q(attachments=[str(note)]), None) is None


def test_expected_sha256_defers_to_arbiter(tmp_path):
    real = "flag{REAL_10663_STRUCTURAL_CHAIN}"
    outer = _build_nested_zip(real, "flag{ni_cai?}", str(tmp_path))
    # 声明 expected_sha256 ⇒ 不抢答，让既有 sha256 仲裁逻辑工作
    got = presolve._zip_chain_quick_flag(
        _q(attachments=[outer], expected_sha256="deadbeef" * 8), None
    )
    assert got is None


def test_decoy_only_no_chain_is_none(tmp_path):
    fake = tmp_path / "fakechain.zip"
    with zipfile.ZipFile(str(fake), "w") as z:
        z.writestr("flag.txt", "flag{ni_cai?}")  # 仅诱饵，无文件名链
    assert presolve._zip_chain_quick_flag(_q(attachments=[str(fake)]), None) is None


def test_flag_pattern_gate_filters_mismatch(tmp_path):
    real = "flag{REAL_10663_STRUCTURAL_CHAIN}"
    outer = _build_nested_zip(real, "flag{ni_cai?}", str(tmp_path))
    # flag_pattern 要求 CTF{...}，与真 flag 不符 ⇒ 丢弃
    got = presolve._zip_chain_quick_flag(
        _q(attachments=[outer], flag_pattern=r"CTF\{[^}]+\}"), None
    )
    assert got is None


def test_mutation_chain_decode_broken_returns_none(tmp_path, monkeypatch):
    """变异校验：链解码失效（ok=False）⇒ 快速通道必返回 None（证明非假绿）。"""
    real = "flag{REAL_10663_STRUCTURAL_CHAIN}"
    outer = _build_nested_zip(real, "flag{ni_cai?}", str(tmp_path))

    def broken(_params):
        return {"ok": False, "error": "mutated"}

    monkeypatch.setattr(chain_skill, "zip_filename_chain_decode", broken)
    got = presolve._zip_chain_quick_flag(_q(attachments=[outer]), None)
    assert got is None
