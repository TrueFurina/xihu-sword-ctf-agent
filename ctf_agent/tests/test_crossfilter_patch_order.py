"""vendor crossfilter patch 的次序不变式守卫。

背景（2026-10-09，GCTF23 crypto-ziphard 真跑实证）：
入库的 ``bkcrack-1.6.1-crossfilter.patch`` 曾把 second-file 过滤检查插在
``keysBackward.updateBackward(data.ciphertext, indexBackward, 0)``（rewind 到
密码初始化态）**之前**——用 flag 中段状态去解 junk.dat 的 12 字节加密头，
真候选全灭，表现为「4,194,304 个 Z 值 100% 扫完 → Could not find the keys」。
修复 = 检查移到 rewind 之后（keysBackward 此时持有全条目共享的密码初始化态，
才能解第二文件的头）。

本测试锁住三条不变式，防历史 bug 回退：
  ① Attack.cpp hunk：g_second_file 检查块必须在 rewind 行之后；
  ② Data.cpp hunk：ATTACK_SIZE 总量检查必须被 ``#if 0`` 停用（7+1+隐含字节=9 < 12）；
  ③ main.cpp hunk：保留 "second-file cross-filter enabled" 自检回显。

㉚ 纪律：判定函数必须可被合成数据穿透——本文件自带正/反两个合成 patch 夹具，
反例（检查在 rewind 之前）必须被判 False，否则判定逻辑本身失真。
"""

from __future__ import annotations

from pathlib import Path

PATCH_PATH = (
    Path(__file__).resolve().parents[1] / "docker" / "vendor" / "bkcrack-1.6.1-crossfilter.patch"
)

REWIND_LINE = "keysBackward.updateBackward(data.ciphertext, indexBackward, 0);"
CHECK_BLOCK_LINE = "if(g_second_file)"
CROSSFILTER_ECHO = "second-file cross-filter enabled"


def _hunk_of(patch_text: str, filename: str) -> str:
    """取 patch 中指定源文件的 hunk 文本（从该文件的 --- 行到下一个 --- 行或结尾）。"""
    marker = "--- a/bkcrack-1.6.1/src/" + filename
    start = patch_text.find(marker)
    if start < 0:
        return ""
    rest = patch_text[start + len(marker):]
    nxt = rest.find("\n--- a/")
    return rest if nxt < 0 else rest[:nxt]


def _order_invariant_holds(attack_hunk: str) -> bool:
    """不变式①：rewind 行存在，且 g_second_file 检查块在其之后。"""
    rewind = attack_hunk.find(REWIND_LINE)
    check = attack_hunk.find(CHECK_BLOCK_LINE)
    return rewind >= 0 and check > rewind


def _attack_size_disabled(data_hunk: str) -> bool:
    """不变式②：ATTACK_SIZE 总量检查被 #if 0 / #endif 停用。"""
    gate = data_hunk.find("#if 0")
    throw = data_hunk.find("Attack::ATTACK_SIZE")
    endif = data_hunk.find("#endif", data_hunk.find("not enough plaintext"))
    return 0 <= gate < throw < endif


def test_patch_file_exists() -> None:
    assert PATCH_PATH.is_file(), f"vendor patch 缺失: {PATCH_PATH}"


def test_real_patch_check_after_rewind() -> None:
    hunk = _hunk_of(PATCH_PATH.read_text(encoding="utf-8"), "Attack.cpp")
    assert hunk, "patch 中找不到 Attack.cpp hunk"
    assert _order_invariant_holds(hunk), (
        "cross-file 检查必须位于 rewind(updateBackward 到密码初始化态)之后；"
        "位于之前会用 flag 中段状态解 junk 头，真候选全灭（2026-10-09 真跑实证）"
    )


def test_real_patch_attack_size_check_disabled() -> None:
    hunk = _hunk_of(PATCH_PATH.read_text(encoding="utf-8"), "Data.cpp")
    assert hunk, "patch 中找不到 Data.cpp hunk"
    assert _attack_size_disabled(hunk), "ATTACK_SIZE 检查必须被 #if 0 停用（明文仅 9 字节）"


def test_real_patch_keeps_crossfilter_echo() -> None:
    hunk = _hunk_of(PATCH_PATH.read_text(encoding="utf-8"), "main.cpp")
    assert CROSSFILTER_ECHO in hunk, "main.cpp hunk 丢失 cross-filter 回显（构建即自检的抓手）"


def test_patch_covers_all_three_files() -> None:
    text = PATCH_PATH.read_text(encoding="utf-8")
    for filename in ("Attack.cpp", "Data.cpp", "main.cpp"):
        assert f"--- a/bkcrack-1.6.1/src/{filename}" in text, f"hunk 缺失: {filename}"


# ── ㉚ 合成自检：判定函数必须能区分正/反例，否则守卫本身失真 ──────────────────

_SYNTHETIC_CORRECT = """\
--- a/bkcrack-1.6.1/src/Attack.cpp
+++ b/bkcrack-1.6.1/src/Attack.cpp
@@ -1,3 +1,5 @@
     // get the keys associated with the initial state
     keysBackward.updateBackward(data.ciphertext, indexBackward, 0);
+    if(g_second_file)
+    {
+    }
"""


def test_synthetic_reversed_order_is_rejected() -> None:
    """检查块在 rewind 之前的合成 patch 必须判 False（变异背书）。"""
    reversed_hunk = (
        " // all tests passed\n"
        "+    if(g_second_file)\n"
        "+    {\n"
        "     // get the keys associated with the initial state\n"
        "     keysBackward.updateBackward(data.ciphertext, indexBackward, 0);\n"
    )
    assert not _order_invariant_holds(reversed_hunk)


def test_synthetic_missing_rewind_is_rejected() -> None:
    """rewind 行缺失（可能被误删）时判 False——fail-closed。"""
    assert not _order_invariant_holds("+    if(g_second_file)\n")


def test_synthetic_correct_order_passes() -> None:
    assert _order_invariant_holds(_SYNTHETIC_CORRECT)
