# -*- coding: utf-8 -*-
"""misc_jpeg_padding_stego 求解器回归（2026-10-13）。

覆盖
----
1. 真实题 white.jpg 解出，sha256 与题库 `flag_sha256` 逐字匹配
   （真值从题目对象读，**不硬编码**）；
2. 负例：非 JPEG / 标准 JPEG（无 padding 隐写信道）/ 缺文件 / 空 params
   → 一律 `{"flag": None}`，不崩不谎报；
3. 生产约束：skill 纯标准库（源码无 numpy/PIL/cv2 import；打桩屏蔽
   三方库后仍可解出真題——生产子进程是 spawn，任何解释器下须可跑）；
4. 反捷径：skill 源码**不得含 flag 明文或 sha256**（防"查表短路"）；
5. 单测不绕过生产形态：`run()` 契约 + 内嵌函数（分段/窗口 IoU）各自
   的针对性用例；
6. 变异：rot90 方向写反 / 阈值乱设 / 模板清空 / 去掉宽度相等约束 →
   真实题必须解不出（证明这些部件真在承载正确性，不是摆设）。
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import misc_jpeg_padding_stego as M  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_QDIR = _ROOT / "data" / "questions_external" / "misc" / "ext_gctf2023_papapapa"
_ATT = _QDIR / "_attachments" / "white.jpg"
_QJSON = _QDIR.parent / "ext_gctf2023_papapapa.json"

# 从题库读真值（缺文件则 skip；gitignore 不入库）
_TRUTH_SHA = ""
if _QJSON.is_file():
    try:
        _TRUTH_SHA = str(json.loads(_QJSON.read_text(encoding="utf-8"))
                         .get("flag_sha256") or "")
    except Exception:  # noqa: BLE001
        _TRUTH_SHA = ""

needs_question = pytest.mark.skipif(
    not (_ATT.is_file() and _TRUTH_SHA),
    reason="外部题库 papapapa 未落地（gitignore）")


# --------------------------------------------------------------------------
# 1) 真实题解出
# --------------------------------------------------------------------------
@needs_question
def test_solves_real_white_jpg():
    out = M.run({"path": str(_ATT)})
    flag = (out or {}).get("flag")
    assert flag, "skill 未解出 papapapa"
    assert M._FLAG_SHAPE_RE.fullmatch(flag), f"形态不合法: {flag!r}"
    assert hashlib.sha256(flag.encode()).hexdigest() == _TRUTH_SHA


@needs_question
def test_solve_jpeg_bytes_entry():
    data = _ATT.read_bytes()
    flag = M.solve_jpeg(data)
    assert flag
    assert hashlib.sha256(flag.encode()).hexdigest() == _TRUTH_SHA


@needs_question
def test_strip_geometry():
    """装配几何：128 个 Y padding 块 → 64×2 块阵 → rot90 CCW 后 16×512。"""
    info = M._parse_jpeg(_ATT.read_bytes())
    blocks = M._decode_blocks(info)
    y_id = info.scan_comps[0][0]
    y_tq = next(c[3] for c in info.comps if c[0] == y_id)
    Q = info.dqt[y_tq]
    Qm = [Q[i * 8:(i + 1) * 8] for i in range(8)]
    pad = M._y_padding_blocks(blocks, y_id)
    assert len(pad) == 128
    assert sum(1 for b in pad if b.acs) == 114  # 携带 AC 的数据块
    strip = M._render_strip(pad, Qm)
    assert len(strip) == 16 and len(strip[0]) == 512


# --------------------------------------------------------------------------
# 2) 负例（必须优雅放弃，不崩不谎报）
# --------------------------------------------------------------------------
def test_negative_non_jpeg(tmp_path):
    p = tmp_path / "not_a_jpeg.bin"
    p.write_bytes(b"hello world, definitely not a jpeg" * 10)
    assert M.run({"path": str(p)}) == {"flag": None}


def test_negative_truncated_jpeg(tmp_path):
    data = _ATT.read_bytes()[:40] if _ATT.is_file() else b"\xff\xd8\xff\xe0" + b"\x00" * 36
    p = tmp_path / "trunc.jpg"
    p.write_bytes(data)
    out = M.run({"path": str(p)})
    assert out == {"flag": None} or out.get("flag") is None


def test_negative_standard_jpeg_no_channel(tmp_path):
    """标准 JPEG（宽高均为 MCU 整数倍、padding 全为平块）→ 无隐写信道。"""
    Image = pytest.importorskip("PIL.Image", reason="PIL 仅测试夹具用")
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), (255, 255, 255)).save(buf, "JPEG")
    p = tmp_path / "plain64.jpg"
    p.write_bytes(buf.getvalue())
    assert M.run({"path": str(p)}) == {"flag": None}


def test_negative_odd_size_standard_jpeg(tmp_path):
    """非整数倍宽但 padding 仍为平块的标准图 → 同样无信道（防"有 padding 就开火"）。"""
    Image = pytest.importorskip("PIL.Image", reason="PIL 仅测试夹具用")
    buf = io.BytesIO()
    Image.new("RGB", (70, 70), (255, 255, 255)).save(buf, "JPEG")
    p = tmp_path / "plain70.jpg"
    p.write_bytes(buf.getvalue())
    assert M.run({"path": str(p)}) == {"flag": None}


def test_run_contract_missing_and_empty(tmp_path):
    assert M.run({"path": str(tmp_path / "nope.jpg")}) == {"flag": None}
    assert M.run({}) == {"flag": None}
    assert M.run(None) == {"flag": None}
    assert M.run({"path": ""}) == {"flag": None}


# --------------------------------------------------------------------------
# 3) 生产约束：纯标准库（spawn 子进程须任何解释器可跑）
# --------------------------------------------------------------------------
def test_no_third_party_imports_in_source():
    """AST 级检查：skill 只许 import 标准库（spawn 子进程须任何解释器可跑）。

    注意不能用子串扫描——docstring 里「无 numpy / 无 PIL」的说明文字
    会误伤；必须解析真实 import 语句的模块根。
    """
    import ast

    src = (_ROOT / "skills" / "misc_jpeg_padding_stego.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    allowed = {"math", "os", "re", "struct", "__future__", "typing"}
    extra = roots - allowed
    assert not extra, f"skill 出现非标准库 import: {sorted(extra)}"


@needs_question
def test_solves_with_third_party_imports_blocked(monkeypatch):
    """打桩屏蔽 numpy/PIL/cv2 import 后仍解出——证明无隐藏三方依赖。"""
    real_import = __import__

    def guarded(name, *a, **kw):
        root = name.split(".")[0]
        if root in ("numpy", "PIL", "cv2", "scipy", "pandas"):
            raise ImportError(f"blocked by test: {name}")
        return real_import(name, *a, **kw)

    monkeypatch.setattr("builtins.__import__", guarded)
    out = M.run({"path": str(_ATT)})
    flag = (out or {}).get("flag")
    assert flag
    assert hashlib.sha256(flag.encode()).hexdigest() == _TRUTH_SHA


# --------------------------------------------------------------------------
# 4) 反捷径：源码不得含 flag 明文 / sha256
# --------------------------------------------------------------------------
@needs_question
def test_no_flag_plaintext_or_sha_in_source():
    src = (_ROOT / "skills" / "misc_jpeg_padding_stego.py").read_text(encoding="utf-8")
    assert _TRUTH_SHA not in src, "skill 源码含 sha256 —— 疑似查表短路"
    # flag 明文同理：用题库真值反查（题库只存 sha256 时从解出结果推）
    out = M.run({"path": str(_ATT)})
    flag = (out or {}).get("flag")
    if flag:
        assert flag not in src, "skill 源码含 flag 明文 —— 疑似查表短路"


# --------------------------------------------------------------------------
# 5) 内嵌函数针对性用例
# --------------------------------------------------------------------------
def test_segments_merge_single_gap():
    bw = [[False] * 12 for _ in range(16)]
    for c in (0, 1, 3, 8, 9):          # 0-1 与 3 间隔 1px → 合并；3 与 8 间隔 4px → 断开
        for r in range(16):
            bw[r][c] = True
    segs = M._segments(bw, 0, 12)
    assert segs == [(0, 4), (8, 10)]


def test_segments_drop_noise_by_ink_count():
    bw = [[False] * 20 for _ in range(16)]
    for c in (0, 1, 2):                # 48 墨 → 保留
        for r in range(16):
            bw[r][c] = True
    bw[0][10] = True                   # 1 墨 → 噪声段滤除
    segs = M._segments(bw, 0, 20)
    assert segs == [(0, 3)]


def test_iou_at_is_windowed():
    """回归：union 必须只算模板窗口（曾漏掩 → 算进整行，IoU 恒 ≈0.02）。"""
    ncols = 64
    smasks = [0] * 16
    # 第 0 行：窗口 [8,12) 有墨，窗口外 [40,64) 也铺满墨
    smasks[0] = (1 << (ncols - 1 - 8)) | (1 << (ncols - 1 - 9)) | \
        (1 << (ncols - 1 - 10)) | (1 << (ncols - 1 - 11))
    smasks[0] |= ((1 << 24) - 1) << (ncols - 64)
    rows = [0b1111] + [0] * 15          # 模板 w=4，仅第 0 行有墨且与窗口一致
    iou = M._iou_at(smasks, ncols, 8, 4, rows)
    assert iou == 1.0


def test_iou_at_rejects_out_of_range():
    smasks = [0] * 16
    assert M._iou_at(smasks, 32, 30, 4, [0] * 16) == 0.0   # x+w > ncols
    assert M._iou_at(smasks, 32, 0, 4, [0] * 16) == 0.0    # w=0


def test_templates_are_bitmaps_only():
    """模板只许是 (char, width, 16 行位图)——不含答案表结构。"""
    assert M._TEMPLATES, "模板为空（标定产物未嵌入）"
    chars = set()
    for entry in M._TEMPLATES:
        ch, w, rows = entry
        assert isinstance(ch, str) and len(ch) == 1
        assert isinstance(w, int) and 2 <= w <= 12
        assert len(rows) == 16
        assert all(0 <= r < (1 << w) for r in rows)
        chars.add(ch)
    assert len(chars) >= 20            # 24 个唯一字符（同字多实例）


# --------------------------------------------------------------------------
# 6) 变异：这些部件必须真在承载正确性
# --------------------------------------------------------------------------
@needs_question
def test_mutation_scan_order_assembly(monkeypatch):
    """装配退化成「扫描序两两配对 + 滤除 DC-only 平块」（skill 初版做法）
    → 真实题必须解不出。注意：rot90 方向变异**测不出问题**——4 取向兜底里
    rot180(CW)==CCW 会补偿它；坐标装配才是真正承载正确性的部件。
    """

    def scan_order_render(pad_blocks, Q):
        db = [b for b in pad_blocks if b.acs]
        n = len(db)
        W = 2
        H = n // W
        img = [[0] * (W * 8) for _ in range(H * 8)]
        for i in range(H * W):
            b = db[i]
            r, c = divmod(i, W)
            px = M._block_pixels(b.dc, b.acs, Q)
            for yy in range(8):
                img[r * 8 + yy][c * 8:c * 8 + 8] = px[yy]
        wcols, hrows = W * 8, H * 8
        return [[img[j][wcols - 1 - i] for j in range(hrows)] for i in range(wcols)]

    monkeypatch.setattr(M, "_render_strip", scan_order_render)
    assert M.run({"path": str(_ATT)})["flag"] is None


@needs_question
def test_mutation_threshold_broken(monkeypatch):
    """阈值乱设（全墨/全白）→ 解不出。"""
    monkeypatch.setattr(M, "_INK_THRESHOLD", 255)
    assert M.run({"path": str(_ATT)})["flag"] is None
    monkeypatch.setattr(M, "_INK_THRESHOLD", 0)
    assert M.run({"path": str(_ATT)})["flag"] is None


@needs_question
def test_mutation_templates_emptied(monkeypatch):
    """模板清空 → 分段匹配无从下手（fail-closed）。"""
    monkeypatch.setattr(M, "_TEMPLATES", [])
    assert M.run({"path": str(_ATT)})["flag"] is None


@needs_question
def test_mutation_width_constraint_removed(monkeypatch):
    """去掉「段宽=模板宽」约束 → 窄模板跨段错配，产出**形似实错**的串
    （实测 'bacl' 冒充 'back'）——必须产不出 sha256 匹配的真 flag。
    这正是下游 sha256 闸存在的理由：形态合法 ≠ 解出。
    """
    import hashlib as _h

    def loose_match(bw, x0, x1):
        ncols = len(bw[0]) if bw else 0
        smasks = M._row_masks(bw)
        out = []
        for a, b in M._segments(bw, x0, x1):
            best_ch, best_iou = None, M._MIN_SEG_IOU
            for ch, tw, rows in M._TEMPLATES:
                iou = M._iou_at(smasks, ncols, a, tw, rows)
                if iou > best_iou:
                    best_iou, best_ch = iou, ch
            if best_ch is None:
                return None
            out.append(best_ch)
        return "".join(out) if out else None

    monkeypatch.setattr(M, "_match_segments", loose_match)
    out = M.run({"path": str(_ATT)})
    flag = (out or {}).get("flag")
    if flag:  # 产出了串也不能是 sha256 匹配的真值
        assert _h.sha256(flag.encode()).hexdigest() != _TRUTH_SHA, \
            f"去掉宽度约束仍产出真 flag（约束是摆设？）: {flag!r}"
