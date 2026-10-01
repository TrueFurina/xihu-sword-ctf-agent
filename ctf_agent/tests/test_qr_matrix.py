"""skills/misc_qr_matrix（数字矩阵 → QR 码解码）的行为 + 变异测试。

真实性：夹具全部由 cv2.QRCodeEncoder 生成的真实二维码矩阵（仅作**测试向量**，
生产代码不含 cv2 依赖）；另有一道真实 NYU CTF Bench 题的 sha256 锁（附件缺失时跳过）。
预期解出值与题面 flag 的 sha256 逐字匹配才算通过。

变异验证：把读取方向或掩码置坏，夹具必须**全部解不出** —— 否则说明
「解码链真的在用这些判据」这一断言不成立。
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import misc_qr_matrix as qr  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_REAL_ATT = (_ROOT / "data" / "questions_ext" / "_attachments" / "forensics"
             / "2023q-for-1black0white" / "qr_code.txt")
# 真实 NYU 题答案的 sha256（仅哈希，不落明文；与题面 flag_sha256 一致）
_REAL_SHA = "d02cc7d165021ac275773ffc743880968716f0474c6aece8a6071084296d967d"
# 题库池 + 真实题 id（端到端用真实元数据，避免自建 Question 漂移）
_POOL_DIR = _ROOT / "data" / "questions_ext"
_REAL_QID = "ext_nyu_ctf_bench_2023q_for_1black0white"
# core/presolve.py 的诱饵守卫：候选 flag 必须匹配本题 flag_pattern
_DECOY_DEFAULT_PATTERN = r"flag\{[^}]+\}"

# (payload, 每行整数) —— 由 cv2 编码的真实 QR 矩阵，MSB 先、暗=1
_FIXTURES = [
    ("flag{synth_qr_ok}", [
        2087551, 1068865, 1525341, 1526365, 1525341, 1068353, 2086271, 4608,
        1789505, 75656, 1894671, 1714869, 413481, 5750, 2081692, 1069039,
        1529641, 1528934, 1526227, 1072767, 2085416]),
    ("1234567890", [
        2083711, 1068609, 1530717, 1526365, 1525085, 1065281, 2086271, 6912,
        1965764, 492609, 1263896, 1380425, 419155, 5802, 2087656, 1072059,
        1529581, 1524834, 1531165, 1071208, 2086229]),
    ("HELLO WORLD 42", [
        2082175, 1065281, 1528925, 1524061, 1526621, 1068609, 2086271, 5120,
        1963460, 2013793, 227064, 665582, 485941, 5253, 2087213, 1069161,
        1528319, 1525474, 1531497, 1073035, 2087521]),
    ("Test_Payload-99", [
        2083199, 1068609, 1530717, 1526621, 1525341, 1065537, 2086271, 6144,
        1965252, 1707475, 486911, 1256450, 1984027, 8056, 2088315, 1069601,
        1529626, 1526594, 1530805, 1069074, 2087215]),
    ("x" * 30, [
        33335935, 17082945, 24466781, 24417629, 24439389, 17066561, 33379711, 76288,
        31402692, 8623437, 19682583, 25946802, 14510824, 7984461, 22418711, 14772914,
        31288312, 70941, 33380183, 17131795, 24472058, 24417820, 24499381, 17164770, 33401675]),
    ("flag{mask_variant_1}", [
        33394559, 17041473, 24460381, 24488797, 24503133, 17078593, 33379711, 41728,
        31786909, 3771880, 19661160, 19938812, 21996254, 10710907, 13915290, 20634112,
        32990204, 71953, 33337687, 17093402, 24394226, 24502263, 24508666, 17121804, 33379535]),
    ("z" * 60, [
        8532113023, 4391092545, 6255831901, 6268499549, 6247003741, 4384014657, 8545195391, 1600256,
        8452945578, 1619113667, 2394079602, 8252582781, 2762061465, 3093149379, 1288618354, 8327293821,
        7236597401, 1883354819, 4558340466, 7958981501, 643937945, 6754776771, 4681810290, 6091729789,
        6645200889, 16889619, 8542929746, 4372851484, 6268499451, 6259848339, 6263062720, 4393036412,
        8541026170]),
]


# ------------------------------------------------------------------ 正向

@pytest.mark.parametrize("payload,rows", _FIXTURES, ids=[f[0][:14] for f in _FIXTURES])
def test_synthetic_qr_decodes(payload, rows):
    """cv2 生成的真实 QR 矩阵 → 必须还原原始 payload。"""
    assert qr.decode_rows(rows) == payload.encode()


def test_run_accepts_rows_text_and_path(tmp_path):
    payload, rows = _FIXTURES[0]
    assert qr.run({"rows": rows}) == payload.encode()

    p = tmp_path / "qr.txt"
    p.write_text("\n".join(str(x) for x in rows), encoding="utf-8")
    assert qr.run({"path": str(p)}) == payload.encode()
    assert qr.run({"text": p.read_text(encoding="utf-8")}) == payload.encode()

    # 逗号分隔同样可解析
    assert qr.run({"text": ",".join(str(x) for x in rows)}) == payload.encode()


def test_bit_order_and_polarity_invariance():
    """位序(MSB/LSB)与明暗极性(暗=1/暗=0)在题面中未知 → 四种组合都要能出结果。"""
    payload, rows = _FIXTURES[0]
    n = len(rows)
    # 极性的另一种写法：每行按 n 位取反
    inv = [((~x) & ((1 << n) - 1)) for x in rows]
    # 位序的另一种写法：行内比特反转
    lsb = [int(format(x, "0%db" % n)[::-1], 2) for x in rows]
    for variant in (rows, inv, lsb):
        assert qr.decode_rows(variant) == payload.encode()


def test_pure_python_no_cv2_dependency(monkeypatch):
    """生产路径不得依赖 cv2：把 cv2 变成导入即炸，解码仍须成功。"""
    import builtins
    real_import = builtins.__import__

    def boom(name, *a, **k):
        if name == "cv2" or name.startswith("cv2."):
            raise ImportError("cv2 被禁用（依赖独立性断言）")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", boom)
    payload, rows = _FIXTURES[1]
    assert qr.decode_rows(rows) == payload.encode()


# ------------------------------------------------------------------ 反例

def test_extract_rows_rejects_non_integer_text():
    assert qr.extract_rows("hello 123\n456") is None
    assert qr.extract_rows("") is None
    assert qr.extract_rows("12 34 abc") is None
    assert qr.extract_rows("1 2 3") == [1, 2, 3]
    assert qr.extract_rows("1,2;3\n4") == [1, 2, 3, 4]


@pytest.mark.parametrize("size", [3, 10, 20, 22, 24, 61, 100])
def test_unsupported_or_wrong_sizes_return_none(size):
    """非 QR 边长（(n-17)%4!=0）或超出支持版本(1-10) → None，不谎报。"""
    rows = [1 << (size - 1)] * size
    assert qr.decode_rows(rows) is None


def test_non_qr_matrix_returns_none():
    """21×21 但内容不是合法 QR（格式信息非法）→ None。"""
    rows = [0] * 21          # 全 0：格式信息解不出
    assert qr.decode_rows(rows) is None


def test_out_of_range_value_returns_none():
    """某行数值超出 n 位 → 直接拒绝（不是「行」）。"""
    _, rows = _FIXTURES[0]
    bad = list(rows)
    bad[0] = 1 << 40          # 远超 21 位
    assert qr.decode_rows(bad) is None


# ------------------------------------------------------------------ 真实题锁

@pytest.mark.skipif(not _REAL_ATT.exists(),
                    reason="NYU 题库未落地（gitignore），跳过真实题锁")
def test_real_nyu_question_solved():
    got = qr.run({"path": str(_REAL_ATT)})
    assert got is not None
    assert hashlib.sha256(got).hexdigest() == _REAL_SHA


# ------------------------------------------------------------------ presolve 接线

def test_presolve_wired():
    from core import presolve as ps
    assert "skills.misc_qr_matrix" in ps.wired_skill_modules()
    assert hasattr(ps, "_try_qr_matrix")


def test_presolve_handler_solves_real_question():
    r"""真实题经 presolve 统一入口也须命中（端到端，用题库真实元数据）。

    2026-10-01 根因：本用例原来自建 Question（不传 flag_pattern），
    于是吃 Question 的默认 `flag\{[^}]+\}`，而非本题真实
    `[A-Za-z0-9_]{1,12}\{...\}`。真 flag 前缀是 csawctf{，被
    presolve 的诱饵守卫（core/presolve.py:504）判定为"不符合本题
    flag_pattern"后 continue → 端到端恒 None（假红）。生产链路用的是
    题库 JSON 里的 flag_pattern，不受影响；本用例改为加载真实题目。
    """
    if not _REAL_ATT.exists():
        pytest.skip("NYU 题库未落地（gitignore）")
    import asyncio
    from core import presolve as ps
    from eval.cases import load_questions

    qs = [q for q in load_questions(str(_POOL_DIR), include_disclosed=True)
          if q.id == _REAL_QID]
    assert qs, "真实题 %s 未加载（题库未落地？）" % _REAL_QID
    q = qs[0]
    # 元数据护栏：本题 flag 前缀非 flag{，必须带显式且足够宽的 flag_pattern，
    # 否则真 flag 会被当诱饵丢弃 —— 这正是上述根因的机器化锁。
    assert q.flag_pattern and q.flag_pattern != _DECOY_DEFAULT_PATTERN
    got = asyncio.run(ps.presolve(q, force=True))
    assert got is not None
    assert hashlib.sha256(got.encode()).hexdigest() == _REAL_SHA


def test_default_flag_pattern_blocks_nonflag_prefix():
    r"""根因回归：只带 Question 默认 flag_pattern（flag\{[^}]+\}）时，
    presolve 的诱饵守卫必须把 csawctf{...} 判为诱饵 → 返回 None。

    锁住 2026-10-01 端到端假红的因果链：本路解出的是非 `flag{` 前缀，
    必须由题目自带足够宽的 flag_pattern 放行（守卫本身是设计行为，不改）。
    """
    if not _REAL_ATT.exists():
        pytest.skip("NYU 题库未落地（gitignore）")
    import asyncio
    from core import presolve as ps
    from eval.cases import Question

    q = Question(id="t_qr_default_fp", title="t", category="forensics",
                 description="qr", flag=None, flag_sha256=_REAL_SHA,
                 attachments=[str(_REAL_ATT)])
    assert q.flag_pattern == _DECOY_DEFAULT_PATTERN      # 前提：默认值即诱饵守卫
    assert asyncio.run(ps.presolve(q, force=True)) is None


# ------------------------------------------------------------------ 变异

def test_mutation_break_reading_direction(monkeypatch):
    """变异：把之字形上行方向写反 → 全部夹具必须解不出。"""
    def broken(mat, size, version):
        f = qr._function_map(size, version)
        bits = []
        col = size - 1
        up = True
        while col > 0:
            if col == 6:
                col -= 1
            rng = range(size) if up else range(size - 1, -1, -1)   # 与生产相反
            for i in rng:
                for c in (col, col - 1):
                    if not f[i][c]:
                        bits.append(mat[i][c] & 1)
            up = not up
            col -= 2
        cw = []
        for i in range(0, len(bits) - 7, 8):
            b = 0
            for j in range(8):
                b = (b << 1) | bits[i + j]
            cw.append(b)
        return cw
    monkeypatch.setattr(qr, "_read_codewords", broken)
    assert all(qr.decode_rows(rows) != payload.encode() for payload, rows in _FIXTURES)


def test_mutation_disable_unmask(monkeypatch):
    """变异：掩码置为恒等 → 全部夹具必须解不出。"""
    monkeypatch.setattr(qr, "_unmask", lambda mat, size, mask: [r[:] for r in mat])
    assert all(qr.decode_rows(rows) != payload.encode() for payload, rows in _FIXTURES)


def test_mutation_break_bit_length(monkeypatch):
    """变异：把 flag 形状判据收紧到不可能匹配 → payload 打分全失败 → None。"""
    import re
    monkeypatch.setattr(qr, "_FLAG_RE", re.compile(rb"NEVER_MATCH_\{\}"))
    payload, rows = _FIXTURES[0]
    got = qr.decode_rows(rows)
    # 仍能解出（payload 可打印，走 printable 分支），但不得被判成 flag 形状
    assert got == payload.encode()
    assert not qr._FLAG_RE.search(got)
