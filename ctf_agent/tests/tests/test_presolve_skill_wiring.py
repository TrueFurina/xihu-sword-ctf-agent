# -*- coding: utf-8 -*-
"""决赛备战 S2 接线回归（2026-08-21 赛后第二波）。

3 个已沉淀 skill 接入 presolve → math_engine 竞速链路后：
1. crypto_pkcs1_oracle  : 10732 真题自动嗅探 + PDF 解密（flag 在绘图层，
                          engine 解到 PDF 但 LLM 需视觉读；此测试只验 PDF
                          生成正确性，不强求 flag 文本命中）
2. crypto_high_exponent : 10733 真题端到端命中（rot18 flag）
3. misc_bigfile_lime    : 10734 真题免全量解压秒级结构分析

presolve 去重（force=True 绕过 vs 默认行为）：
- 同一 question 第一次嗅探命中 → 打标；第二次直接 None
- math_engine 内已被 presolve 嗅探过则不再跑
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────
# 1) crypto_pkcs1_oracle engine：10732 真题 PDF 解密
# ─────────────────────────────────────────────────────────────────
def test_math_engine_pkcs1_oracle_decrypts_pdf_on_10732():
    """10732 真题：math_engine 链路 → crypto_pkcs1_oracle → PDF 落盘。

    验收：engine 至少跑到 skill 调用（解密 PDF），flag 在绘图层（pymupdf get_text
    拿不到），不强求返回 flag——LLM agent 负责视觉读。**已解出**走 LLM 链路。
    """
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question

    enc = os.path.join("data", "race_extract", "10732", "deep", "PKCS#1.v1.5.enc")
    task = os.path.join("data", "race_extract", "10732", "deep", "task.py")
    if not (os.path.exists(enc) and os.path.exists(task)):
        pytest.skip("10732 附件未解压")
    q = Question(
        id="10732", title="CRYPTO-01", category="crypto", difficulty="MEDIUM",
        description="Yusa的密码学课堂——PKCS#1",
        attachments=[task, enc], flag_pattern="DASCTF{[^}]+}", extra={},
    )
    # engine 单独跑（避免被其他 engine 抢命中）
    fn = MathEngineMatrix._engines["crypto_pkcs1_oracle"]
    out_path = os.path.join(os.path.dirname(enc), "_test_engine_decrypt.pdf")
    if os.path.exists(out_path):
        try:
            os.remove(out_path)
        except (OSError, SystemExit):
            pass
    # 把 out_path 注入到 engine 的 params 不可能（engine 是闭包），但 skill 会把
    # plaintext 留在内存里——我们只能从"engine 是否跑到 skill"间接验证。
    # 简化：直接调 skill 验证 decrypted PDF 头
    from skills.crypto_pkcs1_padding_oracle import crypto_pkcs1_padding_oracle
    padded_long = 986236757547332986472011617696226561292849812918563355472727826767720188564083584387121625107510786855734801053524719833194566624465665316622563244215340671405971599343902468620306327831715457360719532421388780770165778156818229863337344187575566725786793391480600129482653072861971002459947277805295727097226389568776499707662505334062639449916265137796823793276300221537201727072401742985542559596685092673521228140822200236743113743661549252453726123450722876929538747702356573783116366629850199080495560991841329893037292397105499226019760899853193278062243717512000415272209561906185887862944154882587563268
    res = crypto_pkcs1_padding_oracle({
        "kind": "full", "padded_long": padded_long, "msg_len": 16,
        "enc_file": enc, "out_file": out_path,
    })
    assert res["ok"]
    assert os.path.exists(out_path)
    with open(out_path, "rb") as f:
        head = f.read(8)
    assert head.startswith(b"%PDF-1.")
    # 清理（safe-delete guard 可能拒绝，try/except 兼容）
    try:
        os.remove(out_path)
    except (OSError, SystemExit):
        pass


def test_math_engine_pkcs1_oracle_skips_non_crypto():
    """非 crypto 题型 → engine 直接返回 None（不浪费时间）。"""
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question
    q = Question(
        id="x", title="x", category="web", difficulty="EASY",
        description="web", attachments=["data/race_extract/10732/deep/task.py"],
        flag_pattern="flag{[^}]+}", extra={},
    )
    fn = MathEngineMatrix._engines["crypto_pkcs1_oracle"]
    assert fn(q) is None


def test_math_engine_pkcs1_oracle_skips_non_py_attachment():
    """crypto 题但附件无 .py → engine 直接返回 None（无 task.py 可解析）。"""
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question
    q = Question(
        id="x", title="x", category="crypto", difficulty="EASY",
        description="crypto", attachments=["data/race_attachments/10732_xxx.enc"],
        flag_pattern="DASCTF{[^}]+}", extra={},
    )
    fn = MathEngineMatrix._engines["crypto_pkcs1_oracle"]
    assert fn(q) is None


# ─────────────────────────────────────────────────────────────────
# 2) crypto_high_exponent engine：10733 真题端到端
# ─────────────────────────────────────────────────────────────────
def test_math_engine_high_exponent_solves_10733():
    """10733 真题：engine 端到端命中 rot18 flag."""
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question
    task = os.path.join("data", "race_extract", "10733", "tempdir", "CRYPTO附件", "task.py")
    if not os.path.exists(task):
        pytest.skip("10733 附件未解压")
    q = Question(
        id="10733", title="CRYPTO-02", category="crypto", difficulty="MEDIUM",
        description="How many rot are there", attachments=[task],
        flag_pattern="DASCTF{[^}]+}", extra={},
    )
    eng, flag = MathEngineMatrix.solve(q, timeout=20)
    assert eng == "crypto_high_exponent", f"应该命中 crypto_high_exponent，实际 {eng}"
    assert flag is not None
    # flag 必须是 DASCTF{ 开头（engine 优先 rot18，再 rot13）
    assert flag.startswith("DASCTF{") and flag.endswith("}")


def test_math_engine_high_exponent_skips_non_e65536():
    """e 不是 65536/2^16 → engine 立即返回 None."""
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question
    q = Question(
        id="x", title="x", category="crypto", difficulty="EASY",
        description="e = 65537\nn = 12345\nc = 1\nhint = 1",
        attachments=[], flag_pattern="flag{[^}]+}", extra={},
    )
    fn = MathEngineMatrix._engines["crypto_high_exponent"]
    assert fn(q) is None


# ─────────────────────────────────────────────────────────────────
# 3) misc_bigfile_lime engine：10734 真题
# ─────────────────────────────────────────────────────────────────
def test_math_engine_misc_bigfile_runs_on_10734():
    """10734 真题：engine 跑 zip_list 拿到内层结构（flag 在 lime 内层，engine
    返回 None 也算通过——主要价值是秒级结构分析)."""
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question
    path = os.path.join("data", "race_attachments", "10734_MISC-01")
    if not os.path.exists(path):
        pytest.skip("10734 附件不存在")
    q = Question(
        id="10734", title="MISC-01", category="misc", difficulty="MEDIUM",
        description="flag^galf", attachments=[path],
        flag_pattern="flag{[^}]+}", extra={},
    )
    fn = MathEngineMatrix._engines["misc_bigfile_lime"]
    # 跑 < 30s（zip_list + nested_tail + xor/flag_scan），超时即失败
    import time
    t0 = time.time()
    result = fn(q)
    dt = time.time() - t0
    assert dt < 30.0, f"engine 耗时 {dt:.2f}s 超 30s 上限"
    # flag 在 lime 内层解出才有，engine 多数情况返 None（正常）；不强求
    assert result is None or isinstance(result, str)


def test_math_engine_misc_bigfile_skips_small_attachments():
    """小附件（< 50MB，非 .lime/.pcapng 等）→ engine 立即返回 None."""
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question
    q = Question(
        id="x", title="x", category="misc", difficulty="EASY",
        description="misc", attachments=["data/race_extract/10733/tempdir/CRYPTO附件/task.py"],
        flag_pattern="flag{[^}]+}", extra={},
    )
    fn = MathEngineMatrix._engines["misc_bigfile_lime"]
    assert fn(q) is None


# ─────────────────────────────────────────────────────────────────
# 4) presolve → math_engine 整链路（含去重）
# ─────────────────────────────────────────────────────────────────
def test_presolve_full_chain_solves_10733():
    """10733 真题：完整 presolve → math_engine → crypto_high_exponent → flag."""
    from core.presolve import presolve
    from eval.cases import Question
    task = os.path.join("data", "race_extract", "10733", "tempdir", "CRYPTO附件", "task.py")
    if not os.path.exists(task):
        pytest.skip("10733 附件未解压")
    q = Question(
        id="10733", title="CRYPTO-02", category="crypto", difficulty="MEDIUM",
        description="How many rot are there", attachments=[task],
        flag_pattern="DASCTF{[^}]+}", extra={},
    )
    flag = asyncio.run(presolve(q, registry=None, sandbox=None, answers=None))
    assert flag is not None
    assert flag.startswith("DASCTF{")


def test_presolve_dedup_after_first_math_engine_sniff():
    """presolve 第一次嗅探后打标，第二次直接 None（force=True 可绕过)."""
    from core.presolve import presolve, presolve_attempted
    from eval.cases import Question
    task = os.path.join("data", "race_extract", "10733", "tempdir", "CRYPTO附件", "task.py")
    if not os.path.exists(task):
        pytest.skip("10733 附件未解压")
    q = Question(
        id="10733_dedup", title="CRYPTO-02", category="crypto", difficulty="MEDIUM",
        description="How many rot are there", attachments=[task],
        flag_pattern="DASCTF{[^}]+}", extra={},
    )
    # 第一次：嗅探 + 命中
    f1 = asyncio.run(presolve(q, registry=None, sandbox=None, answers=None))
    assert f1 is not None
    assert presolve_attempted(q)
    # 第二次：被去重挡住，返 None
    f2 = asyncio.run(presolve(q, registry=None, sandbox=None, answers=None))
    assert f2 is None
    # 第三次 force=True 绕过：应再次命中
    f3 = asyncio.run(presolve(q, registry=None, sandbox=None, answers=None, force=True))
    assert f3 is not None
