# -*- coding: utf-8 -*-
"""决赛备战 S1 真题实测回归（2026-08-21 赛后第二波）。

三个已沉淀但未接线的 skill 在正式赛真题上的端到端跑通：
1. crypto_pkcs1_padding_oracle : 10732 真题（PKCS#1 v1.5 + AES + PDF）
2. crypto_high_exponent        : 10733 真题（e=65536 + hint 分解 n + ROT 编码明文）
3. misc_bigfile_analysis       : 10734 真题（420MB 嵌套 zip，免全量解压秒级分析）

约束：测试不直接比对明文 flag（防泄漏），只验证：
- skill ok=True
- 关键产物生成（AES key、PDF、P inner entry、ROT 候选等）
- 真题附件实际可解（sample 解出明文再 rot13 应得 DASCTF{...}）
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────
# 1) crypto_pkcs1_padding_oracle：10732 真题
# ─────────────────────────────────────────────────────────────────
def test_pkcs1_unpad_padded_long_recovers_aes_key():
    """10732 真题数据：padded_long + msg_len=16 → AES key 0x44bfc33d0bfb3cd688a074a7adad1504."""
    from skills.crypto_pkcs1_padding_oracle import crypto_pkcs1_padding_oracle
    padded_long = 986236757547332986472011617696226561292849812918563355472727826767720188564083584387121625107510786855734801053524719833194566624465665316622563244215340671405971599343902468620306327831715457360719532421388780770165778156818229863337344187575566725786793391480600129482653072861971002459947277805295727097226389568776499707662505334062639449916265137796823793276300221537201727072401742985542559596685092673521228140822200236743113743661549252453726123450722876929538747702356573783116366629850199080495560991841329893037292397105499226019760899853193278062243717512000415272209561906185887862944154882587563268
    res = crypto_pkcs1_padding_oracle({
        "kind": "unpad", "padded_long": padded_long, "msg_len": 16,
    })
    assert res["ok"], res
    # 关键 AES key（明文 flag 所在 PDF 解密密钥）—— 公开已知，加密参数级
    assert res["msg_hex"] == "44bfc33d0bfb3cd688a074a7adad1504"
    assert res["msg_len"] == 16
    # PS 全零兜底标记
    assert res["method"] == "tail-extract"


def test_pkcs1_full_chain_on_10732_real_attachment():
    """10732 真题附件：full 链 → 有效 PDF。

    跳过若附件未解压到 data/race_extract/10732/（需要本机手动 unzip）。
    """
    enc = os.path.join("data", "race_extract", "10732", "deep", "PKCS#1.v1.5.enc")
    if not os.path.exists(enc):
        # 兼容 deep2 路径（部分环境把内层 zip 解到 deep2/）
        enc = os.path.join("data", "race_extract", "10732", "deep2", "PKCS#1.v1.5.enc")
    if not os.path.exists(enc):
        pytest.skip(f"10732 附件未解压到 {enc}（先跑 unzip）")
    from skills.crypto_pkcs1_padding_oracle import crypto_pkcs1_padding_oracle
    padded_long = 986236757547332986472011617696226561292849812918563355472727826767720188564083584387121625107510786855734801053524719833194566624465665316622563244215340671405971599343902468620306327831715457360719532421388780770165778156818229863337344187575566725786793391480600129482653072861971002459947277805295727097226389568776499707662505334062639449916265137796823793276300221537201727072401742985542559596685092673521228140822200236743113743661549252453726123450722876929538747702356573783116366629850199080495560991841329893037292397105499226019760899853193278062243717512000415272209561906185887862944154882587563268
    out = os.path.join(os.path.dirname(enc), "_test_decrypted.pdf")
    res = crypto_pkcs1_padding_oracle({
        "kind": "full", "padded_long": padded_long, "msg_len": 16,
        "enc_file": enc, "out_file": out,
    })
    assert res["ok"], res
    assert res["steps"]["unpad"]["msg_hex"] == "44bfc33d0bfb3cd688a074a7adad1504"
    assert res["steps"]["aes_ecb"]["file_type"] == "PDF"
    assert res["steps"]["aes_ecb"]["size"] == 38624
    # PDF 头校验
    with open(out, "rb") as f:
        head = f.read(8)
    assert head.startswith(b"%PDF-1.")
    # 清理（safe-delete guard 可能会拒绝，try/except 兼容）
    try:
        os.remove(out)
    except (OSError, SystemExit):
        pass


# ─────────────────────────────────────────────────────────────────
# 2) crypto_high_exponent：10733 真题
# ─────────────────────────────────────────────────────────────────
def test_high_exponent_factor_10733_hint_decomposes_n():
    """10733 真题：hint=pow(e*p+e**2, q, n) → gcd(W^2-hint, n) = p."""
    from skills.crypto_high_exponent import factor_from_hint
    n = 131232786046474875167899992758388342524496883222860498694293714537118780151392850883679257361099172761516964104115167485944225089583991161038144993589322315250529302275646269196618503385962458635181473103926087951239559460161218447795578503981054097990206859884036249764383918404640987230150854235563692800669
    e = 65536
    hint = 101048855492044571417475830924088947184757234444475406804947498377420789778570832667138477666669908690663759417316798982038542431531087217671616502327573935462498550576600180793553880691247281813287212166428236802504214599757066100450668324529765827891463527861160593648623157792143035729770978865516948880313
    res = factor_from_hint(hint, e, n)
    assert res["ok"], res
    p, q = res["p"], res["q"]
    assert p * q == n
    # p, q 都 3 mod 4（odd-subgroup 快速路径前提）
    assert p % 4 == 3 and q % 4 == 3
    from Crypto.Util.number import isPrime
    assert isPrime(p) and isPrime(q)


def test_high_exponent_auto_10733_recovers_rot_encoded_flag():
    """10733 真题：auto 链 → 明文 m（ROT 编码）+ rot13/rot18 候选。"""
    from skills.crypto_high_exponent import crypto_high_exponent
    n = 131232786046474875167899992758388342524496883222860498694293714537118780151392850883679257361099172761516964104115167485944225089583991161038144993589322315250529302275646269196618503385962458635181473103926087951239559460161218447795578503981054097990206859884036249764383918404640987230150854235563692800669
    c = 62214676810380175097525195047581624344610596576389901532958749194333175927146005969879818861882074690471600028484419966943711467342568120045965690332607166015419112255944582319675084071747302548088333383655637474764450810187215177625206094644430662667402073753343732910706186228919546522301643978766618493433
    e = 65536
    hint = 101048855492044571417475830924088947184757234444475406804947498377420789778570832667138477666669908690663759417316798982038542431531087217671616502327573935462498550576600180793553880691247281813287212166428236802504214599757066100450668324529765827891463527861160593648623157792143035729770978865516948880313
    res = crypto_high_exponent({
        "kind": "auto", "c": c, "e": e, "n": n, "hint": hint,
        "prefixes": ["DASCTF{", "flag{", "ctf{", "QNFPGS{"],
        "max_flag_len": 128,
    })
    assert res["ok"], res
    # 明文本身是 ROT 编码 flag
    assert res["flag"].startswith("QNFPGS{") and res["flag"].endswith("}")
    # skill 应自动给出 rot13 / rot18 候选
    assert "rot13" in res, "明文是 ROT 编码时 skill 应附 rot13 候选"
    assert "rot18" in res, "明文是 ROT 编码时 skill 应附 rot18 候选"
    # rot13 后必须以 DASCTF{ 开头（题面要求）—— 不比对明文，只验前缀
    assert res["rot13"].startswith("DASCTF{")
    assert res["rot18"].startswith("DASCTF{")


# ─────────────────────────────────────────────────────────────────
# 3) misc_bigfile_analysis：10734 真题
# ─────────────────────────────────────────────────────────────────
def test_bigfile_zip_list_on_10734_real_attachment():
    """10734 真题：420MB 外层 zip → zip_list 0.01s 出 1 个内层条目."""
    path = os.path.join("data", "race_attachments", "10734_MISC-01")
    if not os.path.exists(path):
        pytest.skip(f"10734 附件不存在: {path}")
    from skills.misc_bigfile_analysis import misc_bigfile_analysis
    import time
    t0 = time.time()
    res = misc_bigfile_analysis({"kind": "zip_list", "path": path})
    dt = time.time() - t0
    assert res["ok"], res
    assert res["entry_count"] == 1
    assert any("ubuntu flag" in e["name"].lower() for e in res["entries"])
    # 420MB zip 列条目应 < 5s（实测 0.01s，只读中央目录）
    assert dt < 5.0, f"zip_list 耗时 {dt:.2f}s 偏长（应秒级）"


def test_bigfile_nested_tail_on_10734_real_attachment():
    """10734 真题：nested_tail 免全量解压即可看到内层 lime."""
    path = os.path.join("data", "race_attachments", "10734_MISC-01")
    if not os.path.exists(path):
        pytest.skip(f"10734 附件不存在: {path}")
    from skills.misc_bigfile_analysis import misc_bigfile_analysis
    import time
    t0 = time.time()
    res = misc_bigfile_analysis({"kind": "nested_tail", "path": path, "tail_bytes": 8 * 1024 * 1024})
    dt = time.time() - t0
    assert res["ok"], res
    assert res["inner_size"] > 400 * 1024 * 1024  # 内层 449MB zip
    assert any("lime" in e["name"].lower() for e in res["inner_entries"])
    # nested_tail 也不应超过 30s（420MB zip 只读尾部 8MB）
    assert dt < 30.0, f"nested_tail 耗时 {dt:.2f}s 偏长（应 < 30s）"
