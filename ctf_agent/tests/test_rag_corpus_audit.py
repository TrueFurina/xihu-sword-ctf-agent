"""_rag_corpus_audit 单元测试（RAG 语料护栏——held-out 泄漏审计，纯规则）。"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_spec = importlib.util.spec_from_file_location(
    "_rag_corpus_audit",
    os.path.join(ROOT, "scripts", "_rag_corpus_audit.py"),
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def test_significant_tokens_filters_short():
    toks = mod._significant_tokens("ab abc abcdef RSA_n e_quals_3")
    assert "abcdef" in toks and "rsa_n" in toks and "e_quals_3" in toks
    assert "ab" not in toks and "abc" not in toks  # <5 字符跳过


def test_leak_by_title_hit():
    pools = {"ext_x": {"pool": "external41", "title": "Tiramisu Challenge",
                       "desc": "", "flag": ""}}
    corpus = [(1, {"text": "解法：Tiramisu Challenge 用 LLL 格攻击", "source": "verified: bad"})]
    leaks = mod.audit_leak(corpus, pools)
    assert len(leaks) == 1 and leaks[0][1] == "ext_x" and "题名命中" in leaks[0][3]


def test_leak_by_desc_token_coverage():
    pools = {"ext_y": {"pool": "nyu", "title": "NoMatchTitle",
                       "desc": "keyboard matrix qrcode decode hidden randombytes",
                       "flag": ""}}
    corpus = [(1, {"text": "keyboard matrix qrcode decode hidden randombytes 攻略",
                   "source": "s"})]
    leaks = mod.audit_leak(corpus, pools)
    assert len(leaks) == 1 and "token 命中" in leaks[0][3]


def test_no_leak_for_unrelated_corpus():
    pools = {"ext_z": {"pool": "external41", "title": "SomeHardRSA",
                       "desc": "modulus ciphertext exponent prime factor recovery",
                       "flag": "flag{abc12345}"}}
    corpus = [(1, {"text": "维吉尼亚密钥提取与频率分析解法摘要", "source": "verified: ok"})]
    assert mod.audit_leak(corpus, pools) == []


def test_leak_by_flag_value():
    pools = {"ext_w": {"pool": "nyu", "title": "Unrelated", "desc": "",
                       "flag": "csawctf{leaky_value}"}}
    corpus = [(1, {"text": "答案是 csawctf{leaky_value}，来自附件。", "source": "s"})]
    leaks = mod.audit_leak(corpus, pools)
    assert len(leaks) == 1 and "flag 值命中" in leaks[0][3]


def test_ledger_missing_returns_empty(tmp_path):
    old = mod.LEDGER
    try:
        mod.LEDGER = str(tmp_path / "no_such_ledger.md")
        assert mod.ledger_verified_titles() == []
    finally:
        mod.LEDGER = old
