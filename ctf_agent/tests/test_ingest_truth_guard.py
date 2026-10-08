# -*- coding: utf-8 -*-
"""ingest 红线④（真值可信性守卫）单测——占位词自证真值必须被拒。

背景（2026-10-08 实锤）：09-29「9/17 presolve 解出」中 7 道返回 `flag{program}`/
`flag{this}` 等占位词——根因是 ingest 的 `validate()` 只查「是 flag 格式」，
占位词真值畅通入库，而 presolve 的 desc 抽词会从描述 reproduces 同一个词
→ 明文分支自证假命中。红线④c 对此 fail-closed。

覆盖：④c 拒收 + 放行降级、④b 双字段一致性、④a 空内容、
真 flag 不误伤（假阳性反例）、09-29 污染签名回归锁。
"""
import hashlib
import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ing = importlib.import_module("scripts.ingest_external_ctf")


def _sha(s: str) -> str:
    return hashlib.sha256(s.strip().encode("utf-8")).hexdigest()


def _q(**kw) -> dict:
    base = {"id": "t1", "title": "t", "category": "misc",
            "description": "solve the challenge by reversing the routine",
            "external_source": "test-src-2026"}
    base.update(kw)
    return dict(base)


class TestLine4cPlaceholderSelfMatch:
    def test_placeholder_word_in_description_rejected(self):
        q = _q(flag="flag{program}", description="run the program to get the flag")
        errs = ing.validate(q)
        assert any("红线④c" in e for e in errs), errs
        # fail-closed：拒收时不得写 sha、不得 pop 明文
        assert q.get("flag_sha256") is None
        assert q.get("flag") == "flag{program}"

    def test_override_downgrades_to_warning_and_ingests(self, capsys):
        q = _q(flag="flag{program}", description="run the program to get the flag")
        errs = ing.validate(q, allow_suspect_truth=True)
        assert not any("红线④c" in e for e in errs), errs
        assert q.get("flag_sha256") == _sha("flag{program}")
        assert "flag" not in q
        assert "放行" in capsys.readouterr().err

    def test_short_word_below_4_chars_not_flagged(self):
        # 内容 <4 字符不做 desc 包含检查（避免 "abc" 类误伤由 ④a/格式关把关）
        q = _q(flag="flag{abc}", description="the abc challenge")
        assert ing.validate(q) == []

    def test_regression_0929_papapapa_signature(self):
        """09-29 污染签名回归锁：flag{this} + 描述含 this → 必须拒收。"""
        q = _q(id="ext_gctf2023_papapapa", flag="flag{this}",
               description="this challenge requires counting the papapapa rhythm")
        errs = ing.validate(q)
        assert any("红线④c" in e for e in errs), errs


class TestLine4aEmptyContent:
    def test_empty_braces_rejected(self):
        q = _q(flag="flag{}")
        errs = ing.validate(q)
        assert any("红线④a" in e for e in errs), errs


class TestLine4bConsistency:
    def test_mismatch_rejected(self):
        q = _q(flag="flag{abc}", flag_sha256=_sha("flag{xyz}"))
        errs = ing.validate(q)
        assert any("不一致" in e for e in errs), errs

    def test_consistent_accepted(self):
        q = _q(flag="flag{abc}", flag_sha256=_sha("flag{abc}"))
        assert ing.validate(q) == []


class TestLegitFlagsNotBlocked:
    def test_real_style_long_flag_accepted(self):
        f = "flag{C0nGr@tz_RiV35t_5h4MiR_nD_Ad13MaN_W0ulD_b_h@pPy}"
        q = _q(flag=f, description="recover the secret from the transcript")
        assert ing.validate(q) == []
        assert q.get("flag_sha256") == _sha(f)
        assert "flag" not in q

    def test_desc_mentions_similar_word_not_content(self):
        """假阳性反例：描述含形近词 time，但 flag 内容是 t1m3 → 不得拒。"""
        q = _q(flag="flag{t1m3}",
               description="a time based challenge; beat the clock in time")
        assert ing.validate(q) == []


class TestFlagInner:
    def test_prefix_variants(self):
        assert ing._flag_inner("DASCTF{xyz}") == "xyz"
        assert ing._flag_inner("flag{}") == ""
        assert ing._flag_inner("no braces here") is None


if __name__ == "__main__":
    raise SystemExit(__import__("pytest").main([__file__, "-q"]))
