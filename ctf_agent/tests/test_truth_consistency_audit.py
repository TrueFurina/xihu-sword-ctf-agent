"""题面 flag_sha256 一致性审计器回归测试（2026-10-06）

锁死三处口径，防止后人回退：

1. **FLAG_RE 前缀口径**必须覆盖带赛事前缀的 flag（csawctf{...}）。
   审计器初版误用「flag|ctf 前缀交替 + 花括号」的简化正则，会从 csawctf{
   中间起匹配、截断前缀 → sha256 必然不符 → 把 L0 送分层题误判成 MISMATCH
   （实测 baby_s_third 因此被误判，其真值本已匹配）。
   官方 _stratify_external_benchmark.py 的前缀是字母数字下划线字符类，
   本审计器必须与之同口径。

2. **matches_truth 必须支持两种登记口径**：全串 ctf{...} 与花括号内文 {...}。
   不同题库的 flag_sha256 登记方式不同，只比全串会漏判。本审计器直接复用
   官方实现，不重写，避免两工具判定漂移。

3. **真值不一致必须能检出**：ext_gctf2023_primes 的 chal.sage 直含完整明文
   flag，但该明文 sha256 与题面 flag_sha256 不符（已排除编码/前缀/重复等变体）
   → 属真数据缺陷，须被 B_MISMATCH 捕获而非静默。
"""
import glob
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
_AUDIT = os.path.join(_CTF, "scripts", "_audit_truth_consistency.py")
_OFFICIAL = os.path.join(_CTF, "scripts", "_stratify_external_benchmark.py")


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTruthConsistencyAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load(_AUDIT, "_audit_tc")
        cls.off = _load(_OFFICIAL, "_stratify_official")

    def test_flag_re_matches_prefixed_flag(self):
        """带赛事前缀的 flag 必须被完整匹配（不截断前缀）。"""
        for raw in (b"csawctf{st1ng_th30ry_a1nt_so_h4rd}",
                    b"flag{plain}",
                    b"DASCTF{Some_Thing}",
                    b"nssctf{abc123}"):
            hits = self.mod.FLAG_RE.findall(raw)
            self.assertTrue(hits, "未抓到候选: %r" % raw)
            self.assertIn(raw, hits, "候选被截断: %r -> %r" % (raw, hits))

    def test_matches_truth_full_and_inner(self):
        """两种登记口径都要能命中：全串与花括号内文。"""
        flag = b"ctf{ABCDEFG}"
        full_sha = hashlib.sha256(flag).hexdigest()
        inner_sha = hashlib.sha256(flag[4:-1]).hexdigest()
        self.assertTrue(self.mod.matches_truth(flag, full_sha), "全串口径失败")
        self.assertTrue(self.mod.matches_truth(flag, inner_sha), "内文口径失败")
        self.assertFalse(self.mod.matches_truth(flag, "0" * 64), "不相关摘要应 False")

    def test_flag_re_prefix_semantics_match_official(self):
        """前缀字符类必须与官方分层工具一致（防口径漂移）。"""
        sample = b"csawctf{st1ng_th30ry_a1nt_so_h4rd} DASCTF{abc}"
        mine = set(self.mod.FLAG_RE.findall(sample))
        off = set(self.off.FLAG_RE.findall(sample))
        self.assertEqual(mine, off, "FLAG_RE 与官方口径不一致")

    def test_real_data_primes_is_truth_conflict(self):
        """真实数据回归：primes 附件含完整明文 flag，但 sha256 与题面不符 → MISMATCH。

        这是本审计器抓出的唯一真数据缺陷（其余 MISMATCH 均为密文/占位符，正常）。
        若将来人工修正了题面真值，本护栏会失败并提示同步更新。
        """
        jpath = os.path.join(_CTF, "data", "questions_external", "crypto",
                             "ext_gctf2023_primes.json")
        att = os.path.join(_CTF, "data", "questions_external", "crypto",
                           "ext_gctf2023_primes", "_attachments", "chal.sage")
        if not (os.path.isfile(jpath) and os.path.isfile(att)):
            self.skipTest("primes 题面/附件不在库")
        with open(jpath, encoding="utf-8") as _jf:
            d = json.load(_jf)
        with open(att, "rb") as _af:
            raw = _af.read()
        cands = self.mod.FLAG_RE.findall(raw)
        self.assertTrue(cands, "primes 附件应含 flag 形态明文")
        self.assertFalse(any(self.mod.matches_truth(c, d["flag_sha256"]) for c in cands),
                         "primes 附件明文竟与题面 sha256 匹配——若题面已修正，"
                         "本护栏需同步更新")

    def test_real_data_baby_third_is_l0_match(self):
        """真实数据回归：baby_s_third 附件明文应判 A_MATCH（L0 送分层）。"""
        hits = glob.glob(os.path.join(_CTF, "data", "**",
                                      "ext_nyu_ctf_bench_2023q_rev_baby_s_third.json"),
                         recursive=True)
        if not hits:
            self.skipTest("baby_s_third 题面不在库")
        with open(hits[0], encoding="utf-8") as _jf:
            d = json.load(_jf)
        atts = glob.glob(os.path.join(_CTF, "data", "**", "babysthird"), recursive=True)
        self.assertTrue(atts, "baby_s_third 附件不在库")
        with open(atts[0], "rb") as _af:
            raw = _af.read()
        cands = self.mod.FLAG_RE.findall(raw)
        self.assertTrue(any(self.mod.matches_truth(c, d["flag_sha256"]) for c in cands),
                        "baby_s_third 应能匹配真值（曾因前缀截断被误判）")

    def test_audit_smoke_three_levels(self):
        """主流程冒烟：A_MATCH / B_MISMATCH 两类判定正确。"""
        with tempfile.TemporaryDirectory() as td:
            sub = os.path.join(td, "att")
            os.makedirs(sub)
            flag = b"ctf{ZZZZ}"
            # 用 NUL 包裹，避免相邻字母被并入 flag 前缀
            with open(os.path.join(sub, "a.bin"), "wb") as f:
                f.write(b"\x00junk\x00" + flag + b"\x00tail")
            with open(os.path.join(sub, "b.bin"), "wb") as f:
                f.write(b"\x00 ctf{DIFFERENT} \x00")
            qa = {"id": "qa", "flag_sha256": hashlib.sha256(flag).hexdigest(),
                  "attachments": ["att/a.bin"]}
            qb = {"id": "qb", "flag_sha256": "0" * 64,
                  "attachments": ["att/b.bin"]}
            for q in (qa, qb):
                with open(os.path.join(td, q["id"] + ".json"), "w",
                          encoding="utf-8") as f:
                    json.dump(q, f)
            rows = self.mod.audit(self.mod.load_questions([td]), td)
            levels = {r["id"]: r["level"] for r in rows}
            self.assertEqual(levels.get("qa"), "A_MATCH")
            self.assertEqual(levels.get("qb"), "B_MISMATCH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
