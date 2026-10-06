"""C 类（纯数值参数）skill 的确定性入参提取 + 端到端解题（2026-10-07）

背景：主链 skill 调用打通后（commit ba5042c），`AUTO_CALLABLE` 只覆盖
A/B 类（路径/目录）。余下 6 个 C 类 skill 因"参数藏在附件源码里，主链
无法凭空构造"被显式排除 → 接线的能力仍兑现不成解题率。

本次给其中 3 个加**确定性提取器**（_NUMERIC_EXTRACTORS），前提是：
 structurally parseable（AST / literal_eval / 带门限正则），且**参数到齐
 才产出**——有一个拿不准就返回 None，不用猜测值制造假失败。

本测试锁死四件事：
① **flag 抽取不得过度**（真实缺陷，Cycling 端到端发现）：
   skill 多返回 Python dict 的 repr，如 ``{'flag': 'CTF{Recycling_Is_Great}'}``；
   贪婪正则会一路吃到最外层 ``}`` 之后的 ``'}`` 尾巴 → 提交了
   ``CTF{Recycling_Is_Great}'}`` 这种**带杂质尾缀的错误 flag**。
   后果最坏：solver 明明解对，却因 sha256 不等判失败。必须非贪婪。
② 三个提取器对各自真产出**正确参数**（含 n/ct/e 与 pk/ct 的结构完整性）。
③ fail-closed 不变：拿不到必需参数 → None；
   不属范围的（electric-mayhem 的 .tgz/.gz 打包数据）→ None 且不进白名单。
④ **端到端**：Cycling 真跑 solver 解出 flag 且 sha256 与题库真值逐字匹配。
   primes / mhk2 计算量大（数十秒~数分钟），由 CTF_AGENT_SLOW_TESTS=1 启用。
"""
import asyncio
import hashlib
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
if _CTF not in sys.path:
    sys.path.insert(0, _CTF)

SLOW = os.environ.get("CTF_AGENT_SLOW_TESTS") == "1"

EXT = os.path.join(_CTF, "data", "questions_external")


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _load_question(qid):
    from eval.cases import load_questions
    for root in ("data/questions_external", "data/questions_real"):
        try:
            qs = load_questions(root)
        except Exception:  # noqa: BLE001
            continue
        for q in qs or []:
            if getattr(q, "id", "") == qid:
                return q
    raise AssertionError("题库中找不到 %s" % qid)


class TestExtractFlagNotGreedy(unittest.TestCase):
    """① flag 抽取：非贪婪到第一个 }（回归：贪婪版本会吞尾缀杂质）。"""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, _CTF)
        from tools.skill_dispatch import extract_flag
        cls.extract_flag = staticmethod(extract_flag)

    def test_dict_repr_flag_has_no_trailing_quote(self):
        """这是发现的真实缺陷：字典 repr 输出不得把 ``'}`` 尾巴抽进来。"""
        self.assertEqual(
            self.extract_flag("{'flag': 'CTF{Recycling_Is_Great}'}"),
            "CTF{Recycling_Is_Great}")

    def test_dict_repr_with_other_keys(self):
        self.assertEqual(
            self.extract_flag("{'ok': True, 'flag': 'DASCTF{abc_123}'}"),
            "DASCTF{abc_123}")

    def test_plain_text(self):
        self.assertEqual(
            self.extract_flag("flag is CTF{x} and nothing else"), "CTF{x}")

    def test_bytes_input(self):
        self.assertEqual(
            self.extract_flag(b"{'plaintext': 'flag{bin_out}'}"), "flag{bin_out}")

    def test_no_flag_returns_none(self):
        self.assertIsNone(self.extract_flag("no flag here"))
        self.assertIsNone(self.extract_flag(None))

    def test_stops_at_first_closing_brace(self):
        """两个候选 flag 相邻时取**最短闭合**的前一个（不再合并成一段）。"""
        self.assertEqual(
            self.extract_flag("CTF{a}b} trailing"), "CTF{a}")


class TestNumericParamExtraction(unittest.TestCase):
    """② ③ 提取正确性 + fail-closed。"""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, _CTF)
        from tools.skill_dispatch import (
            AUTO_CALLABLE, extract_numeric_params, should_auto_call,
        )
        cls.EXT = staticmethod(extract_numeric_params)
        cls.AUTO_CALLABLE = AUTO_CALLABLE
        cls.should_auto_call = staticmethod(should_auto_call)

    def test_cycling_extracts_n_ct_e(self):
        q = _load_question("ext_gctf2022_cycling")
        p = self.EXT("crypto_cycling", q)
        self.assertIsNotNone(p, "Cycling 应能从 chall.py 提取 n/ct")
        self.assertTrue(str(p["n"]).startswith("0x"))
        self.assertTrue(str(p["ct"]).startswith("0x"))
        self.assertEqual(p["e"], 65537)
        # 完整性：真实值是 1024-bit 十六进制，长度应远超样例短值（12 hex）
        self.assertGreater(len(p["n"]) - 2, 200)

    def test_primes_extracts_q_x_n(self):
        q = _load_question("ext_gctf2023_primes")
        p = self.EXT("crypto_primes_subset", q)
        self.assertIsNotNone(p, "Primes 应能从 chal.sage 注释提取 q/x")
        self.assertEqual(p["kind"], "solve")
        self.assertEqual(p["r"], 131)
        self.assertTrue(str(p["q"]).startswith("0x"))
        self.assertTrue(str(p["x"]).startswith("0x"))
        # n = 7·len(flag)，且提取器已校验 7 | n 且 n ≥ r
        self.assertEqual(p["n"] % 7, 0)
        self.assertGreaterEqual(p["n"], 131)

    def test_mhk2_extracts_pk_and_ct(self):
        q = _load_question("ext_gctf2023_mhk2")
        p = self.EXT("crypto_knapsack_mhk", q)
        self.assertIsNotNone(p, "MHK2 应能从 output.txt 提取 pk/ct")
        self.assertEqual(p["kind"], "mhk2_decrypt")
        self.assertIn("a1", p["pk"])
        self.assertIn("a2", p["pk"])
        self.assertEqual(len(p["pk"]["a1"]), 256, "公钥应为 256 维")
        self.assertTrue(p["ct"] and len(p["ct"][0]) == 2,
                        "密文应是二元 tuple 列表")

    def test_fail_closed_on_unrelated_question(self):
        """给不含所需数值的题面 → 必须 None（不拿猜测值喂 solver）。"""
        ez = os.path.join(_CTF, "data", "questions_real", "_attachments",
                          "crypto", "real_crypto_ezrsa", "output")

        class _Q:
            attachments = [ez]

        for name in ("crypto_cycling", "crypto_primes_subset",
                     "crypto_knapsack_mhk"):
            self.assertIsNone(self.EXT(name, _Q()),
                              "%s 拿不到参数时必须 None" % name)

    def test_packed_data_not_auto_called(self):
        """electric-mayhem 的 .tgz/.gz 需先解包预处理 → 不在自动调用范围。"""
        q = _load_question("ext_gctf2022_electric-mayhem-cls")
        self.assertIsNone(self.EXT("crypto_electric_mayhem_cls", q))
        self.assertNotIn("crypto_electric_mayhem_cls", self.AUTO_CALLABLE)
        self.assertFalse(self.should_auto_call("crypto_electric_mayhem_cls"))

    def test_three_numeric_skills_in_allowlist(self):
        for name in ("crypto_cycling", "crypto_primes_subset",
                     "crypto_knapsack_mhk"):
            self.assertIn(name, self.AUTO_CALLABLE)
            self.assertTrue(self.should_auto_call(name))


class TestNumericEndToEnd(unittest.TestCase):
    """④ 端到端：走主链同一路径（load → registry.run → extract_flag）。"""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, _CTF)
        from tools.skill_manager import SkillManager
        from tools.registry import ToolRegistry
        from tools.skill_dispatch import extract_flag, extract_numeric_params
        cls.extract_flag = staticmethod(extract_flag)
        cls.EXT = staticmethod(extract_numeric_params)
        cls.registry = ToolRegistry()
        cls.sm = SkillManager(registry=cls.registry)
        try:
            cls.sm.discover()
        except Exception:  # noqa: BLE001
            pass

    def _solve_and_check(self, qid, skill_name):
        q = _load_question(qid)
        params = self.EXT(skill_name, q)
        self.assertIsNotNone(params, "%s 参数提取失败" % qid)
        self.sm.load(skill_name)
        self.assertIsNotNone(self.registry.get(skill_name),
                             "%s 未注册进 registry" % skill_name)
        out = asyncio.run(self.registry.run(skill_name, params))
        flag = self.extract_flag(out)
        self.assertTrue(flag, "%s 未解出 flag：%s" % (qid, str(out)[:200]))
        truth = getattr(q, "flag_sha256", None)
        if truth:
            self.assertEqual(_sha(flag), truth,
                             "%s 解出的 flag 与题库真值不符: %r" % (qid, flag))
        return flag

    def test_cycling_solves_and_matches_truth(self):
        flag = self._solve_and_check("ext_gctf2022_cycling", "crypto_cycling")
        # 尾缀杂质回归：解出的 flag 必须干净（贪婪版本会变成 ...Great}'}）
        self.assertTrue(flag.endswith("}"), flag)
        self.assertNotIn("'", flag, "flag 不应含引号杂质: %r" % flag)

    def test_primes_solves_and_matches_truth(self):
        """实测 ~12s（Coppersmith + flint LLL），够快，进常规回归。

        附带证明：解出的 flag 与附件 chal.sage 里那句 ``m = b"CTF{YkDOL...}"``
        **不同**——即 solver 是真算出，不是把题面明文抄回来。
        """
        flag = self._solve_and_check("ext_gctf2023_primes",
                                     "crypto_primes_subset")
        self.assertNotIn("YkDOL", flag,
                         "解出的 flag 不应是题面里的诱饵明文: %r" % flag)

    @unittest.skipUnless(SLOW, "慢（MHK2 双公钥恢复 ~数分钟），同上开关启用")
    def test_mhk2_solves_and_matches_truth(self):
        self._solve_and_check("ext_gctf2023_mhk2", "crypto_knapsack_mhk")


if __name__ == "__main__":
    unittest.main()
