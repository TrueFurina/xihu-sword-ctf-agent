"""B2 纠错回归测试：锁死 10733 类题（高偶指数 RSA + hint 泄露 p + ROT13）正确路由到
crypto_high_exponent 并端到端解出（2026-10-06）。

背景（2026-10-06 实证翻转）：
- 10733 真实题面经 infer_skill_require 曾被 'rot13' 抢路由到 base64_multilayer（编码
  solver，完全错方向）——因为它题面含 "rot13/编码" 且 crypto_high_exponent 在 skill_map
  无任何触发词。
- crypto_high_exponent.factor_from_hint 用 W=e^n mod n → p=gcd(W²-hint,n) 分解 n（无需
  先知 q），已实测解出 10733（verify_10733.py 验证）。早前对 rsa_fermat_factor 的 p_known
  补丁补错了 skill；真根因是 skill_map 路由缺口（与 specialcurve2 同类）。
- 本测试锁死两层：① 路由正确（题面不再误入 base64_multilayer）；② 真实题面+参数端到端
  解出，且 ROT13 编码态经 rot13 归一后命中题面真值 sha256（真题坑点：明文是 ROT13 编码）。
"""
import os
import re
import unittest
import hashlib
import importlib.util
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
PROMPTS_PATH = os.path.join(_HERE, "..", "core", "prompts.py")
Q10733_JSON = os.path.join(_HERE, "..", "data", "questions_real", "crypto", "10733.json")
TASK_PY = os.path.join(
    _HERE, "..", "data", "race_attachments",
    "10733_How_many_rot_are_there的附件", "tempdir", "CRYPTO附件", "task.py")

with open(PROMPTS_PATH, encoding="utf-8") as _f:
    PROMPTS_SRC = _f.read()


def _load_che():
    spec = importlib.util.spec_from_file_location(
        "crypto_high_exponent",
        os.path.join(_HERE, "..", "skills", "crypto_high_exponent.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _real_n_e_c_hint():
    with open(TASK_PY, encoding="utf-8") as _tf:
        block = re.search(r"'''(.*?)'''", _tf.read(), re.S).group(1)
    v = {m.group(1): int(m.group(2))
         for m in re.finditer(r"(n|hint|c|p|q)\s*=\s*(\d+)", block)}
    return v["n"], 65536, v["c"], v["hint"]


class Test10733HighExponentRoute(unittest.TestCase):
    def test_skillmap_routes_to_crypto_high_exponent_not_base64(self):
        # 触发词必须存在且排在 'rot13' 之前（按 dict 真实键序，非文件位置）
        self.assertIn(
            '"奇数阶子群": "crypto_high_exponent"', PROMPTS_SRC,
            "skill_map 缺 10733 路由触发词 奇数阶子群 -> crypto_high_exponent")
        # 'rot13' 仍指向编码 solver（不得被改坏）
        self.assertIn('"rot13": "base64_multilayer"', PROMPTS_SRC)
        # 顺序断言：在 skill_map 真实键序中，奇数阶子群 必须排在 rot13 之前，
        # 否则 10733 题面会被编码 solver 抢走（实测 CPython 保留重复键首次位置）。
        import re as _re
        _body = _re.search(r"skill_map = \{(.*?)\n    \}", PROMPTS_SRC, _re.S).group(1)
        _ns = {}
        exec("skill_map = {" + _body + "\n}", _ns)
        _keys = list(_ns["skill_map"].keys())
        self.assertIn("奇数阶子群", _keys)
        self.assertIn("rot13", _keys)
        self.assertLess(
            _keys.index("奇数阶子群"), _keys.index("rot13"),
            "10733 路由键 奇数阶子群 必须排在 rot13 之前，否则误路由到 base64_multilayer")

    def test_infer_skill_require_loads_crypto_high_exponent_for_10733(self):
        """端到端确定性路由验证（不依赖 LLM）：10733 真实题面必须触发
        skill_manager.load('crypto_high_exponent')，不得 load base64_multilayer。"""
        from core.prompts import infer_skill_require
        with open(Q10733_JSON, encoding="utf-8") as _qf:
            qj = __import__("json").load(_qf)

        class _Mgr:
            def __init__(self):
                self.loaded = []

            def list_loaded(self):
                return self.loaded

            def list_available(self):
                return ["crypto_high_exponent", "base64_multilayer",
                        "rsa_fermat_factor"]

            def load(self, name):
                self.loaded.append(name)

        class _Q:
            category = "crypto"
            description = qj["description"]
            candidate_flag = None

        class _Ctx:
            question = _Q()

        mgr = _Mgr()
        infer_skill_require(_Ctx(), {"ability_gap": ["缺少有效攻击路径"]}, mgr)
        self.assertIn(
            "crypto_high_exponent", mgr.loaded,
            "10733 题面必须路由加载 crypto_high_exponent（B2 修复核心生效）")
        self.assertNotIn(
            "base64_multilayer", mgr.loaded,
            "10733 题面不得误路由到 base64_multilayer（编码 solver 完全错方向）")

    @pytest.mark.local
    def test_crypto_high_exponent_solves_10733_real(self):
        """端到端解出 10733 真实实例（纯本地数学，无网络）：run() 成功且 ROT13 编码态
        经 rot13 归一后命中题面真值 sha256（真题坑点）。"""
        che = _load_che()
        n, e, c, hint = _real_n_e_c_hint()
        res = che.run({"n": n, "e": e, "c": c, "hint": hint, "kind": "auto"})
        self.assertTrue(res.get("ok"), "crypto_high_exponent 未能解出 10733: %r" % res)
        raw = res.get("flag") or ""
        self.assertTrue(raw, "解出为空")
        # 真题坑点：明文为 ROT13 编码（QNFPGS{...}），需 rot13 归一
        canonical = che.codecs_rot(raw, 13)
        with open(Q10733_JSON, encoding="utf-8") as _qf:
            qj = __import__("json").load(_qf)
        truth = qj["flag_sha256"]
        self.assertEqual(
            hashlib.sha256(canonical.encode()).hexdigest(), truth,
            "10733 解出经 rot13 归一后未命中真值 sha256；raw=%r canonical=%r"
            % (raw, canonical))


if __name__ == "__main__":
    unittest.main(verbosity=2)
