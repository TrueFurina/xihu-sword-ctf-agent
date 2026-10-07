"""B 接线回归测试：真·L2 纯推理层两道玄盾杯题正确路由并端到端解出（2026-10-06）。

背景（审计 + 实证）：
- crypto_legendre_phi（phi 泄露分解 + Legendre 符号逐位判定）与
  crypto_modinv_factor（phi + 双模逆）都是「单题专用」求解器，长期是 skill_map
  孤儿（存在于 skills/ 却无任何触发词），两题路由到 None（诚实但能力浪费）。
- 二者均属真·L2 纯推理层（provenance=external_westlake_ctf_L2），是本次 B 层
  回收中价值最高的两题——接线后**端到端实证解出**（非仅路由断言）：
    simplelegendre   -> flag{GO0D_J0b_of_TH1s_encrYption}   （sha256 逐字匹配）
    exciting_inverse -> flag{QUITE_S1mpLe_TAsk}             （sha256 逐字匹配）
- 键选取纪律：单题专用 solver 必须用**题面独有短语**，禁用泛化词。
    "逐位加密" 全题库仅命中 simplelegendre（0 误伤）；
    "模逆"     仅命中 exciting_inverse；**禁用「逆元」**（全库 9 题会误伤）。
- 键序纪律：两键必须排在裸 "rsa" catch-all 之前，否则被抢走
  （同 specialcurve2 / 10733 的 wrong_direction 陷阱）。
- 本测试锁死四层：① 两键存在；② 两键按 dict 真实键序排在 "rsa" 之前；
  ③ 真实题面经 infer_skill_require 必须 load 对应 solver 且不 load rsa_fermat_factor；
  ④ 真实附件 output 经 solver.run 端到端解出且 sha256 与题面逐字匹配。
"""
import ast
import hashlib
import importlib.util
import json
import os
import unittest
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
PROMPTS_PATH = os.path.join(_CTF, "core", "prompts.py")

# 真·L2 题 JSON 与真实附件（attachments 字段指向 questions_real/_attachments）
_L2_DIR = os.path.join(_CTF, "data", "questions_ext_L2_pure_reasoning")
_ATT_DIR = os.path.join(_CTF, "data", "questions_real", "_attachments", "crypto")

CASES = [
    {
        "name": "simplelegendre",
        "key": "逐位加密",
        "skill": "crypto_legendre_phi",
        "json": os.path.join(_L2_DIR, "real_crypto_simplelegendre.json"),
        "real_json": os.path.join(_CTF, "data", "questions_real", "crypto",
                                  "real_crypto_simplelegendre.json"),
        "attachment": os.path.join(_ATT_DIR, "real_crypto_simplelegendre", "output"),
    },
    {
        "name": "exciting_inverse",
        "key": "模逆",
        "skill": "crypto_modinv_factor",
        "json": os.path.join(_L2_DIR, "real_crypto_exciting_inverse.json"),
        "real_json": os.path.join(_CTF, "data", "questions_real", "crypto",
                                  "real_crypto_exciting_inverse.json"),
        "attachment": os.path.join(_ATT_DIR, "real_crypto_exciting_inverse", "output"),
    },
]


def _load_skill(name):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_CTF, "skills", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _skill_map_keys():
    """解析 prompts.py 里 infer_skill_require 内部的 skill_map 真实键序。"""
    return list(_skill_map().keys())


def _skill_map():
    """返回 skill_map 的 key -> value 映射（判定键值指向关系）。"""
    with open(PROMPTS_PATH, encoding="utf-8") as _pf:
        tree = ast.parse(_pf.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "skill_map":
                    return ast.literal_eval(node.value)
    raise AssertionError("skill_map not found in prompts.py")


class TestL2LegendreModinvRoute(unittest.TestCase):
    def test_both_l2_keys_exist(self):
        smap = _skill_map()
        for c in CASES:
            self.assertIn(c["key"], smap,
                          "skill_map 缺 %s 题专属键 %r" % (c["name"], c["key"]))
            self.assertEqual(
                smap[c["key"]], c["skill"],
                "键 %r 应指向 %s，实际指向 %r"
                % (c["key"], c["skill"], smap[c["key"]]))

    def test_l2_keys_precede_rsa_catchall(self):
        """键序硬点：专属键必须排在裸 "rsa" 之前，否则被 RSA catch-all 抢走。"""
        keys = _skill_map_keys()
        rsa_idx = keys.index("rsa")
        for c in CASES:
            self.assertLess(
                keys.index(c["key"]), rsa_idx,
                "%s 的专属键 %r 排在裸 'rsa' 之后 → 会被 RSA catch-all 抢走"
                "（specialcurve2 同款 wrong_direction 陷阱）" % (c["name"], c["key"]))

    @pytest.mark.local
    def test_infer_skill_require_routes_each_l2_to_its_solver(self):
        """端到端确定性路由：真实题面必须 load 对应 solver，且不得 load rsa_fermat_factor。"""
        from core.prompts import infer_skill_require

        for c in CASES:
            with open(c["json"], encoding="utf-8") as _jf:
                qj = json.load(_jf)

            class _Mgr:
                def __init__(self):
                    self.loaded = []

                def list_loaded(self):
                    return self.loaded

                def list_available(self):
                    return [c["skill"], "rsa_fermat_factor",
                            "crypto_legendre_phi", "crypto_modinv_factor"]

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
                c["skill"], mgr.loaded,
                "%s 真实题面必须路由加载 %s（实际 loaded=%r）"
                % (c["name"], c["skill"], mgr.loaded))
            self.assertNotIn(
                "rsa_fermat_factor", mgr.loaded,
                "%s 被裸 'rsa' catch-all 抢走 → wrong_direction" % c["name"])

    @pytest.mark.local
    def test_both_l2_solvers_solve_real_instances(self):
        """端到端解出（纯本地数论，无网络/无 LLM）：flag 非空且 sha256 逐字匹配题面。"""
        for c in CASES:
            mod = _load_skill(c["skill"])
            hit = mod.run({"path": c["attachment"]})
            self.assertTrue(hit, "%s 求解器未解出真实实例（返回 %r）"
                            % (c["name"], hit))
            with open(c["real_json"], encoding="utf-8") as _rf:
                expected = json.load(_rf).get("flag_sha256")
            self.assertTrue(expected, "%s 题面缺 flag_sha256，无法校验" % c["name"])
            got = hashlib.sha256(hit.encode("utf-8")).hexdigest()
            self.assertEqual(
                got, expected,
                "%s 解出结果与题面 flag_sha256 不匹配（got=%s expect=%s）"
                % (c["name"], got, expected))


if __name__ == "__main__":
    unittest.main(verbosity=2)
