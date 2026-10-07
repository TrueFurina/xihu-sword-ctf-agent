"""B 接线回归测试：孤儿求解器回收·第五批两题（FilterRandom / Electric Mayhem CLS）。

本批与前四批不同——**含solver 源码修复**：

1. `lfsr_filter_recover`：此前**只有 solve_lfsr_filter()、缺 run()**，
   `SkillManager.load()` 直接判「缺少 run() 函数」加载失败
   （tools/skill_manager.py:288-291）→ 接路由键也是假接线。
   本次补标准 run() 薄包装（**不改核心算法**），load 状态由 FAIL 变 OK。
   端到端实证：真实 FilterRandom.py 的 ''' 块（含 mask1/mask2/2048位输出）
   经 run() 解出 DASCTF{init1-init2}，sha256 与题面逐字匹配。

2. `crypto_electric_mayhem_cls`：源码无需改（`_load_challenge_json` 直接支持
   .gz 直读，无需手工解压）。侧信道 CPA 实测 **0.3s** 解出，sha256 匹配。

键选取纪律：
- FilterRandom → "两个 64 位 LFSR"（全题库仅本题）。
- CLS → "where XXX is your recovered key"：**cls 与同系列 -pqc 的 description
  前两句完全相同**，只有 cls 多这一句附注。用「power traces」会把 PQC（后量子
  格密码）错路由进 AES-CPA solver（wrong_direction）。
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

FR_JSON = os.path.join(_CTF, "data", "questions_real", "crypto",
                       "real_crypto_filterrandom.json")
FR_ATT = os.path.join(_CTF, "data", "questions_real", "_attachments", "crypto",
                      "real_crypto_filterrandom", "FilterRandom.py")
CLS_JSON = os.path.join(_CTF, "data", "questions_external", "crypto",
                        "ext_gctf2022_electric-mayhem-cls.json")
CLS_ATT = os.path.join(_CTF, "data", "questions_external", "crypto",
                       "ext_gctf2022_electric-mayhem-cls", "_attachments",
                       "stm32f0_aes.json.gz")

ROUTES = [
    ("filterrandom", "两个 64 位 lfsr", "lfsr_filter_recover", FR_JSON, "crypto"),
    ("electric-mayhem-cls", "where xxx is your recovered key",
     "crypto_electric_mayhem_cls", CLS_JSON, "crypto"),
]


def _skill_map():
    with open(PROMPTS_PATH, encoding="utf-8") as _pf:
        tree = ast.parse(_pf.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "skill_map":
                    return ast.literal_eval(node.value)
    raise AssertionError("skill_map not found in prompts.py")


def _load_skill(name):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_CTF, "skills", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestFifthBatchRoutes(unittest.TestCase):
    def test_keys_exist_and_point_correctly(self):
        smap = _skill_map()
        for name, key, skill, _, _ in ROUTES:
            self.assertIn(key, smap, "skill_map 缺 %s 题专属键 %r" % (name, key))
            self.assertEqual(smap[key], skill,
                             "键 %r 应指向 %s，实际 %r" % (key, skill, smap[key]))

    def test_keys_precede_rsa_catchall(self):
        keys = list(_skill_map().keys())
        rsa_idx = keys.index("rsa")
        for name, key, _, _, _ in ROUTES:
            self.assertLess(keys.index(key), rsa_idx,
                            "%s 专属键排在裸 'rsa' 之后 → 被catch-all 抢走" % name)

    @pytest.mark.local
    def test_infer_skill_require_routes_each(self):
        from core.prompts import infer_skill_require
        for name, key, skill, qjson, cat in ROUTES:
            with open(qjson, encoding="utf-8") as _jf:
                qj = json.load(_jf)

            class _Mgr:
                def __init__(self):
                    self.loaded = []

                def list_loaded(self):
                    return self.loaded

                def list_available(self):
                    return [skill, "rsa_fermat_factor"]

                def load(self, n):
                    self.loaded.append(n)

            class _Q:
                category = cat
                description = qj["description"]
                candidate_flag = None

            class _Ctx:
                question = _Q()

            mgr = _Mgr()
            infer_skill_require(_Ctx(), {"ability_gap": ["缺少有效攻击路径"]}, mgr)
            self.assertIn(skill, mgr.loaded,
                          "%s 必须路由到 %s（实际 %r）" % (name, skill, mgr.loaded))

    def test_both_skills_loadable_by_skill_manager(self):
        """接线前提：两个 solver 都能被 SkillManager 真实加载。

        lfsr_filter_recover 这一条是本批修复的核心证据——修复前 load 失败。
        """
        from tools.skill_manager import SkillManager
        sm = SkillManager()
        for name, _, skill, _, _ in ROUTES:
            self.assertTrue(sm.load(skill),
                            "%s 无法被 SkillManager 加载：%r" % (name, sm.list_failures()))

    def test_lfsr_skill_exposes_run_entrypoint(self):
        """回归护栏：solve_lfsr_filter 仍在（核心算法未被破坏）且 run() 存在。"""
        mod = _load_skill("lfsr_filter_recover")
        self.assertTrue(hasattr(mod, "solve_lfsr_filter"), "核心函数被误删")
        self.assertTrue(callable(getattr(mod, "run", None)), "run() 入口缺失")

    def test_lfsr_run_honest_on_bad_input(self):
        """诚实边界：缺参/附件不存在须返回 ok=False，不得抛异常或谎报。"""
        mod = _load_skill("lfsr_filter_recover")
        for bad in ({}, {"path": "definitely_missing_file.py"}):
            res = mod.run(bad)
            self.assertIsInstance(res, dict)
            self.assertFalse(res.get("ok"), "坏输入应 ok=False：%r" % res)
            self.assertIsNone(res.get("flag"))

    @pytest.mark.local
    def test_filterrandom_real_solve(self):
        mod = _load_skill("lfsr_filter_recover")
        res = mod.run({"path": FR_ATT})
        self.assertTrue(res.get("ok"), "FilterRandom 未解出：%r" % res)
        with open(FR_JSON, encoding="utf-8") as _jf:
            exp = json.load(_jf)["flag_sha256"]
        got = hashlib.sha256(res["flag"].encode("utf-8")).hexdigest()
        self.assertEqual(got, exp, "FilterRandom sha256 不匹配")

    @pytest.mark.local
    def test_electric_mayhem_cls_real_solve(self):
        mod = _load_skill("crypto_electric_mayhem_cls")
        with open(CLS_JSON, encoding="utf-8") as _jf:
            exp = json.load(_jf)["flag_sha256"]
        res = mod.run({"path": CLS_ATT, "expected_sha": exp})
        self.assertTrue(res.get("ok"), "Electric Mayhem CLS 未解出：%r" % res)
        flag = res.get("flag")
        raw = flag if isinstance(flag, bytes) else str(flag).encode("latin-1")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), exp,
                         "Electric Mayhem CLS sha256 不匹配")

    @pytest.mark.local
    def test_pqc_sibling_not_stolen_by_cls_key(self):
        """防错路由：同系列 -pqc（后量子格密码）题面不含本批 CLS 键。"""
        pqc = os.path.join(_CTF, "data", "questions_external", "crypto",
                           "ext_gctf2022_electric-mayhem-pqc.json")
        with open(pqc, encoding="utf-8") as _jf:
            pqc_desc = json.load(_jf)["description"].lower()
        self.assertNotIn("where xxx is your recovered key", pqc_desc,
                         "PQC 题面若含 CLS 键 → 会被错路由进 AES-CPA solver")


if __name__ == "__main__":
    unittest.main(verbosity=2)
