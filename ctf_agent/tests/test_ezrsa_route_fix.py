"""ezRSA 路由纠错 + rsa_fermat_factor 异常兜底回归测试（2026-10-06）

发现的问题（实测，非推测）：
1. `skill_map` 里 `"hastad"` / `"广播攻击"` 原指向 `rsa_fermat_factor`，
   但该 skill **跑 ezRSA 直接抛异常**：
   `ValueError: pow() 3rd argument cannot be 0`。
   根因：走 `path`/`text` 输入时 `_collect_pairs` 只从 dict 取 `n1/c1…`，
   文本里的数字对未被解析 → `len(ns) < 2` → auto-detect 误落默认费马分支
   → `_fermat_factor` 内 `pow(c, d, n)` 遇 n=0 崩。
2. ezRSA（**真·L2 层**）真正能解出的是专用 solver `crypto_hastad_broadcast`
   （Coppersmith/CRT + 开 e 次方），端到端解出且 sha256 逐字匹配。

本测试锁死：
① 路由键 `hastad`/`广播攻击` 必须指向 `crypto_hastad_broadcast`；
② 键序硬点：排在裸 `rsa` 之前；
③ ezRSA 真实题面经 `infer_skill_require` 必 load 专用 solver；
④ 专用 solver 端到端解出 + sha256 逐字匹配；
⑤ **rsa_fermat_factor 遇该输入不得抛异常**（优雅返 None，诚实兜底）；
⑥ SkillManager 两个 solver 均可加载。
"""
import ast
import hashlib
import importlib.util
import json
import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
PROMPTS_PATH = os.path.join(_CTF, "core", "prompts.py")
EZRSA_JSON = os.path.join(_CTF, "data", "questions_real", "crypto",
                          "real_crypto_ezrsa.json")
EZRSA_ATT = os.path.join(_CTF, "data", "questions_real", "_attachments",
                         "crypto", "real_crypto_ezrsa", "output")

DEDICATED = "crypto_hastad_broadcast"
GENERIC = "rsa_fermat_factor"


def _skill_map():
    with open(PROMPTS_PATH, encoding="utf-8") as _pf:
        tree = ast.parse(_pf.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "skill_map":
                    return ast.literal_eval(node.value)
    raise AssertionError("skill_map not found in prompts.py")


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_CTF, "skills", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestEzRsaRouteFix(unittest.TestCase):
    def test_hastad_keys_point_to_dedicated_solver(self):
        smap = _skill_map()
        for k in ("hastad", "广播攻击"):
            self.assertIn(k, smap, "skill_map 缺键 %r" % k)
            self.assertEqual(smap[k], DEDICATED,
                             "键 %r 应指向专用 solver %s（实际 %r）"
                             % (k, DEDICATED, smap[k]))

    def test_active_key_precedes_rsa_catchall(self):
        """**实际生效的**专属键必须在裸 "rsa" 之前。

        注意：真正命中 ezRSA 的是 description 内的专属键 `同一明文`
        （`hastad`/`广播攻击` 只在 title 里，infer_skill_require 不匹配 title，
        保留它们仅为无害冗余，位置不参与路由）。
        """
        keys = list(_skill_map().keys())
        rsa_idx = keys.index("rsa")
        active = "同一明文"
        self.assertIn(active, keys, "缺description 内专属键 %r" % active)
        self.assertLess(keys.index(active), rsa_idx,
                        "生效键 %r 排在裸 'rsa' 之后 → 被 catch-all 抢走" % active)
        self.assertEqual(_skill_map()[active], DEDICATED)

    def test_infer_skill_require_routes_to_dedicated(self):
        from core.prompts import infer_skill_require
        with open(EZRSA_JSON, encoding="utf-8") as _jf:
            qj = json.load(_jf)

        class _Mgr:
            def __init__(self):
                self.loaded = []

            def list_loaded(self):
                return self.loaded

            def list_available(self):
                return [DEDICATED, GENERIC]

            def load(self, n):
                self.loaded.append(n)

        class _Q:
            category = "crypto"
            description = qj["description"]
            candidate_flag = None

        class _Ctx:
            question = _Q()

        mgr = _Mgr()
        infer_skill_require(_Ctx(), {"ability_gap": ["缺少有效攻击路径"]}, mgr)
        self.assertIn(DEDICATED, mgr.loaded,
                      "ezRSA 必须路由到 %s（实际 %r）" % (DEDICATED, mgr.loaded))

    def test_dedicated_solver_solves_ezrsa(self):
        with open(EZRSA_JSON, encoding="utf-8") as _jf:
            truth = json.load(_jf)["flag_sha256"]
        mod = _load(DEDICATED)
        res = mod.run({"path": EZRSA_ATT,
                       "patterns": [r"flag\{[^}]+\}"]})
        self.assertTrue(res, "专用 solver 未解出 ezRSA")
        m = re.search(r"flag\{[^}]+\}", res)
        self.assertIsNotNone(m, "解出应含 flag{...}：%r" % res)
        self.assertEqual(hashlib.sha256(m.group(0).encode()).hexdigest(), truth,
                         "ezRSA sha256 不匹配")

    def test_generic_solver_does_not_raise(self):
        """核心护栏：rsa_fermat_factor 遇 ezRSA 输入不得抛异常，应优雅返 None。

        修复前：`ValueError: pow() 3rd argument cannot be 0` 直接冒泡崩掉。
        """
        mod = _load(GENERIC)
        try:
            res = mod.run({"path": EZRSA_ATT, "patterns": [r"flag\{[^}]+\}"]})
        except Exception as exc:  # noqa: BLE001 - 本测试就是不许抛
            self.fail("rsa_fermat_factor 抛异常未兜底：%r" % exc)
        self.assertIsNone(res, "解不出时应诚实返回 None，实际 %r" % res)

    def test_generic_solver_still_works_on_dict_input(self):
        """回归：兜底不得破坏原有 dict 形态能力（费马分解 p/q 接近场景）。

        构造要点：明文必须**接近 n** 才需要费马分解；若 m 很小则 c<n 根本不需分解，
        会让本用例失去意义（踩过一次）。
        """
        mod = _load(GENERIC)
        p, q = 1000003, 1000033
        n = p * q
        e = 65537
        # 明文取「接近 n」：m = n - 0x41424344，保证走费马分解路径
        m = n - 0x41424344
        c = pow(m, e, n)
        res = mod.run({"n": n, "e": e, "c": c, "attack": "fermat"})
        self.assertIsNotNone(res, "费马分解能力被兜底改动破坏：%r" % res)
        self.assertEqual(int.from_bytes(res, "big"), m)

    def test_both_solvers_loadable(self):
        import sys
        if _CTF not in sys.path:
            sys.path.insert(0, _CTF)
        from tools.skill_manager import SkillManager
        sm = SkillManager()
        for n in (DEDICATED, GENERIC):
            self.assertTrue(sm.load(n),
                            "%s 无法被 SkillManager 加载：%r" % (n, sm.list_failures()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
