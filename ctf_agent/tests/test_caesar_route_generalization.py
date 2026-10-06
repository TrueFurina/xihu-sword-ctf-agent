"""A 修复回归测试：锁死 caesar_bruteforce 的「移位/位移」过度泛化收口（2026-10-06）。

背景（审计实证）：
- skill_map 曾含 "移位"/"位移" -> caesar_bruteforce，导致两道非 Caesar 题被静默错带：
  * real_crypto_anwang_crypto1（实为 Vigenère，"key 字符当移位" 触发 移位）-> caesar
  * real_crypto_anxun2020_aes（实为 AES-CBC，"求位移" 触发 位移）-> caesar
  两者均非 L2（L0/L1 有 writeup 明文 flag），但属 10733 同家族「通用词偷路由」。
- 修复：删除 caesar 的 "移位"/"位移" 键（凯撒/caesar 已足以覆盖真 Caesar 题）。
  删除后这两道路由到 None（诚实，因仓库无 AES/Vigenère 精确匹配键），而非错带 caesar。

本测试锁死两层：① 源文件不再含 移位/位移->caesar（防回归）；② 两道真实题面
经 infer_skill_require 不得 load caesar_bruteforce（端到端确定性路由，不依赖 LLM）。
"""
import os
import unittest
import importlib.util

_HERE = os.path.dirname(os.path.abspath(__file__))
PROMPTS_PATH = os.path.join(_HERE, "..", "core", "prompts.py")
ANWANG_JSON = os.path.join(_HERE, "..", "data", "questions_real", "crypto",
                            "real_crypto_anwang_crypto1.json")
ANXUN_JSON = os.path.join(_HERE, "..", "data", "questions_real", "crypto",
                           "real_crypto_anxun2020_aes.json")

with open(PROMPTS_PATH, encoding="utf-8") as _f:
    PROMPTS_SRC = _f.read()


class TestCaesarRouteGeneralization(unittest.TestCase):
    def test_caesar_no_overbroad_shift_keys(self):
        # 修复核心：凯撒/caesar 保留，移位/位移 必须移除（否则再次偷路由）
        self.assertIn('"凯撒": "caesar_bruteforce"', PROMPTS_SRC,
                      "skill_map 缺 凯撒->caesar_bruteforce（真 Caesar 路由退化）")
        self.assertIn('"caesar": "caesar_bruteforce"', PROMPTS_SRC,
                      "skill_map 缺 caesar->caesar_bruteforce（真 Caesar 路由退化）")
        self.assertNotIn('"移位": "caesar_bruteforce"', PROMPTS_SRC,
                          "skill_map 仍含 移位->caesar（过度泛化未收口）")
        self.assertNotIn('"位移": "caesar_bruteforce"', PROMPTS_SRC,
                          "skill_map 仍含 位移->caesar（过度泛化未收口）")

    def _route_loaded(self, json_path):
        from core.prompts import infer_skill_require
        import json as _json
        with open(json_path, encoding="utf-8") as _qf:
            qj = _json.load(_qf)

        class _Mgr:
            def __init__(self):
                self.loaded = []

            def list_loaded(self):
                return self.loaded

            def list_available(self):
                # 含 caesar_bruteforce：若题面会错路由到它，则会被 load，测试即失败
                return ["caesar_bruteforce", "vigenere_decode", "hash_crack",
                        "base64_multilayer", "rsa_fermat_factor"]

            def load(self, name):
                self.loaded.append(name)

        class _Q:
            category = "crypto"
            description = qj.get("description") or ""
            candidate_flag = None

        class _Ctx:
            question = _Q()

        mgr = _Mgr()
        infer_skill_require(_Ctx(), {"ability_gap": ["缺少有效攻击路径"]}, mgr)
        return mgr.loaded

    def test_anwang_crypto1_not_routed_to_caesar(self):
        """anwang_crypto1（Vigenère）不得被 移位 偷路由到 caesar_bruteforce。"""
        self.assertNotIn(
            "caesar_bruteforce", self._route_loaded(ANWANG_JSON),
            "anwang_crypto1 仍被错路由到 caesar_bruteforce（移位 泛化未收口）")

    def test_anxun2020_aes_not_routed_to_caesar(self):
        """anxun2020_aes（AES-CBC）不得被 位移 偷路由到 caesar_bruteforce。"""
        self.assertNotIn(
            "caesar_bruteforce", self._route_loaded(ANXUN_JSON),
            "anxun2020_aes 仍被错路由到 caesar_bruteforce（位移 泛化未收口）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
