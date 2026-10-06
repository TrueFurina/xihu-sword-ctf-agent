"""B 修复回归测试：锁死 Google CTF 2022「Cycling」题（RSA 循环攻击，2^1025-2 因数）
正确路由到 crypto_cycling 并端到端解出（2026-10-06）。

背景（审计实证）：
- crypto_cycling 是「单题专用」求解器（硬编码 2^1025-2 因数库），长期是 skill_map
  孤儿（存在 skills/ 却无任何触发词），导致该题路由到 None（诚实但能力浪费）。
- 该题描述含 "2^1025-3 encryptions" / "cycle attack"，但通用键会过泛（caesar 式错误），
  故采用**题专属键** "2^1025"（极具体，仅该题命中）接线——这是 B 层孤儿求解器的
  正确接线范式：单题专用 solver 必须用题专属键，禁用通用键。
- 本测试锁死两层：① 路由正确（题面 load crypto_cycling）；② 真实 chall.py 的
  n/e/ct 经 crypto_cycling.run 端到端解出且 flag 非空（纯本地数论，无网络/LLM）。
"""
import os
import re
import unittest
import importlib.util

_HERE = os.path.dirname(os.path.abspath(__file__))
PROMPTS_PATH = os.path.join(_HERE, "..", "core", "prompts.py")
CYCLING_JSON = os.path.join(
    _HERE, "..", "data", "questions_external", "crypto",
    "ext_gctf2022_cycling.json")
CHALL_PY = os.path.join(
    _HERE, "..", "data", "questions_external", "crypto",
    "ext_gctf2022_cycling", "_attachments", "chall.py")

with open(PROMPTS_PATH, encoding="utf-8") as _f:
    PROMPTS_SRC = _f.read()


def _load_cycling():
    spec = importlib.util.spec_from_file_location(
        "crypto_cycling",
        os.path.join(_HERE, "..", "skills", "crypto_cycling.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _real_n_e_ct():
    with open(CHALL_PY, encoding="utf-8") as _cf:
        src = _cf.read()
    # 长度过滤排除示例短值（0x112b00148621），只取真实长十六进制
    n = int(re.search(r"n\s*=\s*(0x[0-9a-fA-F]{40,})", src).group(1), 16)
    ct = int(re.search(r"ct\s*=\s*(0x[0-9a-fA-F]{40,})", src).group(1), 16)
    e = 65537
    return n, e, ct


class TestCyclingRoute(unittest.TestCase):
    def test_skillmap_has_cycling_challenge_key(self):
        # 题专属键（不过泛）：仅本题描述 "2^1025-3 encryptions" 命中
        self.assertIn('"2^1025": "crypto_cycling"', PROMPTS_SRC,
                      "skill_map 缺 Cycling 题专属键 2^1025 -> crypto_cycling")

    def test_infer_skill_require_loads_crypto_cycling_for_cycling(self):
        """端到端确定性路由：Cycling 真实题面必须 load crypto_cycling。"""
        from core.prompts import infer_skill_require
        import json as _json
        with open(CYCLING_JSON, encoding="utf-8") as _qf:
            qj = _json.load(_qf)

        class _Mgr:
            def __init__(self):
                self.loaded = []

            def list_loaded(self):
                return self.loaded

            def list_available(self):
                return ["crypto_cycling", "rsa_fermat_factor",
                        "crypto_high_exponent"]

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
            "crypto_cycling", mgr.loaded,
            "Cycling 题面必须路由加载 crypto_cycling（B 孤儿求解器接线生效）")

    def test_crypto_cycling_solves_cycling_real(self):
        """端到端解出 Cycling 真实实例（纯本地数论）：run() 返回非空 flag。"""
        cyc = _load_cycling()
        n, e, ct = _real_n_e_ct()
        res = cyc.run({"n": n, "e": e, "ct": ct})
        self.assertTrue(res.get("ok", True),
                        "crypto_cycling 未能解出 Cycling: %r" % res)
        flag = res.get("flag") or ""
        self.assertTrue(flag, "解出为空（Cycling 真实实例）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
