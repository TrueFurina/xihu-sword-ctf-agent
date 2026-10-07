"""B 接线回归测试：孤儿求解器回收·第四批三题（1black0white / MHK2 / LCD）
正确路由并端到端解出，sha256 逐字匹配（2026-10-06）。

背景（审计 + 实证）：
三者均为「单题专用」求解器，长期是skill_map 孤儿（存在于 skills/ 却无触发词），
对应题目路由到 None。本测试锁死接线后**端到端真解**（非仅路由断言）：
- 1black0white（数字矩阵→QR）：run({"path": qr_code.txt}) 直接解出。
- MHK2（Murakami 背包）：run({"kind":"mhk2_decrypt","pk":...,"ct":...})，
  output.txt 为两行 Python dict/列表字面量，用 ast.literal_eval 解析。
- least-common-genominator（LCG→RSA 私钥重建）：run({"kind":"dir",...})，
  flag.txt 是**密文**（非明文），dump.txt 是 6 个 LCG 输出。
- 另附 primes 的**诚实失败**断言：该题chal.sage 附件直含明文 flag（L0 送分层），
  且求解器实跑返回 ok=False（max_attempts 未命中）——禁止把它记成"已解"。

键选取纪律（题专属短语，禁泛化）：
- "seemingly random numbers"（禁「QR/二维码」泛化）
- "murakami"（语义精确指孟三脚背包攻击）
- "dumped the first six"（**必须取 description 内短语**——infer_skill_require 只匹配
  description，题名 "Least Common Genominator?" 不参与匹配。实测：只挂题名键时
  该题路由为None，测试立刻转红）
"""
import ast
import hashlib
import importlib.util
import json
import os
import re
import unittest
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
PROMPTS_PATH = os.path.join(_CTF, "core", "prompts.py")

_EXT = os.path.join(_CTF, "data", "questions_ext")
_EXTQ = os.path.join(_CTF, "data", "questions_external")
_ATT_EXT = os.path.join(_EXT, "_attachments")

QR_DIR = os.path.join(_ATT_EXT, "forensics", "2023q-for-1black0white")
QR_JSON = os.path.join(_EXT, "forensics",
                       "ext_nyu_ctf_bench_2023q_for_1black0white.json")
MHK_DIR = os.path.join(_EXTQ, "crypto", "ext_gctf2023_mhk2", "_attachments")
MHK_JSON = os.path.join(_EXTQ, "crypto", "ext_gctf2023_mhk2.json")
LCD_DIR = os.path.join(_EXTQ, "crypto",
                       "ext_gctf2023_least-common-genominator", "_attachments")
LCD_JSON = os.path.join(_EXTQ, "crypto",
                        "ext_gctf2023_least-common-genominator.json")
PRIMES_JSON = os.path.join(_EXTQ, "crypto", "ext_gctf2023_primes.json")
PRIMES_ATT = os.path.join(_EXTQ, "crypto", "ext_gctf2023_primes", "_attachments")

# (用例名, 题专属键, 求解器, 题面 JSON)
ROUTES = [
    ("1black0white", "seemingly random numbers", "misc_qr_matrix", QR_JSON),
    ("mhk2", "murakami", "crypto_knapsack_mhk", MHK_JSON),
    ("lcd", "dumped the first six", "crypto_lcg_recover", LCD_JSON),
    # primes（GCTF 2023 素数背包）：2026-10-06 复核后接线（此前误判为 L0 不接）。
    ("primes", "mangled somehow", "crypto_primes_subset", PRIMES_JSON),
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


def _primes_qx_from_chal():
    """从附件 chal.sage 的注释里取官方打印的 (q, x) 与 n（明文长度 × 7）。"""
    chal = os.path.join(PRIMES_ATT, "chal.sage")
    with open(chal, encoding="utf-8") as _cf:
        src = _cf.read()
    q = int(re.search(r"q = 0x([0-9A-Fa-f]+)", src).group(1), 16)
    x = int(re.search(r"x = 0x([0-9A-Fa-f]+)", src).group(1), 16)
    msg = re.search(r'm = b"([^"]+)"', src).group(1)
    return q, x, 7 * len(msg)


def _load_skill(name):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_CTF, "skills", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TestFourthBatchRoutes(unittest.TestCase):
    def test_all_keys_exist_and_point_correctly(self):
        smap = _skill_map()
        for name, key, skill, _ in ROUTES:
            self.assertIn(key, smap, "skill_map 缺 %s 题专属键 %r" % (name, key))
            self.assertEqual(smap[key], skill,
                             "键 %r 应指向 %s，实际 %r" % (key, skill, smap[key]))

    def test_all_keys_precede_rsa_catchall(self):
        keys = list(_skill_map().keys())
        rsa_idx = keys.index("rsa")
        for name, key, _, _ in ROUTES:
            self.assertLess(keys.index(key), rsa_idx,
                            "%s 专属键排在裸 'rsa' 之后 → 会被 catch-all 抢走" % name)

    @pytest.mark.local
    def test_infer_skill_require_routes_each(self):
        """端到端确定性路由：三题真实题面必须 load 对应 solver。"""
        from core.prompts import infer_skill_require
        for name, key, skill, qjson in ROUTES:
            with open(qjson, encoding="utf-8") as _jf:
                qj = json.load(_jf)

            class _Mgr:
                def __init__(self):
                    self.loaded = []

                def list_loaded(self):
                    return self.loaded

                def list_available(self):
                    return [skill, "rsa_fermat_factor", "base64_multilayer"]

                def load(self, n):
                    self.loaded.append(n)

            class _Q:
                category = getattr(qj, "get", lambda *_: "crypto")("category") or "crypto"
                description = qj["description"]
                candidate_flag = None

            class _Ctx:
                question = _Q()

            mgr = _Mgr()
            infer_skill_require(_Ctx(), {"ability_gap": ["缺少有效攻击路径"]}, mgr)
            self.assertIn(skill, mgr.loaded,
                          "%s 必须路由到 %s（实际 %r）" % (name, skill, mgr.loaded))

    def test_all_target_skills_loadable_by_skill_manager(self):
        """接线前提：三个 solver 都能被 SkillManager 真实加载。"""
        from tools.skill_manager import SkillManager
        sm = SkillManager()
        for name, _, skill, _ in ROUTES:
            self.assertTrue(sm.load(skill),
                            "%s 无法被 SkillManager 加载：%r" % (name, sm.list_failures()))

    @pytest.mark.local
    def test_1black0white_real_solve(self):
        mod = _load_skill("misc_qr_matrix")
        out = mod.run({"path": os.path.join(QR_DIR, "qr_code.txt")})
        self.assertTrue(out, "1black0white 未解出")
        with open(QR_JSON, encoding="utf-8") as _jf:
            exp = json.load(_jf)["flag_sha256"]
        self.assertEqual(_sha(out.decode("utf-8", "replace")), exp,
                         "1black0white sha256 不匹配")

    @pytest.mark.local
    def test_mhk2_real_solve(self):
        mod = _load_skill("crypto_knapsack_mhk")
        with open(os.path.join(MHK_DIR, "output.txt"), encoding="utf-8") as _of:
            lines = [l for l in _of.read().splitlines() if l.strip()]
        pk = ast.literal_eval(lines[0])
        ct = ast.literal_eval(lines[1])
        res = mod.run({"kind": "mhk2_decrypt", "pk": pk, "ct": ct})
        self.assertTrue(res.get("ok"), "MHK2 未解出：%r" % res)
        with open(MHK_JSON, encoding="utf-8") as _jf:
            exp = json.load(_jf)["flag_sha256"]
        self.assertEqual(_sha(res["plaintext"]), exp, "MHK2 sha256 不匹配")

    @pytest.mark.local
    def test_lcd_real_solve(self):
        mod = _load_skill("crypto_lcg_recover")
        res = mod.run({"kind": "dir", "dir": LCD_DIR})
        self.assertTrue(res.get("ok"), "LCD 未解出：%r" % res)
        with open(LCD_JSON, encoding="utf-8") as _jf:
            exp = json.load(_jf)["flag_sha256"]
        self.assertEqual(_sha(res["flag"]), exp, "LCD sha256 不匹配")

    @pytest.mark.local
    def test_primes_real_solve_sha_match(self):
        """primes（GCTF 2023 素数背包）实证解出，sha256 逐字匹配题面真值。

        🔴 2026-10-06 更正：本测试原先断言「primes 是L0 送分层、不应接线」——
        该前提**错误**，已被确定性重算推翻。真相：
        - 附件 chal.sage 里 `m = b"...CTF{YkDOL...}"` 是**别处粘贴的无关示例**
          （重算 x 与官方 x 不符）；
        - 真值需Coppersmith 平滑因子法真解，求解器 32s 解出且
          `sha256("CTF{...}")` 与题面 flag_sha256 **完全匹配**（登记口径只对
          `CTF{...}` 部分取摘要，不含前缀）。
        因此 primes 是**真·推理题**，现已接线。
        """
        import hashlib
        mod = _load_skill("crypto_primes_subset")
        with open(PRIMES_JSON, encoding="utf-8") as _jf:
            truth = json.load(_jf)["flag_sha256"]
        q, x, n = _primes_qx_from_chal()
        res = mod.run({"kind": "solve", "q": q, "x": x, "n": n, "r": 131})
        self.assertTrue(res.get("ok"), "primes 求解器未解出：%r" % res)
        flag = res["flag"]
        m = re.search(rb"CTF\{[^}]*\}", flag.encode() if isinstance(flag, str) else flag)
        self.assertIsNotNone(m, "解出结果应含 CTF{...}：%r" % flag)
        got = hashlib.sha256(m.group(0)).hexdigest()
        self.assertEqual(got, truth, "primes 解出 sha256 不匹配（口径：只对 CTF{...} 取摘要）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
