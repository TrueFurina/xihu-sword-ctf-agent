"""B 接线回归测试：lowe（CSAW-Quals 2018·e=3 无填充 + Y+N 完全立方）正确路由
到 crypto_pkcs1_padding_oracle 并端到端解出（2026-10-06）。

背景（审计 + 实证）：
- crypto_pkcs1_padding_oracle 是「单题专用」求解器（lowe 是其目标题），长期是
  skill_map 孤儿（存在于 skills/ 却无触发词），该题路由到 None。
- 攻击链（纯本地数论，零 LLM/零网络）：
    1) pubkey.pem 的 DER 中提取 1536-bit N（偏移 0x0281c1 标记后 193 字节）；
    2) key.enc 是十进制 ASCII 的 Y；e=3 且**无 padding**，题面明示
       「by construction Y+N is a perfect cube, whose root is K」；
    3) K = iroot(Y+N, 3)（gmpy2，实测 exact=True）；
    4) file.enc 是 base64 的 C；secret S = C XOR K 的**低 64 字节**（64-byte secret）。
- 端到端实证：解出 64 字节明文 secret，sha256 与题面 flag_sha256 逐字匹配。
- 键选取纪律：题专属短语 "perfect cube"（全题库仅命中本题 4 份副本，零误伤）；
  禁用「无填充」「1536-bit」等泛化表述（同 caesar 位移键的教训）。
"""
import ast
import base64
import hashlib
import importlib.util
import json
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
PROMPTS_PATH = os.path.join(_CTF, "core", "prompts.py")
Q_JSON = os.path.join(_CTF, "data", "questions_ext", "crypto",
                      "ext_nyu_ctf_bench_2018q_cry_lowe.json")
ATT_DIR = os.path.join(_CTF, "data", "questions_ext", "_attachments", "crypto",
                       "2018q-cry-lowe")
KEY_ENC = os.path.join(ATT_DIR, "key.enc")
FILE_ENC = os.path.join(ATT_DIR, "file.enc")
PUBKEY = os.path.join(ATT_DIR, "pubkey.pem")

SKILL_NAME = "crypto_pkcs1_padding_oracle"
ROUTE_KEY = "perfect cube"


def _skill_map():
    with open(PROMPTS_PATH, encoding="utf-8") as _pf:
        tree = ast.parse(_pf.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "skill_map":
                    return ast.literal_eval(node.value)
    raise AssertionError("skill_map not found in prompts.py")


def _load_skill():
    spec = importlib.util.spec_from_file_location(
        SKILL_NAME, os.path.join(_CTF, "skills", SKILL_NAME + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pem_modulus(path):
    """从 RSA 公钥 PEM 的 DER 中提取模数 N（定位 0x02 0x81 0xc1 标记后的 193 字节）。"""
    with open(path, "rb") as _kf:
        pem = _kf.read()
    body = b"".join(l for l in pem.split(b"\n") if not l.startswith(b"---"))
    der = base64.b64decode(body)
    marker = der.find(b"\x02\x81\xc1")
    assert marker >= 0, "pubkey.pem DER 结构异常：未定位到 N 标记"
    return int.from_bytes(der[marker + 3:marker + 3 + 193], "big")


class TestLoweRoute(unittest.TestCase):
    def test_skillmap_has_lowe_challenge_key(self):
        smap = _skill_map()
        self.assertIn(ROUTE_KEY, smap, "skill_map 缺 lowe 题专属键 %r" % ROUTE_KEY)
        self.assertEqual(smap[ROUTE_KEY], SKILL_NAME,
                         "键 %r 应指向 %s" % (ROUTE_KEY, SKILL_NAME))

    def test_lowe_key_precedes_generic_catchalls(self):
        """专属键必须排在裸 "rsa" 之前，否则被 RSA catch-all 抢走。"""
        keys = list(_skill_map().keys())
        self.assertLess(keys.index(ROUTE_KEY), keys.index("rsa"),
                        "lowe 专属键排在裸 'rsa' 之后 → 会被 catch-all 抢走")

    def test_infer_skill_require_routes_lowe(self):
        """端到端确定性路由：lowe 真实题面必须 load crypto_pkcs1_padding_oracle。"""
        from core.prompts import infer_skill_require
        with open(Q_JSON, encoding="utf-8") as _jf:
            qj = json.load(_jf)

        class _Mgr:
            def __init__(self):
                self.loaded = []

            def list_loaded(self):
                return self.loaded

            def list_available(self):
                return [SKILL_NAME, "rsa_fermat_factor"]

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
        self.assertIn(SKILL_NAME, mgr.loaded,
                      "lowe 题面必须路由加载 %s（实际 %r）" % (SKILL_NAME, mgr.loaded))

    def test_lowe_real_instance_solved_with_sha_match(self):
        """端到端解出 lowe 真实实例：e=3 无填充 → Y+N 完全立方 → C XOR K_low64。"""
        import gmpy2

        n = _pem_modulus(PUBKEY)
        self.assertEqual(n.bit_length(), 1536, "lowe N 应为 1536-bit")

        with open(KEY_ENC, encoding="utf-8") as _kf:
            y = int(_kf.read().strip())
        with open(FILE_ENC, encoding="utf-8") as _ff:
            c = base64.b64decode(_ff.read().strip())
        self.assertEqual(len(c), 64, "lowe secret 应为 64 字节")

        k, exact = gmpy2.iroot(gmpy2.mpz(y + n), 3)
        self.assertTrue(exact, "Y+N 应为完全立方（lowe 构造保证）")

        secret = bytes(a ^ b for a, b in zip(c, int(k).to_bytes(64, "big")))

        with open(Q_JSON, encoding="utf-8") as _jf:
            expected = json.load(_jf).get("flag_sha256")
        self.assertTrue(expected, "lowe 题面缺 flag_sha256，无法校验")
        got = hashlib.sha256(secret).hexdigest()
        self.assertEqual(got, expected,
                         "lowe 解出与题面 flag_sha256 不匹配（got=%s）" % got)

    def test_skill_manager_can_load_target_skill(self):
        """接线前提：目标求解器必须能被 SkillManager 真实加载（有 run() 且过 AST 沙箱）。"""
        from tools.skill_manager import SkillManager
        sm = SkillManager()
        self.assertTrue(sm.load(SKILL_NAME),
                        "%s 无法被 SkillManager 加载（接路由键将失效）：%r"
                        % (SKILL_NAME, sm.list_failures()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
