"""B2 回归：rsa_fermat_factor 补「已知 p/q + 高偶指数 e=2^k 降幂+Rabin 还原」。

覆盖 DASCTF 10733 形态（hint 泄露 p → 分解得 p,q≡3 mod 4 → e=2^16 → 降幂到 m^2 → Rabin 还原 m）。
测试向量自构造（同结构、不同参数），不过拟合真实题答案。

需 gmpy2 + pycryptodome（项目 .venv 已具备）；无 gmpy2 时 skill.run 返回 None，测试会失败提示依赖缺失。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills"))
import rsa_fermat_factor as skill  # noqa: E402

from Crypto.Util.number import getPrime, bytes_to_long  # noqa: E402


def _gen_blum(bits):
    """生成两个 ≡3 mod 4 的 bits 位奇素数（Blum 整数所需）。"""
    while True:
        p = getPrime(bits)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(bits)
        if q % 4 == 3 and q != p:
            break
    return p, q


class TestPKnownHighEven(unittest.TestCase):
    def test_p_known_high_even_blum(self):
        """10733 核心形态：已知 p + e=2^16 + p,q≡3 mod 4 → 还原明文。"""
        p, q = _gen_blum(160)
        n = p * q
        e = 2 ** 16
        msg = b"flag{how_many_rot_there_xyz_123}"
        m = bytes_to_long(msg)
        c = pow(m, e, n)
        out = skill.run({"n": n, "e": e, "c": c, "p": p})
        self.assertIsNotNone(out, "高偶指数已知 p 应解出明文")
        self.assertEqual(out, msg)

    def test_p_known_high_even_rot13(self):
        """10733 真实终态：明文 m 本身是 ROT13 编码（可打印 ASCII），筛选应命中。"""
        p, q = _gen_blum(160)
        n = p * q
        e = 2 ** 16
        rot = b"SYNT{ubj_zl_ebg_gurer_xyz_456}"  # ROT13 形态占位（非真 flag）
        m = bytes_to_long(rot)
        c = pow(m, e, n)
        out = skill.run({"n": n, "e": e, "c": c, "p": p})
        self.assertEqual(out, rot)

    def test_p_known_normal_e(self):
        """已知 p 但 e 正常（gcd(e,phi)=1）→ 标准 invert 解密仍生效（回归旧路径）。"""
        p, q = _gen_blum(160)
        n = p * q
        e = 65537
        msg = b"normal_e_known_p_test"
        m = bytes_to_long(msg)
        c = pow(m, e, n)
        out = skill.run({"n": n, "e": e, "c": c, "p": p})
        self.assertEqual(out, msg)

    def test_p_known_via_q(self):
        """已知 q（而非 p）也应走 p_known 路径。"""
        p, q = _gen_blum(160)
        n = p * q
        e = 65537
        msg = b"known_via_q_param"
        m = bytes_to_long(msg)
        c = pow(m, e, n)
        out = skill.run({"n": n, "e": e, "c": c, "q": q})
        self.assertEqual(out, msg)

    def test_high_even_wrong_p_rejected(self):
        """传入非素因子 p → 返回 None，不应崩溃或误报。"""
        p, q = _gen_blum(160)
        n = p * q
        e = 2 ** 16
        msg = b"should_not_solve"
        m = bytes_to_long(msg)
        c = pow(m, e, n)
        out = skill.run({"n": n, "e": e, "c": c, "p": n + 5})
        self.assertIsNone(out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
