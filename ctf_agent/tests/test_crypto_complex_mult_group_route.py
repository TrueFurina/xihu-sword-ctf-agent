"""B2 纠错回归测试：锁死 specialcurve2 类题目的正确路由（非 ECC）。

背景（2026-10-06）：盲测 specialcurve2 失败根因是 skill_map 无任何触发词匹配
"复数乘法群/类 RSA"题面 → crypto_complex_mult_group 现成 skill 未路由 → agent 硬推
wrong_direction。曾误判为椭圆曲线并加过 ECC 方向模板（a4a2a64/7b4c237），实证证伪后已
回退（1c52dd9/4460cb1）。本测试锁死"正确修复"不被静默回退：
  ① skill_map 必须含复数乘法群 RSA 变体的触发词 → crypto_complex_mult_group
  ② crypto 标准路径必须浮现 crypto_complex_mult_group skill 指引，且明确"不是椭圆曲线"
  ③ 旧的 ECC 方向模板字符串必须已彻底清除
"""
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
PROMPTS_PATH = os.path.join(_HERE, "..", "core", "prompts.py")
TEMPLATES_PATH = os.path.join(_HERE, "..", "agents", "templates.py")

with open(PROMPTS_PATH, encoding="utf-8") as _f:
    PROMPTS_SRC = _f.read()
with open(TEMPLATES_PATH, encoding="utf-8") as _f:
    TEMPLATES_SRC = _f.read()

_TRIGGERS = ["复数乘法群", "复乘", "类 rsa", "specialcurve", "高斯整数"]


class TestComplexMultGroupRoute(unittest.TestCase):
    def test_skillmap_routes_complex_mult_group(self):
        for kw in _TRIGGERS:
            self.assertIn(
                '"%s": "crypto_complex_mult_group"' % kw, PROMPTS_SRC,
                "skill_map 缺触发词路由: %s -> crypto_complex_mult_group" % kw)

    def test_standard_flow_uses_skill_and_rejects_ecc(self):
        self.assertIn(
            "crypto_complex_mult_group", TEMPLATES_SRC,
            "crypto 标准路径未提及 crypto_complex_mult_group skill")
        self.assertIn(
            "复数乘法群", TEMPLATES_SRC,
            "crypto 标准路径未提及复数乘法群识别")
        # 纠错核心：必须明确这不是椭圆曲线，防止旧误判复发
        self.assertIn(
            "不是椭圆曲线", TEMPLATES_SRC,
            "crypto 标准路径未明确'不是椭圆曲线'，旧 ECC 误判未清除")
        # 反方向：旧 ECC 方向模板字符串必须已彻底清理
        self.assertNotIn(
            "椭圆曲线/ECDLP/离散对数方向", TEMPLATES_SRC,
            "仍残留旧的 ECC 方向模板，未彻底清理")


if __name__ == "__main__":
    unittest.main(verbosity=2)
