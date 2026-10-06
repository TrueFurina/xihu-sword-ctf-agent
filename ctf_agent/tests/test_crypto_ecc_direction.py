"""B2 提推理：crypto 卡壳时的椭圆曲线/ECDLP 方向模板回归。

背景（2026-10-06）：真·L2=10 纯推理层仅剩 2 道失败（10733 / real_crypto_specialcurve2），
均为 crypto、已训练池内、wrong_direction（奔错方向、烧 487s 墙钟放弃）。
根因：引擎对 crypto 的「标准路径」(STANDARD_FLOWS) 与 FEW_SHOT_BANK / skill_map
完全没有椭圆曲线/离散对数方向模板——crypto_auto 只覆盖 RSA/编码/格攻击，ECC 题
agent 无方向可走只能乱猜。本测试锁死该缺口已补齐，防静默回退。

验证两层：
1. STANDARD_FLOWS["crypto"] 含 ECC/ECDLP 方向步骤；
2. 卡壳 crypto 题经分层作战视图(build_hierarchical_view)必把该方向注入 prompt。
"""

import unittest
from types import SimpleNamespace

from agents.templates import TemplateBank
from core.hierarchical_plan import build_hierarchical_view
from core.strategy_blackboard import StrategyBlackboard


class TestCryptoEccDirection(unittest.TestCase):
    def test_standard_flow_has_ecc_guidance(self):
        flow = TemplateBank().standard_flow("crypto")
        self.assertTrue(flow, "crypto 标准路径不应为空")
        joined = "\n".join(flow)
        self.assertIn("椭圆曲线", joined)
        self.assertIn("ECDLP", joined)
        self.assertIn("BSGS", joined)
        # 关键：明确禁止把 ECC 当 RSA 处理（原 wrong_direction 主因）
        self.assertIn("禁止默认当 RSA", joined)

    def test_hierarchical_view_surfaces_ecc_when_stuck_on_crypto(self):
        # 构造卡壳 crypto 上下文：黑板已沉淀一条失败策略签名
        bb = StrategyBlackboard()
        bb.record(SimpleNamespace(
            stage="recon", action="reason", observation="",
            error_category="wrong_direction", tool_used=None,
        ))
        self.assertTrue(bb.failed_signatures(), "失败签名应被记录")

        ctx = SimpleNamespace(
            question=SimpleNamespace(category="crypto"),
            blackboard=bb,
        )
        view = build_hierarchical_view(ctx)
        self.assertTrue(view, "crypto 卡壳时分层作战视图应为非空")
        self.assertIn("椭圆曲线", view)
        self.assertIn("ECDLP", view)


if __name__ == "__main__":
    unittest.main(verbosity=2)
