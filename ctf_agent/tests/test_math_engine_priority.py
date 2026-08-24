# -*- coding: utf-8 -*-
"""数学引擎优先级测试：空壳引擎不得进入竞速顺序（锐评 P1-3）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.math_engine import MathEngineMatrix

_STUB_ENGINES = {
    "crypto_coppersmith", "crypto_lattice",
    "crypto_ecb", "rsa_factor_ecm", "dlp_bsgs",
}


def test_priority_order_excludes_stub_engines():
    order = MathEngineMatrix._priority_order()
    overlap = _STUB_ENGINES & set(order)
    assert not overlap, f"空壳引擎不应在竞速顺序中: {overlap}"
    assert "rsa_chain" in order
    assert "misc_decode" in order
