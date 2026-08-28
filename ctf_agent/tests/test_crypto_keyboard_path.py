"""crypto_keyboard_path 确定性解码单测（暗泉杯 DNUICTF「键盘侠」）。"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from skills.crypto_keyboard_path import decode, run, decode_token  # noqa: E402

ATT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "questions_real", "_attachments", "crypto",
    "real_crypto_dnui_keyboard", "[签到]键盘侠.txt",
)


def test_decode_known_sample():
    # 暗泉杯实测 8 字母走法，确定性解出 CLCKOUTHK
    sample = "UYTGBNM EDCV UYTGBNM TGBUHM YTFVBH QAZXCDE TYUHN EDCTGBF RFVYGN"
    assert decode(sample) == "CLCKOUTHK"


def test_run_on_real_attachment():
    # 独立从附件推导出 flag（不读题面答案），sha256 与官方真值一致
    r = run({"path": ATT})
    assert r["decoded"] == "CLCKOUTHK"
    assert r["flag"] == "flag{CLCKOUTHK}"


def test_decode_token_known():
    assert decode_token("UYTGBNM") == "C"
    assert decode_token("EDCV") == "L"
    assert decode_token("TGBUHM") == "K"
    assert decode_token("RFVYGN") == "K"  # K 的另一走法


def test_instruction_line_filtered():
    # 题面说明行（小写 flag / 中文）不应污染解码
    text = "UYTGBNM EDCV\nflag{} 提交时括号内为大写字母"
    assert decode(text) == "CL"
