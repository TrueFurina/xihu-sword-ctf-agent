"""xuanhun_signin（JPEG 尾部嵌 PNG + 视觉 flag）OCR 回归测试。

锁定 M3 增强：presolve 经 jpeg_png_embedded skill 提取内嵌 PNG 后用 tesseract OCR
命中视觉 flag，使真题集确定性覆盖从 14/15 提升至 15/15。CI 环境若无 tesseract 则 skip，
避免在没有 OCR 引擎的机器上误红。
"""
from __future__ import annotations
import os
import sys
import unittest

# 让仓库根可被 import（与项目其它测试一致）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from skills.jpeg_png_embedded import _locate_tesseract, run  # noqa: E402

_ATTACH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "questions_real", "_attachments", "misc",
    "real_misc_xuanhun_signin", "xz1.jpg",
)


class TestJpegPngOcr(unittest.TestCase):
    def test_tesseract_locatable(self):
        exe, tdata = _locate_tesseract()
        self.assertIsNotNone(exe, "tesseract 未在 PATH 或候选路径中找到")
        self.assertIsNotNone(tdata, "tessdata 目录（含 eng.traineddata）未定位")

    @unittest.skipUnless(os.path.isfile(_ATTACH), "xz1.jpg 附件缺失")
    def test_xuanhun_signin_ocr_flag(self):
        exe, _ = _locate_tesseract()
        if not exe:
            self.skipTest("tesseract 不可用，跳过 OCR 断言")
        r = run({"path": _ATTACH})
        self.assertTrue(r.get("ok"), f"skill 执行失败: {r}")
        self.assertEqual(r.get("flag"), "flag{mooaudqxs5nbydw3}",
                         "xuanhun_signin 视觉 flag 未被 OCR 命中")
        self.assertEqual(r.get("flag_source"), "ocr:tesseract")


if __name__ == "__main__":
    unittest.main()
