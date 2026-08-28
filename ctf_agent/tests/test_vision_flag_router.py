"""vision_flag_router 诚实路由测试。

不依赖 PIL/numpy/视觉模型：仅验证
1. 尾部文件 carving 确定性正确（xuanhun 第一步可解部分）；
2. 图内渲染文字检测关键词命中正确；
3. **诚实性**：无视觉端点时一律 NEEDS_VISION 且 flag=None，绝不伪造；
4. 提供视觉端点时走真实 OCR 取 flag。
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.vision_flag_router import (
    VisionResult,
    carve_trailing_file,
    detect_vision_flag,
    route_vision_flag,
)

_JPEG_EOI = b"\xff\xd9"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _fake_jpeg_with_png(png_body: bytes = b"\xaa" * 32) -> bytes:
    # PNG 主体给足 32 字节，确保超过 carve 守卫 min_len(16)，贴近真实尾部文件
    return b"fake-jpeg-data" + _JPEG_EOI + _PNG_MAGIC + png_body


class TestCarveTrailing(unittest.TestCase):
    def test_carve_png_from_jpeg(self):
        raw = _fake_jpeg_with_png(b"\xaa" * 32)
        out = carve_trailing_file(raw, _PNG_MAGIC)
        self.assertIsNotNone(out)
        self.assertTrue(out.startswith(_PNG_MAGIC))
        self.assertEqual(out, _PNG_MAGIC + b"\xaa" * 32)

    def test_no_magic_returns_none(self):
        self.assertIsNone(carve_trailing_file(b"plain data no magic", _PNG_MAGIC))

    def test_empty_input(self):
        self.assertIsNone(carve_trailing_file(b"", _PNG_MAGIC))
        self.assertIsNone(carve_trailing_file(None, _PNG_MAGIC))


class TestDetectVisionFlag(unittest.TestCase):
    def test_xuanhun_description_hits(self):
        desc = "xz1.jpg 是 JPEG 文件，尾部嵌入 PNG（FFD9 后接 PNG 头）。提取 PNG 即可看到 flag 文字。"
        needs, reason = detect_vision_flag(desc)
        self.assertTrue(needs)
        self.assertIn("flag", reason)

    def test_vnctf_dotmatrix_hits(self):
        desc = "flag 文字藏在点阵排布中，网格重采样显字类"
        needs, _ = detect_vision_flag(desc)
        self.assertTrue(needs)

    def test_plain_crypto_misses(self):
        desc = "RSA modulus n = p*q, recover d from e"
        needs, _ = detect_vision_flag(desc)
        self.assertFalse(needs)

    def test_empty_description_misses(self):
        self.assertEqual(detect_vision_flag(""), (False, ""))


class TestHonestRouting(unittest.TestCase):
    def test_no_vision_fn_is_needs_vision_not_fake(self):
        desc = "JPEG 尾部嵌入 PNG，提取 PNG 即可看到 flag 文字。"
        res = route_vision_flag(desc, attachment=_fake_jpeg_with_png())
        self.assertIsInstance(res, VisionResult)
        self.assertEqual(res["status"], "NEEDS_VISION")
        self.assertTrue(res["needs_vision"])
        self.assertIsNone(res["flag"])  # 关键：绝不伪造
        self.assertIsNotNone(res["carved"])  # 但可解的第一步（carving）已做

    def test_non_vision_domain_passes_through(self):
        desc = "RSA modulus n = p*q"
        res = route_vision_flag(desc, attachment=b"x")
        self.assertEqual(res["status"], "NOT_VISION_DOMAIN")
        self.assertFalse(res["needs_vision"])
        self.assertIsNone(res["flag"])

    def test_vision_fn_used_when_provided(self):
        # 贴近 xuanhun 真实场景：JPEG 尾部嵌入 PNG，carving 触发后交视觉端点
        desc = "JPEG 尾部嵌入 PNG，提取 PNG 即可看到 flag 文字。"
        png = _PNG_MAGIC + b"\xaa" * 32

        def fake_ocr(img: bytes) -> str:
            self.assertTrue(img.startswith(_PNG_MAGIC))
            return "the flag is flag{xuanhun_2026_visible}"

        res = route_vision_flag(desc, attachment=_fake_jpeg_with_png(), vision_fn=fake_ocr)
        self.assertEqual(res["status"], "SOLVED_VIA_VISION")
        self.assertEqual(res["flag"], "flag{xuanhun_2026_visible}")

    def test_vision_fn_failure_degrades_honestly(self):
        desc = "JPEG 尾部嵌入 PNG，提取 PNG 即可看到 flag 文字。"

        def boom(img: bytes) -> str:
            raise RuntimeError("vision endpoint down")

        res = route_vision_flag(desc, attachment=_fake_jpeg_with_png(), vision_fn=boom)
        self.assertEqual(res["status"], "NEEDS_VISION")
        self.assertIsNone(res["flag"])


if __name__ == "__main__":
    unittest.main()
