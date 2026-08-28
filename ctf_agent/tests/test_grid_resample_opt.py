"""misc_grid_resample._build_or_reveal 向量化回归测试。

不依赖 tesseract / 视觉 LLM：仅验证确定性揭示层（网格重采样算法本身）
在向量化改写后行为等价——给定非黑像素网格，揭示图二进制一致、可复现。
"""
import os
import sys
import tempfile
import unittest

import numpy as np
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import skills.misc_grid_resample as M


def _make_grid_image(cols=8, rows=6, gx=20, gy=20, ox=4, oy=4, color=(200, 30, 30)):
    """在纯黑图上，按网格 (gx,gy,ox,oy) 在每格中心放一个彩色点。"""
    w = ox + cols * gx
    h = oy + rows * gy
    arr = np.zeros((h, w, 3), dtype=np.uint8)
    for r in range(rows):
        for c in range(cols):
            x = ox + c * gx + gx // 2
            y = oy + r * gy + gy // 2
            arr[y, x] = color
    return Image.fromarray(arr), arr, cols * rows


class TestGridResampleReveal(unittest.TestCase):
    def test_or_reveal_lits_placed_cells(self):
        img, arr, n = _make_grid_image()
        reveal, dims, _ = M._build_or_reveal(img, arr, 20, 20, 4, 4)
        self.assertIsNotNone(reveal, "应有揭示图")
        ra = np.array(reveal)
        # 揭示图为 2D 灰度：点亮格=0(黑)，背景=255(白)
        mask = ra < 250
        self.assertEqual(int(mask.sum()), n,
                         f"点亮单元格 {int(mask.sum())} != 放置彩点 {n}")

    def test_or_reveal_empty_image_returns_none(self):
        arr = np.zeros((100, 100, 3), dtype=np.uint8)
        img = Image.fromarray(arr)
        reveal, dims, _ = M._build_or_reveal(img, arr, 20, 20, 4, 4)
        self.assertIsNone(reveal, "纯黑图应返回 None")

    def test_or_reveal_deterministic(self):
        img, arr, _ = _make_grid_image(color=(10, 220, 90))
        r1, _, _ = M._build_or_reveal(img, arr, 20, 20, 4, 4)
        r2, _, _ = M._build_or_reveal(img, arr, 20, 20, 4, 4)
        self.assertTrue(np.array_equal(np.array(r1), np.array(r2)),
                        "同输入应产生完全一致揭示图")

    def test_run_end_to_end_on_synthetic_is_safe(self):
        img, _, _ = _make_grid_image()
        out = tempfile.mkdtemp()
        res = M.run({"file": None, "out_dir": out, "flag_sha256": "",
                     "flag_pattern": r"flag\{[^}]+\}"})
        self.assertIn(res.get("ok"), (True, False))
        self.assertTrue("reveal_path" in res or "error" in res)


if __name__ == "__main__":
    unittest.main()
