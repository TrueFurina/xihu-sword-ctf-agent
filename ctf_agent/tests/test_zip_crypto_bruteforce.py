"""zip_crypto_bruteforce skill 回归测试（2026-10-08）。

背景：xuanhun_ezip L3 攻防中，ZipCrypto 快筛实现曾出现"跳步 bug"——
12 字节头校验未流式消费明文头字节并持续更新 keys，导致大空间爆破
结果全部作废却无人察觉（直到与 zipfile._ZipDecrypter 逐字节对拍
才发现）。本测试用真加密 fixture 锁死正确实现。

fixture：tests/fixtures/zipcrypto_66688.zip（3915B）
  - 由 bkcrack -U 用独立 C 实现生成（非本仓 Python 代码，避免同源
    实现自证循环），密码 66688，两个条目（multzip3.zip + Readme.txt），
    Readme.txt 为 store + data descriptor（flag_bits=0x9）。
  - 覆盖两种校验字节路径：descriptor 条目（DOS time 高字节）与
    本测试直接调用 _local_entry 验证 check 字节推导。

锁死三件事：
① 流式正确实现能从真加密样本找回密码（回归跳步 bug）；
② 候选超上限时 fail-closed（不假装成功、不无限烧时间）；
③ check 字节推导与 flag_bits 分支逻辑正确。
"""

import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKILL_DIR = os.path.join(REPO, "ctf_agent", "skills")
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                       "zipcrypto_66688.zip")

sys.path.insert(0, SKILL_DIR)


def _have_fixture() -> bool:
    return os.path.exists(FIXTURE)


@pytest.fixture(scope="module")
def zcb():
    import zip_crypto_bruteforce as mod
    return mod


@pytest.mark.skipif(not _have_fixture(), reason="fixture 缺失")
class TestZipCryptoBruteforce:
    def test_recovers_known_password(self, zcb):
        """核心回归：真加密样本上找回 66688（跳步 bug 的直接反例）。"""
        result = zcb.run({
            "zip_path": FIXTURE,
            "entry": "Readme.txt",
            "charsets": ["digits"],
            "min_len": 5,
            "max_len": 5,
        })
        assert result["ok"] is True, f"未命中: {result}"
        assert result["password"] == "66688"
        assert result["size"] == 115
        with open(result["out_path"], "rb") as f:
            plain = f.read()
        assert b"zip" in plain  # Readme 明文特征（zip*19 套娃提示）

    def test_miss_is_fail_closed(self, zcb):
        """空间不够时必须显式报未命中，不得伪造成功。"""
        result = zcb.run({
            "zip_path": FIXTURE,
            "entry": "Readme.txt",
            "charsets": ["digits"],
            "min_len": 1,
            "max_len": 3,
        })
        assert result["ok"] is False
        assert "未命中" in result.get("error", "")
        assert result["tried"] == 1110  # 1-3 位数字全空间 10+100+1000

    def test_max_candidates_guard(self, zcb):
        """候选上限护栏：超限立即止损（防死循环烧 token——五宗罪之一）。"""
        result = zcb.run({
            "zip_path": FIXTURE,
            "entry": "Readme.txt",
            "charsets": ["digits"],
            "min_len": 5,
            "max_len": 5,
            "max_candidates": 100,
        })
        assert result["ok"] is False
        assert "超上限" in result.get("error", "")

    def test_check_byte_branches(self, zcb):
        """校验字节分支：descriptor 条目取 DOS time 高字节，非 CRC 高字节。"""
        hdr, body, crc, check, method, usize = zcb._local_entry(FIXTURE, "Readme.txt")
        assert method == 8  # bkcrack -U 保留原条目：deflate
        assert crc == 0xADAC3A81
        assert len(hdr) == 12
        # dt=(2020,5,31,11,0,50) → dos time = 0x5819 → 高字节 0x58 ≠ CRC 高字节 0xad
        assert check == 0x58, f"descriptor 校验字节推导错误: {check:#x}"

    def test_missing_zip_fails_clean(self, zcb):
        result = zcb.run({"zip_path": "Z:/no/such/file.zip"})
        assert result["ok"] is False
        assert "不存在" in result.get("error", "")
