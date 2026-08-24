"""哈希爆破适配器：MD5/SHA1/SHA256 弱密码字典爆破（crypto/misc 通用）。

纯 Python 实现（无外部依赖），沙盒内运行：
- 支持 md5/sha1/sha224/sha256/sha384/sha512
- 内置常见弱密码字典（6 位数字/常见口令），可传自定义字典
- 输出过滤：只返回命中结果，不返回全量尝试日志
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Optional

from tools.base import ToolAdapter, ToolOutput

# 内置常见弱密码（精简版）
BUILTIN_WORDS = [
    "123456", "12345678", "123456789", "password", "qwerty", "admin",
    "admin123", "root", "toor", "letmein", "welcome", "monkey",
    "abc123", "111111", "000000", "654321", "123123", "666666",
    "888888", "password1", "passw0rd", "P@ssw0rd", "secret", "test",
    "test123", "password123", "iloveyou", "dragon", "sunshine", "princess", "football",
]


class HashCrackAdapter(ToolAdapter):
    """哈希爆破适配器（弱密码字典）。"""

    name = "hash_crack"
    categories = ["crypto", "misc"]

    async def run(self, params: dict) -> ToolOutput:
        target = str(params.get("target") or params.get("hash") or "").strip().lower()
        algorithm = str(params.get("algorithm") or "md5").lower().replace("-", "")
        words = params.get("words") or BUILTIN_WORDS
        # R3 止损线（2026-08-22 整改）：暴力必须有界——默认预算 20 万条，
        # 超限直接失败并提示缩小空间（弱口令空间、已知信息优先）。
        max_words = int(params.get("max_words") or 200000)
        if len(words) > max_words:
            return ToolOutput(
                text=f"字典 {len(words)} 条超过预算上限 {max_words}（R3 止损），"
                     "请用题目信息缩小空间（长度/字符集/常见口令）",
                ok=False,
            )

        if not target:
            return ToolOutput(text="未提供目标哈希", ok=False)
        if algorithm not in hashlib.algorithms_available:
            return ToolOutput(text=f"不支持的哈希算法: {algorithm}", ok=False)

        # 自动识别算法（若未显式指定）：按长度猜测
        if not params.get("algorithm"):
            algorithm = self._guess_algo(target)

        # R4 信息优先于暴力（2026-08-22 整改）：哈希题最常见明文空间是纯数字
        # （6/8 位）。字典前先试有界数字空间——哈希长度已知=已知信息，比盲字典命中率高。
        found = self._crack(target, algorithm, words, max_words)
        if found:
            return ToolOutput(
                text=f"爆破成功: {target} ({algorithm}) = {found}",
                ok=True,
            )
        # 数字空间补充尝试（有界：默认 10^6，可经 max_digits 调整）
        max_digits = int(params.get("max_digits") or 6)
        if max_digits > 8:
            max_digits = 8
        if params.get("try_digits", True) is not False and max_digits >= 1:
            # 2026-08-22 质检修复：CPU 密集爆破放线程池，不阻塞事件循环
            # （并发池中同步跑 10^6 次 hashlib 会卡住其他题目轮询）。
            found = await asyncio.to_thread(
                self._crack_digits, target, algorithm, max_digits)
            if found:
                return ToolOutput(
                    text=f"爆破成功(数字空间): {target} ({algorithm}) = {found}",
                    ok=True,
                )
        return ToolOutput(
            text=f"爆破失败: {target} ({algorithm}) 未在字典/数字空间命中"
                 f"（字典 {min(len(words), max_words)} 条 + 数字≤{max_digits}位）",
            ok=False,
        )

    @staticmethod
    def _crack_digits(target: str, algorithm: str, max_digits: int) -> Optional[str]:
        """有界纯数字空间爆破（R4：已知信息=哈希长度→优先试数字口令）。

        2026-08-22 质检修复：每个候选同时试「变长 str(i)」与「定长 zfill」
        ——否则 000123 这类带前导零的口令永远漏试（历史 bug 复发）。
        """
        import hashlib as _hl

        hf = getattr(_hl, algorithm)
        limit = 10 ** max_digits
        # 预算保护：数字空间超过 1000 万条则放弃（避免无界）
        if limit > 10_000_000:
            return None
        for i in range(limit):
            w = str(i)
            if hf(w.encode()).hexdigest() == target:
                return w
            # 前导零变体：000123 与 123 都试（定长补零）
            z = w.zfill(max_digits)
            if z != w and hf(z.encode()).hexdigest() == target:
                return z
        return None

    @staticmethod
    def _crack(target: str, algorithm: str, words, max_words: int) -> Optional[str]:
        """字典爆破（有界）。"""
        import hashlib as _hl

        hf = getattr(_hl, algorithm)
        for idx, w in enumerate(words):
            if idx >= max_words:
                return None
            if hf(str(w).encode()).hexdigest() == target:
                return str(w)
        return None

    @staticmethod
    def _guess_algo(target: str) -> str:
        """按哈希长度猜测算法。"""
        length = len(target)
        if length == 32:
            return "md5"
        if length == 40:
            return "sha1"
        if length == 64:
            return "sha256"
        if length == 128:
            return "sha512"
        return "md5"
