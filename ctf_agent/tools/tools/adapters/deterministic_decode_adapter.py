"""确定性解码 fallback 适配器：LLM 失败后自动尝试多策略解码链提取 flag。

Postmortem #3 修复：LLM 对附件类题目（DNS隧道/摩斯/RAID0/多层编码）的确定性解码
能力不足，容易陷入 stuck_loop（循环 60-96s 后超时）。

策略：MainAgent 检测到 stuck_loop 或连续失败后，调用本适配器自动尝试：

1. 直接 flag 搜索（原始文本/bytes）
2. Base64/Base32/Base16 多层嵌套解码
3. Hex → ASCII
4. ROT13 / Atbash / 凯撒位移 1-25
5. 摩斯密码
6. URL decode
7. Unicode escape 解码
8. ZIP 文件名链（复用 skills/zip_chain_decode）
9. DNS 隧道数据提取
10. RAID0 多磁盘拼接

用法：
    registry.run("deterministic_decode", {"text": "编码内容"})
    registry.run("deterministic_decode", {"path": "附件路径"})
    registry.run("deterministic_decode", {"text": "...", "strategy": "morse"})
"""

from __future__ import annotations

import base64
import binascii
import codecs
import logging
import os
import re
import string
import urllib.parse
from typing import Any, Callable, Optional

from tools.base import ToolAdapter, ToolOutput

logger = logging.getLogger(__name__)

FLAG_PATTERNS = [
    re.compile(r"flag\{[^}\s]{4,}\}", re.IGNORECASE),
    re.compile(r"DASCTF\{[^}\s]{4,}\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}\s]{4,}\}", re.IGNORECASE),
]

MORSE_TABLE = {
    '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
    '..-.': 'f', '--.': 'g', '....': 'h', '..': 'i', '.---': 'j',
    '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n', '---': 'o',
    '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't',
    '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y',
    '--..': 'z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9',
}


class DeterministicDecodeAdapter(ToolAdapter):
    """确定性解码 fallback：多策略链式尝试，LLM 失败时的最后防线。"""

    def __init__(self) -> None:
        super().__init__()

    @property
    def name(self) -> str:
        return "deterministic_decode"

    @property
    def description(self) -> str:
        return "确定性解码 fallback（base64/hex/morse/ROT13/zip链/DNS隧道/RAID0）"

    @property
    def categories(self) -> list:
        return ["crypto", "misc", "reverse", "web"]

    def can_handle(self, category: str) -> bool:
        return category in ("crypto", "misc", "reverse", "web", "")

    async def run(self, params: dict) -> ToolOutput:
        """执行确定性解码链。

        Args:
            params: {
                "text": "待解码文本（可选）",
                "path": "附件文件路径（可选）",
                "strategy": "指定策略名（可选，默认 auto 全部尝试）",
            }

        Returns:
            ToolOutput: ok=True 时 text 含提取到的 flag
        """
        text = str(params.get("text", "")).strip()
        path = str(params.get("path", "") or params.get("file_path", "")).strip()
        strategy = str(params.get("strategy", "auto")).strip()

        # 从文件读取
        raw_hex = ""
        if path and os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    raw_bytes = f.read()
                for enc in ("utf-8", "latin-1", "ascii"):
                    try:
                        text = text or raw_bytes.decode(enc).strip()
                        break
                    except (UnicodeDecodeError, ValueError):
                        continue
                raw_hex = raw_bytes.hex()
            except Exception as exc:
                logger.warning("[deterministic_decode] 文件读取失败: %s", exc)

        if not text and not raw_hex:
            return ToolOutput(text="无输入数据（需提供 text 或 path）", ok=False)

        # ── 策略列表（按优先级排序）──
        all_strategies: list[tuple[str, Callable]] = [
            ("direct_search", lambda t, p, h: self._strategy_direct(t, h)),
            ("base64_chain", lambda t, p, h: self._strategy_base64(t)),
            ("hex_decode", lambda t, p, h: self._strategy_hex(t, h)),
            ("rot13_atbash_caesar", lambda t, p, h: self._strategy_rot13_caesar(t)),
            ("morse", lambda t, p, h: self._strategy_morse(t)),
            ("url_decode", lambda t, p, h: self._strategy_url(t)),
            ("unicode_escape", lambda t, p, h: self._strategy_unicode(t)),
            ("zip_chain", lambda t, p, h: self._strategy_zip(p)),
            ("dns_tunnel", lambda t, p, h: self._strategy_dns(t)),
            ("raid0", lambda t, p, h: self._strategy_raid0(t)),
        ]

        if strategy != "auto":
            all_strategies = [(n, fn) for n, fn in all_strategies if n == strategy]
            if not all_strategies:
                all_strategies = [(strategy, lambda t, p, h: None)]

        evidence = []
        for strat_name, strat_fn in all_strategies:
            try:
                result = strat_fn(text, path, raw_hex)
                if result:
                    flag = self._search_flag(result)
                    if flag:
                        logger.info("[deterministic_decode] %s 提取到 flag: %s", strat_name, flag[:60])
                        return ToolOutput(
                            text=f"解码成功 (策略={strat_name})\nflag: {flag}\n证据: {result[:200]}",
                            ok=True,
                        )
                    if result != text:
                        evidence.append(f"[{strat_name}] {result[:100]}")
            except Exception as exc:
                evidence.append(f"[{strat_name}] 异常: {str(exc)[:80]}")

        if evidence:
            summary = "\n".join(evidence[:5])
            return ToolOutput(text=f"未直接提取到 flag，但找到解码结果:\n{summary}", ok=False)

        return ToolOutput(text="所有解码策略均未产生有效结果", ok=False)

    # ── flag 搜索 ──────────────────────────────────────

    def _search_flag(self, text: str) -> str:
        """在文本中搜索 flag pattern。"""
        for pat in FLAG_PATTERNS:
            m = pat.search(text)
            if m:
                return m.group(0)
        return ""

    # ── 策略实现 ────────────────────────────────────────

    def _strategy_direct(self, text: str, raw_hex: str) -> str:
        """策略 1：直接在原始文本/hex 中搜索 flag。"""
        for source in [text, raw_hex]:
            if not source:
                continue
            flag = self._search_flag(source)
            if flag:
                return flag
        return ""

    def _strategy_base64(self, text: str) -> str:
        """策略 2：Base64/Base32/Base16 多层嵌套解码。"""
        if not text:
            return ""
        current = text.strip()
        for _ in range(20):
            decoded = self._try_base_decode(current)
            if decoded is None or decoded == current:
                break
            current = decoded
            if self._search_flag(current):
                return current
        return current if current != text else ""

    def _try_base_decode(self, text: str) -> Optional[str]:
        """尝试 Base64 → Base32 → Base16 逐个解码。"""
        text = text.strip()
        if not text:
            return None
        # Base64
        try:
            padded = text + "=" * ((4 - len(text) % 4) % 4) if len(text) % 4 else text
            result = base64.b64decode(padded).decode("utf-8", errors="replace")
            if result and all(c.isprintable() or c in "\n\r\t" for c in result):
                return result
        except Exception:
            pass
        # Base32
        try:
            padded = text + "=" * ((8 - len(text) % 8) % 8) if len(text) % 8 else text
            result = base64.b32decode(padded.upper()).decode("utf-8", errors="replace")
            if result and all(c.isprintable() or c in "\n\r\t" for c in result):
                return result
        except Exception:
            pass
        # Base16 (hex)
        try:
            if all(c in "0123456789abcdefABCDEF" for c in text) and len(text) % 2 == 0:
                result = bytes.fromhex(text).decode("utf-8", errors="replace")
                if result and all(c.isprintable() or c in "\n\r\t" for c in result):
                    return result
        except Exception:
            pass
        return None

    def _strategy_hex(self, text: str, raw_hex: str) -> str:
        """策略 3：Hex → ASCII 解码。"""
        for source in [text, raw_hex]:
            if not source:
                continue
            clean = re.sub(r'[\s\n\r\t]', '', source)
            if len(clean) >= 4 and len(clean) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in clean):
                try:
                    result = bytes.fromhex(clean).decode("utf-8", errors="replace")
                    if result and any(c.isprintable() for c in result):
                        return result
                except (ValueError, binascii.Error):
                    pass
        return ""

    def _strategy_rot13_caesar(self, text: str) -> str:
        """策略 4：ROT13 / Atbash / 凯撒位移 1-25。"""
        if not text:
            return ""
        # ROT13
        try:
            decoded = codecs.decode(text, "rot_13")
            if self._search_flag(decoded):
                return decoded
        except Exception:
            pass
        # Atbash (a↔z, b↔y, ...)
        atbash_map = str.maketrans(
            string.ascii_lowercase + string.ascii_uppercase,
            string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1],
        )
        decoded = text.translate(atbash_map)
        if self._search_flag(decoded):
            return decoded
        # 凯撒位移 1-25
        for shift in range(1, 26):
            decoded = self._caesar_shift(text, shift)
            if self._search_flag(decoded):
                return decoded
        return ""

    def _caesar_shift(self, text: str, shift: int) -> str:
        """凯撒位移。"""
        result = []
        for c in text:
            if c.isalpha():
                base = ord("a") if c.islower() else ord("A")
                result.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                result.append(c)
        return "".join(result)

    def _strategy_morse(self, text: str) -> str:
        """策略 5：摩斯密码解码。"""
        if not text or not re.search(r'[.\-]{1,5}(?:[ /][.\-]{1,5})+', text):
            return ""
        m = re.search(r'[.\-]{1,5}(?:[ /][.\-]{1,5})*', text)
        code = m.group(0) if m else text
        result = []
        for token in code.replace('/', ' ').split():
            if token in MORSE_TABLE:
                result.append(MORSE_TABLE[token])
            else:
                result.append('?')
        return ''.join(result)

    def _strategy_url(self, text: str) -> str:
        """策略 6：URL decode。"""
        if not text or "%" not in text:
            return ""
        try:
            decoded = urllib.parse.unquote(text)
            return decoded if decoded != text else ""
        except Exception:
            return ""

    def _strategy_unicode(self, text: str) -> str:
        """策略 7：Unicode escape 解码。"""
        if not text or ("\\u" not in text and "\\x" not in text):
            return ""
        try:
            decoded = text.encode("utf-8").decode("unicode_escape")
            return decoded if decoded != text else ""
        except Exception:
            return ""

    def _strategy_zip(self, path: str) -> str:
        """策略 8：ZIP 文件名链解码（复用 skills/zip_chain_decode）。"""
        if not path or not path.endswith(".zip") or not os.path.exists(path):
            return ""
        try:
            from skills.zip_chain_decode import run as zip_run
            result = zip_run({"path": path})
            if isinstance(result, dict):
                flag = result.get("flag", "")
                if flag:
                    return str(flag)
                return str(result.get("output", ""))
            return str(result) if result else ""
        except Exception:
            return ""

    def _strategy_dns(self, text: str) -> str:
        """策略 9：DNS 隧道数据提取（从 DNS 查询日志中提取 hex 子域名）。"""
        if not text:
            return ""
        # 常见格式：xxxx.example.com 或 xxxx.txt
        chunks = re.findall(r'([a-f0-9]{2,})\.(?:txt|example\.com|ctf\.local)', text, re.I)
        if not chunks:
            return ""
        hex_data = "".join(chunks)
        try:
            if len(hex_data) % 2 == 0:
                return bytes.fromhex(hex_data).decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""

    def _strategy_raid0(self, text: str) -> str:
        """策略 10：RAID0 多磁盘拼接（disk1: xxx, disk2: yyy → 交错拼接）。"""
        if not text or not re.search(r'disk\s*\d+:', text, re.I):
            return ""
        disks = {}
        for m in re.finditer(r'disk\s*(\d+):\s*([^\n]+)', text, re.I):
            idx = int(m.group(1))
            disks[idx] = m.group(2).strip()
        if len(disks) < 2:
            return ""
        max_len = max(len(d) for d in disks.values())
        result = []
        for i in range(max_len):
            for idx in sorted(disks.keys()):
                if i < len(disks[idx]):
                    result.append(disks[idx][i])
        return "".join(result)
