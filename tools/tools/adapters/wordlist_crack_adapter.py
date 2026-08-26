"""字典爆破适配器：压缩包密码/弱口令字典尝试（misc/web 通用）。

纯 Python 实现：
- 对 zip 压缩包尝试字典密码（zipfile 暴力解压）
- 对登录接口尝试弱口令（可选，需网络）
- 输出过滤：只返回命中密码
"""

from __future__ import annotations

from typing import Optional

from tools.base import ToolAdapter, ToolOutput

# 常见压缩包密码字典（精简版）
ZIP_PASSWORDS = [
    "123456", "password", "admin", "root", "1234", "12345", "12345678",
    "qwerty", "abc", "test", "secret", "666666", "888888", "123123",
    "flag", "ctf", "key", "pass", "passwd", "default",
]


class WordlistCrackAdapter(ToolAdapter):
    """字典爆破适配器（zip 密码 / 弱口令）。"""

    name = "wordlist_crack"
    categories = ["misc", "web", "crypto"]

    async def run(self, params: dict) -> ToolOutput:
        target = str(params.get("path") or params.get("zip_path") or "").strip()
        words = params.get("words") or ZIP_PASSWORDS
        mode = str(params.get("mode") or "zip")
        # R3 止损线（2026-08-22 整改）：暴力必须有界——默认预算 10 万条，
        # 超限直接失败并提示缩小空间，禁止无上限字典循环烧墙钟。
        max_words = int(params.get("max_words") or 100000)
        if len(words) > max_words:
            return ToolOutput(
                text=f"字典 {len(words)} 条超过预算上限 {max_words}（R3 止损），"
                     "请用题目信息缩小空间或改用向量化有界爆破（声明预算轮数）",
                ok=False,
            )

        if mode == "zip":
            if not target:
                return ToolOutput(text="未提供 zip 路径", ok=False)
            return self._crack_zip(target, words, max_words)

        return ToolOutput(text=f"不支持的爆破模式: {mode}（当前支持 zip）", ok=False)

    @staticmethod
    def _crack_zip(path: str, words, max_words: int) -> ToolOutput:
        """对 zip 尝试字典密码解压（带轮次预算上限）。

        2026-08-22 质检修复分支逻辑：
        - 用加密位(flag_bits&0x1)判定，替代"zf.read 抛异常试探"——
          旧逻辑首条目加密即 break，后续条目即使免密也读不到；
        - 字典爆破目标取第一个**加密**条目（密码一致原则），不再写死 namelist()[0]；
        - 伪加密已修复(加密位清零)的 zip 走免密路径直接读。
        """
        import zipfile

        if not zipfile.is_zipfile(path):
            return ToolOutput(text=f"不是有效的 zip 文件: {path}", ok=False)

        with zipfile.ZipFile(path) as zf:
            infos = list(zf.infolist())
            if not infos:
                return ToolOutput(text=f"zip 无条目: {path}", ok=False)
            encrypted = [i for i in infos if i.flag_bits & 0x1]

            # 全免密（含伪加密已修复）：直接读第一个文本条目
            if not encrypted:
                for info in infos:
                    try:
                        data = zf.read(info.filename)
                    except (RuntimeError, zipfile.BadZipFile):
                        continue
                    text = data.decode("utf-8", errors="replace")
                    return ToolOutput(
                        text=f"免密解压成功: {info.filename}\n内容: {text[:300]}", ok=True
                    )
                return ToolOutput(text="zip 无加密条目但读取失败", ok=False)

            # 有加密条目：对第一个加密条目做字典爆破
            target = encrypted[0].filename
            for idx, word in enumerate(words):
                if idx >= max_words:
                    return ToolOutput(
                        text=f"字典爆破达预算上限 {max_words} 条未命中（R3 止损），"
                             "请缩小密码空间或换已知明文攻击（bkcrack）",
                        ok=False,
                    )
                try:
                    data = zf.read(target, pwd=word.encode())
                    text = data.decode("utf-8", errors="replace")
                    return ToolOutput(
                        text=f"字典爆破成功: 密码={word}\n内容: {text[:300]}", ok=True
                    )
                except (RuntimeError, zipfile.BadZipFile):
                    continue

        return ToolOutput(
            text=f"字典爆破失败（尝试 {min(len(words), max_words)} 个密码）", ok=False
        )
