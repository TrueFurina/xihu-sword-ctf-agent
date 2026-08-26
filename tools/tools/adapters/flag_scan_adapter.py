"""flag_scan 确定性扫描适配器：扫附件目录全部文件（含源码注释/HTML alert/字符串），
直接提取 flag{...} 明文。

背景（2026-08-21 攻坚）：reverse_js/web2 类题的 flag 明文写在 index.html 注释 /
HTML alert / 源码注释里，模型不读注释就幻觉输出（实测 2 题均 hallucination 被拦截）。
本工具确定性 grep 全部附件，命中即出，杜绝幻觉。

用法：
    registry.run("flag_scan", {"attachments": [path1, path2]})
    registry.run("flag_scan", {"path": "目录或文件"})
"""

from __future__ import annotations

import logging
import os
import re

from tools.base import ToolAdapter, ToolOutput

logger = logging.getLogger(__name__)

FLAG_PATTERNS = [
    re.compile(r"flag\{[^}\s]{3,}\}", re.IGNORECASE),
    re.compile(r"DASCTF\{[^}\s]{3,}\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}\s]{3,}\}", re.IGNORECASE),
]

# 二进制/不可读文件跳过（grep 文本即可）
_TEXT_EXTS = {".txt", ".md", ".html", ".htm", ".php", ".js", ".py", ".c", ".cpp",
              ".java", ".json", ".xml", ".yml", ".yaml", ".conf", ".ini", ".log",
              ".css", ".ts", ".go", ".rb", ".sh", ".bat", ".csv"}


class FlagScanAdapter(ToolAdapter):
    """确定性 flag 扫描：扫附件目录全部文本文件，命中 flag 模式即返回。"""

    name = "flag_scan"
    categories = ["web", "reverse", "misc", "crypto"]

    def __init__(self, sandbox=None) -> None:
        super().__init__(sandbox=sandbox)

    @property
    def description(self) -> str:
        return (
            "确定性 flag 扫描：传附件路径（文件或目录），递归读取全部文本文件"
            "（含源码注释/HTML alert/JS），直接提取 flag{...} 明文——源码审计/注释泄露类题先用它"
        )

    def _scan_text(self, text: str, source: str, hits: list) -> None:
        for pat in FLAG_PATTERNS:
            for m in pat.finditer(text):
                raw = m.group(0)
                # UPX 反 strings 混淆：flag 中间插入 \x91\xe6\xff\xff 等非打印字节
                # （helloupx11 实测），清理后才是真 flag——cleaned 放前面优先被采纳
                cleaned = re.sub(r"[^\x20-\x7e]", "", raw)
                if cleaned != raw:
                    hits.append(f"{source}(cleaned): {cleaned}")
                hits.append(f"{source}: {raw}")

    async def run(self, params: dict) -> ToolOutput:
        paths = params.get("attachments") or params.get("paths") or params.get("path") or []
        if isinstance(paths, str):
            paths = [paths]
        hits: list = []
        seen: set = set()
        for p in paths:
            if not p or not os.path.exists(str(p)):
                continue
            p = str(p)
            files = []
            if os.path.isdir(p):
                for root, _dirs, fnames in os.walk(p):
                    if any(s in root for s in ("node_modules", ".git", "__pycache__", ".venv")):
                        continue
                    for fn in fnames:
                        files.append(os.path.join(root, fn))
            else:
                files = [p]
                # 2026-08-21 攻坚：附件是单文件时，把同目录兄弟文件也纳入扫描
                # （reverse_js 附件只有 coso.js，真 flag 在兄弟 index.html 注释里）
                _parent = os.path.dirname(p)
                try:
                    for fn in sorted(os.listdir(_parent)):
                        _fp = os.path.join(_parent, fn)
                        if os.path.isfile(_fp) and _fp != p:
                            files.append(_fp)
                except OSError:
                    pass
            for f in files:
                if f in seen:
                    continue
                seen.add(f)
                ext = os.path.splitext(f)[1].lower()
                try:
                    if os.path.getsize(f) > 2 * 1024 * 1024:
                        continue
                    data = open(f, "rb").read()
                except OSError:
                    continue
                # 二进制里也可能藏明文 flag（strings 效果）
                for enc in ("utf-8", "latin-1"):
                    try:
                        text = data.decode(enc)
                        break
                    except (UnicodeDecodeError, ValueError):
                        continue
                else:
                    text = data.decode("latin-1", errors="ignore")
                self._scan_text(text, os.path.basename(f), hits)
                if len(hits) >= 10:
                    break
            if len(hits) >= 10:
                break

        if hits:
            uniq = list(dict.fromkeys(hits))
            return ToolOutput(text="扫描到 flag:\n" + "\n".join(uniq[:8]), raw="\n".join(uniq), ok=True)
        return ToolOutput(text="附件中未直接发现明文 flag（可尝试 file/strings/反汇编深挖）", ok=False)
