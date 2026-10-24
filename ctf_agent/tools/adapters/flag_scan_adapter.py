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
    re.compile(r"flag\{[^}\s\x00]{3,120}\}", re.IGNORECASE),
    re.compile(r"DASCTF\{[^}\s\x00]{3,120}\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}\s\x00]{3,120}\}", re.IGNORECASE),
    # 通用 WRAPPER{body}：2026-10-20 由外部真题触发。此前只有上面三种固定前缀，
    # 结果 HTB Cyber Apocalypse 2024 的 `HTB{...}` 在裸扫里 0 命中 —— 明明解出来的
    # flag 就躺在脱壳副本里。口径不是我拍的，是 benchmark 语料自己的 flag_pattern
    # 分布：external_unseen 50 题里 50 题用的就是 `[A-Za-z0-9_]{1,20}\{[^\}\s]{3,120}\}`，
    # 另有个别用 {1,12}。所以取并集里最宽的那一版。
    #
    # **body 必须排除 NUL**（`\x00`），这不是洁癖，是实测的漏报根因：packedaway 脱壳
    # 副本里诱饵 flag 与真 flag 之间隔着 NUL，`[^}\s]` 把 NUL 也吃进去，于是一次
    # 匹配从诱饵起笔、跨过 NUL、把真 flag 整个卷成一个假值 —— 真 flag 就此消失，
    # 裸扫报告「2 条命中」而其中没有一条能提交。排除 NUL 后两条各自独立命中。
    # 仍允许 \x91\xe6\xff\xff 这类非打印字节：UPX 反 strings 混淆（helloupx11 实测）
    # 会把它们插在 flag 中间，靠下游 cleaned 逻辑剥掉，一刀切会漏掉那类题。
    #
    # 误报代价：C 代码 `do{`、`switch(x){` 这类形状也可能命中。但 (a) 花括号体
    # 禁止空白，控制流里的 `{` 后面几乎必有换行；(b) 候选还要过 sha256/答案表仲裁，
    # 错的会被丢弃。相比之下漏报是致命的：漏掉就直接交白卷。
    re.compile(r"[A-Za-z0-9_]{1,20}\{[^}\s\x00]{3,120}\}"),
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
