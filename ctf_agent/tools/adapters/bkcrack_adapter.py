"""bkcrack 已知明文攻击适配器（zip 加密破解——2026-08-22 事故整改 R1 落地）。

事故复盘（xuanhun_ezip）：会话绕开现成工具手搓 200 行 Z3 已知明文建模，
又陷 bkcrack 版本坑（1.7/1.8 在此环境段错误），最后无方向盲爆。
整改：bkcrack 封装为 ToolAdapter，LLM 一行调用即可：
    {"tool": "bkcrack", "mode": "attack", "enc_zip": "...", "cipher_entry": "Readme.txt",
     "plain_zip": "...", "plain_entry": "Readme.txt"}     # 已知明文攻击 → 输出 Keys
    {"tool": "bkcrack", "mode": "decrypt", "enc_zip": "...", "cipher_entry": "...",
     "keys": "k0 k1 k2", "out": "..."}                     # 密钥解密
    {"tool": "bkcrack", "mode": "recover", "enc_zip": "...", "cipher_entry": "...",
     "keys": "k0 k1 k2", "min": 4, "max": 8, "charset": "?d"}  # 密码反推

版本坑提示（本机实测 2026-08-22）：
- bkcrack 1.6.1 win64 可正常攻击；1.7.1 / 1.8.1 在此 Windows 环境 Z-reduction 段错误。
- 已知明文攻击建议用 -P/-p 传入明文 zip（bkcrack 自动取压缩后字节），
  直接 -p 传压缩字节文件也行，但 offset 需正确（-o 12 跳过加密头，视条目而定）。
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
from typing import Optional

from tools.base import ToolAdapter, ToolOutput

# 常见 bkcrack 位置（本机 / 决赛机）
_BKCRACK_CANDIDATES = [
    os.environ.get("BKCRACK", ""),
    shutil.which("bkcrack") or "",
    # 纯 ASCII 路径（2026-08-22 质检修复：项目路径含中文「西湖论剑」，
    # Windows cmd 按 GBK 解析导致 exe 执行失败——bkcrack 必须放纯 ASCII 目录）
    "C:/Users/Lenovo/bkcrack_161/bkcrack.exe",
    "/tmp/bkcrack/bkcrack-1.6.1-win64/bkcrack.exe",
    "C:/Users/Lenovo/AppData/Local/Temp/bkcrack/bkcrack-1.6.1-win64/bkcrack.exe",
    "/usr/local/bin/bkcrack",
    "/usr/bin/bkcrack",
]


def _find_bkcrack() -> Optional[str]:
    for p in _BKCRACK_CANDIDATES:
        if p and os.path.isfile(p):
            return p
    return None


def _sanitize_path(v: str) -> str:
    """路径净化：只允许文件路径字符，防注入。"""
    v = (v or "").strip()
    if not v:
        return ""
    if all(c.isalnum() or c in "./_\\- " for c in v):
        return v
    return ""


def _sanitize_keys(v: str) -> str:
    """密钥净化：三个 8 位十六进制数。"""
    v = (v or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]{8}( [0-9a-fA-F]{8}){2}", v):
        return v.lower()
    return ""


def _sanitize_charset(v: str) -> str:
    """bkcrack -r 字符集净化：只允许 ?d/?a/?l/?u/?p/?s 掩码或纯字母数字集合。

    2026-08-22 质检修复：原实现直接拼入命令字符串——charset 是唯一未净化
    的用户输入，虽有沙盒 cmd 拦截兜底，但适配器层必须防御纵深。
    """
    v = (v or "").strip()
    if not v:
        return ""
    if re.fullmatch(r"\?[adlups]", v):
        return v  # 掩码形式：?d ?a ?l ?u ?p ?s
    if re.fullmatch(r"[A-Za-z0-9]+", v):
        return v  # 自定义纯字母数字字符集
    return ""


def _q(v: str) -> str:
    """仅当 token 含空格/特殊字符时才加引号。

    ⚠️ 2026-08-22 质检修复：sandbox 在 Windows 走 `cmd.exe /c`，
    对开头带引号的命令会剥离首尾引号（cmd /c 的著名坑），导致
    `"C:/path/bkcrack.exe"` 被解析成非法命令名。纯 ASCII 无空格路径
    直接裸传即可；含空格/特殊字符的才加引号。
    """
    v = (v or "").strip()
    if not v:
        return '""'
    if any(c in v for c in ' "&|<>^%'):
        return f'"{v}"'
    return v


class BkcrackAdapter(ToolAdapter):
    """bkcrack 已知明文攻击 / 密钥解密 / 密码反推适配器。"""

    name = "bkcrack"
    categories = ["misc", "crypto"]

    def __init__(self, sandbox=None) -> None:
        super().__init__(sandbox=sandbox)
        self._bin = _find_bkcrack()

    async def run(self, params: dict) -> ToolOutput:
        if self.sandbox is None:
            return ToolOutput(text="沙盒未配置，无法执行 bkcrack", ok=False)
        if not self._bin:
            return ToolOutput(
                text="未找到 bkcrack 二进制。安装：从 github.com/kimci86/bkcrack releases 下载 "
                     "win64 zip（推荐 v1.6.1，本机 1.7/1.8 段错误），解压后设置环境变量 BKCRACK 指向 exe。",
                ok=False,
            )
        if not os.path.isfile(self._bin):
            self._bin = _find_bkcrack()
            if not self._bin:
                return ToolOutput(text="bkcrack 路径失效，请设置 BKCRACK 环境变量", ok=False)

        mode = str(params.get("mode") or "attack").strip()
        if mode == "attack":
            return await self._attack(params)
        if mode == "decrypt":
            return await self._decrypt(params)
        if mode == "recover":
            return await self._recover(params)
        return ToolOutput(text=f"未知 bkcrack 模式: {mode}（支持 attack/decrypt/recover）", ok=False)

    # ── 已知明文攻击 ────────────────────────────────
    async def _attack(self, params: dict) -> ToolOutput:
        enc_zip = _sanitize_path(params.get("enc_zip") or params.get("zip"))
        cipher = _sanitize_path(params.get("cipher_entry") or params.get("cipher"))
        plain_zip = _sanitize_path(params.get("plain_zip"))
        plain = _sanitize_path(params.get("plain_entry") or params.get("plain"))

        if not enc_zip or not cipher or not os.path.isfile(enc_zip):
            return ToolOutput(text="已知明文攻击需要 enc_zip(存在的zip) + cipher_entry", ok=False)

        cmd = f'{_q(self._bin)} -C {_q(enc_zip)} -c {_q(cipher)}'
        if plain_zip and plain:
            if not os.path.isfile(plain_zip):
                return ToolOutput(text=f"plain_zip 不存在: {plain_zip}", ok=False)
            cmd += f' -P {_q(plain_zip)} -p {_q(plain)}'
        else:
            # 直接给明文文件（压缩后字节）
            plain_file = _sanitize_path(params.get("plain_file"))
            if plain_file:
                cmd += f' -p {_q(plain_file)}'
            else:
                return ToolOutput(text="已知明文攻击需要 plain_zip+plain_entry 或 plain_file", ok=False)

        return await self._run_cmd(cmd)

    # ── 密钥解密 ────────────────────────────────────
    async def _decrypt(self, params: dict) -> ToolOutput:
        enc_zip = _sanitize_path(params.get("enc_zip") or params.get("zip"))
        cipher = _sanitize_path(params.get("cipher_entry") or params.get("cipher"))
        keys = _sanitize_keys(params.get("keys"))
        out = _sanitize_path(params.get("out"))

        if not enc_zip or not cipher or not keys or not os.path.isfile(enc_zip):
            return ToolOutput(text="密钥解密需要 enc_zip + cipher_entry + keys(k0 k1 k2)", ok=False)
        if not out:
            out = os.path.join(os.path.dirname(enc_zip), f"_{os.path.basename(cipher)}_dec.bin")
        cmd = f'{_q(self._bin)} -C {_q(enc_zip)} -c {_q(cipher)} -k {keys} -d {_q(out)}'
        result = await self._run_cmd(cmd)
        if result.ok:
            return ToolOutput(
                text=f"{result.text}\n[解密输出] {out}（可能为压缩数据，需按条目压缩方式解压）",
                raw=result.raw, ok=True,
            )
        return result

    # ── 密码反推（已知密钥 → 找回密码） ──────────────
    async def _recover(self, params: dict) -> ToolOutput:
        enc_zip = _sanitize_path(params.get("enc_zip") or params.get("zip"))
        cipher = _sanitize_path(params.get("cipher_entry") or params.get("cipher"))
        keys = _sanitize_keys(params.get("keys"))
        charset = _sanitize_charset(params.get("charset") or "?d")
        try:
            lo = int(params.get("min") or 4)
            hi = int(params.get("max") or 8)
        except (TypeError, ValueError):
            return ToolOutput(text="min/max 需为整数", ok=False)

        if not enc_zip or not cipher or not keys:
            return ToolOutput(text="密码反推需要 enc_zip + cipher_entry + keys", ok=False)
        if not charset:
            return ToolOutput(text="charset 仅支持 ?d/?a/?l/?u/?p/?s 掩码或纯字母数字集合", ok=False)
        if not (0 <= lo <= hi <= 12):
            return ToolOutput(text="min/max 需满足 0 <= min <= max <= 12", ok=False)
        # 1.6.1 语法：-r <min>..<max> <charset>
        cmd = f'{_q(self._bin)} -C {_q(enc_zip)} -c {_q(cipher)} -k {keys} -r {lo}..{hi} {charset}'
        return await self._run_cmd(cmd)

    # ── 统一执行 ────────────────────────────────────
    async def _run_cmd(self, cmd: str, timeout: int | None = None) -> ToolOutput:
        try:
            result = await self.sandbox.run(cmd, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return ToolOutput(text=f"bkcrack 执行异常: {exc}", ok=False)
        if result.timed_out:
            return ToolOutput(text=f"[超时] bkcrack 超过 {self.sandbox.default_timeout}s（可设 max 预算后重试）", ok=False)
        out = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        if result.exit_code != 0:
            hint = self._first_lines(result.stderr or "未知错误", 6)
            return ToolOutput(text=f"[bkcrack失败 exit={result.exit_code}]\n{hint}", ok=False)
        # 提取 Keys 行（攻击成功标志）
        keys = re.findall(r"[0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8}", out)
        text = self._first_lines(out, 12)
        if keys:
            text = f"Keys: {keys[-1]}\n{text}"
        return ToolOutput(text=text, raw=out, ok=True)
