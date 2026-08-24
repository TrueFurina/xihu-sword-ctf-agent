"""crypto_auto 确定性嗅探适配器：把 crypto_toolkit 的确定性 RSA 攻击链变成可调用工具。

背景（2026-08-21 攻坚）：实测 agent 对 RSA 变种题（已知 phi / Hastad 广播 / 共模 / 费马 /
Wiener / small_e）能识别方向（监督 AI 确认"方向正确"）但写不出攻击脚本 → stuck_loop
空转 130-374s（exciting_inverse/ezrsa 实测）。而 crypto_toolkit.build_fallback_script 早已
内置全套确定性嗅探+攻击（裸数字行嗅探 phi_known_inv / Hastad e=3..99 爆破 / 参数行嗅探 /
哈希爆破 / 多层编码），命中即出 flag。

方案：注册为工具 crypto_auto，模型或兜底逻辑传附件路径 → 沙盒执行确定性脚本 → 提取 flag。
让"确定性解出"成为模型的一键选择，而不是赌它现场写代码。

用法：
    registry.run("crypto_auto", {"attachments": [path1, path2]})
"""

from __future__ import annotations

import logging
import os
import re

from tools.base import ToolAdapter, ToolOutput

logger = logging.getLogger(__name__)

FLAG_LINE_RE = re.compile(r"flag\{[^}\s]{3,}\}", re.IGNORECASE)


class CryptoAutoAdapter(ToolAdapter):
    """确定性 crypto 嗅探/攻击（RSA 全套 + 哈希 + 多层编码），一键直出。"""

    name = "crypto_auto"
    categories = ["crypto", "misc"]

    def __init__(self, sandbox=None) -> None:
        super().__init__(sandbox=sandbox)

    @property
    def description(self) -> str:
        return (
            "确定性 crypto 一键嗅探/攻击：传附件路径列表，自动嗅探 RSA 参数并执行 "
            "phi_known/Hastad广播(爆破e)/共模/费马/Wiener/small_e 攻击 + 哈希爆破 + "
            "多层编码解码，命中即返回 flag（无需手写攻击脚本）"
        )

    async def run(self, params: dict) -> ToolOutput:
        from agents.crypto_toolkit import CryptoToolkit

        paths = params.get("attachments") or params.get("paths") or params.get("path") or []
        if isinstance(paths, str):
            paths = [paths]
        paths = [p for p in paths if p and os.path.exists(str(p))]
        if not paths:
            return ToolOutput(text="未提供有效附件路径（参数 attachments 传文件路径列表）", ok=False)
        if self.sandbox is None:
            return ToolOutput(text="沙盒未配置，无法执行确定性脚本", ok=False)

        code = CryptoToolkit.build_fallback_script(str(paths[0]), [str(p) for p in paths[1:]])
        if not code:
            return ToolOutput(text="无法构建确定性嗅探脚本", ok=False)

        result = await self.sandbox.run(f"python: {code}")
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        # 命中 flag 的行（[label] flag{...}）
        flag_lines = [ln.strip() for ln in stdout.splitlines() if FLAG_LINE_RE.search(ln)]
        if result.timed_out:
            return ToolOutput(text=f"[确定性嗅探超时] {self._first_lines(stdout, 5)}", ok=False)
        if flag_lines:
            return ToolOutput(text="\n".join(flag_lines[:5]), raw=stdout, ok=True)
        if result.exit_code != 0:
            return ToolOutput(
                text=f"[确定性嗅探执行失败 exit={result.exit_code}] {self._first_lines(stderr, 5)}",
                ok=False,
            )
        # 未命中：若附件含真加密 zip，明确提示走 bkcrack（先验假设补全——2026-08-22 整改 R2）
        hint = self._zip_encryption_hint(paths)
        return ToolOutput(
            text=f"确定性嗅探未命中 flag（stdout 摘要）:\n{self._first_lines(stdout, 10)}" + hint,
            raw=stdout,
            ok=False,
        )

    @staticmethod
    def _zip_encryption_hint(paths: list) -> str:
        """附件含真加密 zip 时给出 bkcrack 路由提示；非 zip/伪加密返回空。"""
        try:
            import zipfile
        except Exception:  # noqa: BLE001
            return ""
        real_enc = []
        for p in paths or []:
            try:
                if not zipfile.is_zipfile(p):
                    continue
                with zipfile.ZipFile(p) as z:
                    for info in z.infolist():
                        # 加密位 bit0=1；伪加密常见 bit0=1 但本地/中央不一致，
                        # 这里仅提示存在加密条目，由模型/后续 skill 判定真伪。
                        if info.flag_bits & 0x1:
                            real_enc.append(info.filename)
            except Exception:  # noqa: BLE001
                continue
        if not real_enc:
            return ""
        sample = ", ".join(real_enc[:3])
        return (
            f"\n⚠️ 附件含加密 zip 条目({sample})：真加密请用 bkcrack 工具做已知明文攻击"
            "（工具已注册：mode=attack，需提供同 zip 内可复现明文或已知压缩字节），"
            "伪加密用 misc_zip_fake_encryption，禁止手写 Z3 建模替代。"
        )
