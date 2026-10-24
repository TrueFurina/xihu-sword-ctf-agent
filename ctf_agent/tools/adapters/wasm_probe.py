"""WASM 静态分析适配器（WABT 1.0.42）。

为什么单独一个适配器而不是塞进 rea_probe：REA 6.5.0 不支持 wasm，
`rea inspect-artifact *.wasm` 走不到任何引擎。WABT 是**独立工具链**，把它并进
rea_probe 会让「REA 能力边界」和「外部工具能力」混在同一份契约里，
溯源时分不清某个结论到底是谁给的。

工具选型（实测对比，见报告）：
- `wasm2wat` —— 主用。伪 wat 文本里 `i32.const 42` / `i32.eq` 这类比较逻辑
  直接可读，data 段字符串也以明文出现，是 CTF 里性价比最高的一路。
- `wasm-objdump -x` —— 结构摘要（类型/导入/导出/段），用于快速看清程序骨架。
- `wasm2c` —— **不用**。实测 148 字节的样本产出 1000+ 行 C，其中 500 行是
  `I32_TRUNC_U_F32` 之类的模板宏，真正的逻辑淹没在里面，信噪比不可接受。

不做的事：不执行 wasm（`wasm-interp` 需要构造导入环境，属于动态分析，
与本适配器的静态契约不同）；不还原被加密/编码的 data 段。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess

from tools.base import ToolAdapter, ToolOutput
from tools.adapters.rea_probe import _contract, _flags_in, _rawscan

logger = logging.getLogger(__name__)

#: WABT bin 目录（可用 WABT_BIN 覆盖，便于换机器）
_DEFAULT_WABT_BIN = os.environ.get("WABT_BIN", r"E:\Program\tools\wabt-1.0.42\bin")
_TIMEOUT = int(os.environ.get("WASM_TIMEOUT", "60"))
#: wat 正文回给上层的字符上限（超出只报行数，避免把上下文塞爆）
_WAT_SHOW = int(os.environ.get("WASM_WAT_SHOW", "6000"))


def _exe(tool: str) -> str:
    return os.path.join(_DEFAULT_WABT_BIN, tool + (".exe" if os.name == "nt" else ""))


def _wabt_available() -> tuple[bool, str]:
    need = ("wasm2wat", "wasm-objdump")
    missing = [n for n in need if not os.path.isfile(_exe(n))]
    if missing:
        return False, (f"WABT 缺少 {', '.join(missing)}（设 WABT_BIN 指向 bin 目录，"
                       f"当前 {_DEFAULT_WABT_BIN}）")
    return True, ""


def _run(tool: str, *args: str) -> tuple[int, str, str]:
    """跑一个 WABT 工具，返回 (rc, stdout, stderr)。绝不抛异常。"""
    try:
        p = subprocess.run(
            [_exe(tool), *args],
            capture_output=True, timeout=_TIMEOUT,
            encoding="utf-8", errors="replace",
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {_TIMEOUT}s"
    except Exception as exc:  # noqa: BLE001 - 工具层不因外部进程崩
        return 127, "", f"{type(exc).__name__}: {exc}"


def _wat_strings(wat: str) -> tuple[list[str], list[str]]:
    """从 wat 文本里取 (全部字符串常量, data 段字符串)。

    引号内必须禁止跨行。早先的 `[^"\\\\]` 会把换行也吃进去，于是一个 data 段的
    开引号能一路吞到下一个 data 段，切出 `(memory 0))` / `(func 1))` 这种碎片，
    而真正的 `flag{...}` 反而被盖住不显示。这是实测踩到的，不是假想。
    """
    all_strs = re.findall(r'"((?:\\.|[^"\\\n]){4,200})"', wat)
    # wat 的 data 行形如： (data (;0;) (i32.const 16) "flag{...}")
    data_strs = re.findall(r'\(data\b[^\n]*?"((?:\\.|[^"\\\n])*)"', wat)
    return all_strs, [s for s in data_strs if 4 <= len(s) <= 120]


def _is_wasm(data: bytes) -> bool:
    return len(data) >= 8 and data[:4] == b"\x00asm"


def _parse_structure(objdump_text: str) -> dict:
    """从 `wasm-objdump -x` 的文本里抽骨架。只做行级正则，不引第三方解析器。"""
    def count(head: str) -> int:
        m = re.search(rf"^{head}\[(\d+)\]:", objdump_text, re.M)
        return int(m.group(1)) if m else 0

    # objdump 里写的是 `- func[0] sig=0 <env.log> <- env.log`：
    # 尖括号内已经是「模块.名字」的完整标识。
    # 必须保留结尾的 `<-` 作为区分：Function[..] 段的行格式是
    # `- func[1] sig=1 <check>`，没有 `<-`，否则会把内部函数算成导入。
    # 另外单 group 的 findall 返回的是字符串列表，不能再取 [0]。
    imports = re.findall(
        r"^\s*-\s*func\[\d+\]\s+sig=\d+\s+<([^>]+)>\s*<-", objdump_text, re.M)
    exports = re.findall(r'^\s*-\s*(func|memory|global|table)\[\d+\].*?"([^"]+)"',
                         objdump_text, re.M)
    data_segs = re.findall(r"^\s*-\s*segment\[(\d+)\]\s+memory=\d+\s+size=(\d+)", objdump_text, re.M)
    return {
        "types": count("Type"),
        "imports": imports,
        "functions": count("Function"),
        "exports": exports,
        "data_segments": [(int(i), int(s)) for i, s in data_segs],
        "has_memory": "Memory[1]:" in objdump_text or count("Memory") > 0,
    }


class WasmProbeAdapter(ToolAdapter):
    """WASM 静态分析：结构骨架 + wat 反汇编 + data 段字符串 / flag 提取。"""

    name = "wasm_probe"
    categories = ["reverse", "misc"]
    #: plan 可透传参数（主链按此白名单转发，见 core/action_executor.py）
    param_spec = {
        "mode": "auto|info|wat（wat=完整反汇编）",
    }

    def __init__(self, sandbox=None) -> None:
        super().__init__(sandbox=sandbox)

    @property
    def description(self) -> str:
        return (
            "WASM 静态分析（WABT 1.0.42）：结构骨架（类型/导入/导出/数据段）、"
            "wasm2wat 反汇编文本、data 段字符串与 flag 候选，并附带全文件裸扫。"
            "传 path；可选 mode=auto|info|wat（auto 给结构与 wat 摘要，wat 给完整 wat）。"
            "不做动态执行，也不还原加密的 data 段。"
        )

    async def run(self, params: dict) -> ToolOutput:
        path = str(params.get("path") or params.get("file") or "")
        mode = str(params.get("mode") or "auto").lower()
        if path:
            path = os.path.abspath(path)
        if not path or not os.path.isfile(path):
            return ToolOutput(text=f"[wasm_probe] 目标不存在：{path or '(空)'}", ok=False)
        return await asyncio.to_thread(self._run_sync, path, mode)

    def _run_sync(self, path: str, mode: str) -> ToolOutput:
        ok, why = _wabt_available()
        if not ok:
            return ToolOutput(
                text=f"[wasm_probe] WABT 不可用：{why}（not_applicable，勿当作'分析干净'）",
                ok=False,
            )
        try:
            with open(path, "rb") as f:
                head = f.read(16)
        except OSError as exc:
            return ToolOutput(text=f"[wasm_probe] 读取失败：{exc}", ok=False)

        if not _is_wasm(head):
            # 不是 wasm 就别硬解：wasm2wat 对任意字节会报错，但错误信息对用户没价值
            return ToolOutput(
                text=f"[wasm_probe] {os.path.basename(path)} 不是 wasm（魔数应为 \\0asm，"
                     f"实际 {head[:4]!r}）—— 用 rea_probe 或按文件类型另选工具",
                ok=False,
            )

        size = os.path.getsize(path)
        lines: list[str] = [
            f"[wasm_probe] {os.path.basename(path)}  {size:,} B  mode={mode}",
        ]
        limitations: list[str] = []
        status = "complete"
        truncated = False

        # ── 结构骨架 ──────────────────────────────────────
        rc_o, out_o, err_o = _run("wasm-objdump", "-x", path)
        struct: dict = {}
        if rc_o != 0 or not out_o.strip():
            lines.append(f"  结构：objdump 失败（rc={rc_o}）—— {(err_o or out_o)[:160]}")
            limitations.append("结构解析失败，本次只有 wat 与裸扫结果")
            status = "partial"
        else:
            struct = _parse_structure(out_o)
            lines.append(
                f"  类型 {struct['types']} / 函数 {struct['functions']} / "
                f"导入 {len(struct['imports'])} / 导出 {len(struct['exports'])} / "
                f"数据段 {len(struct['data_segments'])}"
                f"{'（含 memory）' if struct['has_memory'] else ''}"
            )
            if struct["imports"]:
                lines.append("  导入：" + " ⋮ ".join(struct["imports"][:8]))
            if struct["exports"]:
                lines.append("  导出：" + " ⋮ ".join(
                    f'{nm}({kind})' for kind, nm in struct["exports"][:10]))
            if struct["data_segments"]:
                tot = sum(s for _, s in struct["data_segments"])
                lines.append(f"  data 段合计 {tot:,} B")

        # ── wat 反汇编 ────────────────────────────────────
        rc_w, out_w, err_w = _run("wasm2wat", path)
        wat = out_w if rc_w == 0 else ""
        if not wat:
            lines.append(f"  wasm2wat 失败（rc={rc_w}）—— {(err_w or out_w)[:160]}")
            limitations.append("wasm2wat 未产出文本，逻辑层不可读")
            status = "partial"
        else:
            wat_lines = wat.count("\n") + 1
            lines.append(f"  wat {len(wat):,} 字符 / {wat_lines} 行")

        # ── flag 候选：wat 文本 + 裸扫（data 段明文两种情况都覆盖）──
        candidates: list[str] = []
        if wat:
            strings, data_strs = _wat_strings(wat)
            candidates.extend(_flags_in(strings))
            if data_strs:
                lines.append("  data 段字符串：" + " ⋮ ".join(data_strs[:8]))
        hits, meta = _rawscan(path)
        candidates.extend(h.get("value") or h.get("match") or "" for h in hits)
        seen: list[str] = []
        for c in candidates:
            if c and c not in seen:
                seen.append(c)
        if seen:
            lines.append("  ★ flag 候选：" + " | ".join(seen[:8]))
        else:
            lines.append("  flag 候选：0（＝明文没命中，不是『没有 flag』："
                         "可能被加密/编码在 data 段，需人工看 wat）")

        # ── wat 正文 ──────────────────────────────────────
        if wat and mode in ("auto", "wat"):
            shown = wat[:_WAT_SHOW]
            if len(wat) > _WAT_SHOW:
                truncated = True
                status = "partial"
                limitations.append(f"wat 仅列前 {_WAT_SHOW} 字符（共 {len(wat):,}）")
            lines.append("")
            lines.append("-" * 60)
            lines.append(shown)

        if not struct and not wat:
            status = "not_applicable"
            limitations.append("结构化与反汇编均失败，目标可能损坏或非标准 wasm")

        limitations.append("静态分析：未执行 wasm，运行时才生成的字符串/解密结果一律不可见")
        contract = _contract(
            authority="observed" if (struct or wat) else "unknown",
            status=status,
            truncated=truncated,
            degraded=status in ("not_applicable",),
            limitations=limitations,
            evidence={
                "tool": "wabt.wasm2wat+wasm-objdump",
                "wabtDir": _DEFAULT_WABT_BIN,
                "rawscanScanned": meta.get("scanned"),
                "rawscanHits": len(hits),
            },
        )
        body = "\n".join(lines)
        body += "\n  _contract: " + json.dumps(contract, ensure_ascii=False)
        return ToolOutput(
            text=body,
            raw=json.dumps(contract, ensure_ascii=False),
            ok=not contract.get("degraded"),
        )
