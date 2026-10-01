"""持久会话（G1 抽象）· 跨步保留工作目录 + 命令历史 + 产物索引。

移植自 NYU EnIGMA / CAI 的「持久交互会话 + 跨步记忆」能力
（见 `2027-prep/差异分析-SOTA对比-20260928.md` 第 G1 项）。

设计约束（与项目铁律一致）：
- **纯抽象、零 LLM 依赖**：本类不直接调用任何模型，只负责"把命令跑出来、
  把状态留下"。这样"真推理"能力可以在上层（planner/executor）接入，
  而不污染确定性优先的 presolve 层。
- **与活环境解耦**：`run()` 默认在本地 subprocess 执行（Windows/Linux 通用）。
  轨道 B 接 Docker 时只需替换 exec 后端（子类化 `_exec`），接口不变。
- **不烧 token**：无任何网络/LLM 调用。
- **线程安全**：多会话并行跑批（benchmark / held-out）时同一实例可被多 worker 复用。

这是把本仓从"LLM 贡献 0/14"推向"有贡献"的第一块地基——没有持久会话，
presolve miss 后 LLM 看不到"我刚跑了什么"，只能凭题面静态猜（09-27 实测根因）。
"""

from __future__ import annotations

import locale
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CommandRecord:
    """单条命令执行记录（跨步记忆的基本单元）。"""

    cmd: str
    cwd: str
    stdout: str
    stderr: str
    returncode: int
    ts: str
    note: str = ""

    def ok(self) -> bool:
        return self.returncode == 0


def _decode_out(b: bytes | None) -> str:
    """命令输出解码：utf-8 优先，失败回退系统本地编码（中文 Windows = cp936/GBK）。

    P0 修复（2026-10-01 实测实锤）：
        此前 `_exec` 用 `subprocess.run(..., text=True)`，Python 默认按 **utf-8 严格**
        解码。在中文路径工作区跑 `dir` / `type`（cmd 内置命令输出是 GBK）时，
        解码线程抛 `UnicodeDecodeError` → **`proc.stdout` 变成 None** → 上层拿到
        「命令返回 0 但没有任何输出」。

        后果不是报错，而是**静默空输出**：agent 以为命令执行了却读不到东西，
        于是一遍遍重试 recon，把整题预算空烧光。A 档 5 题抬到单题 20 万 token
        仍 0/5，日志里的「工作区 shell 持续不可用…无法读取脚本内容」就是它。

    改为先取 bytes 再自行解码：utf-8 正常，GBK 回退本地编码，最坏 errors=replace
    ——**任何编码都不返回 None，也不抛异常**。
    """
    if not b:
        return ""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode(locale.getpreferredencoding(False) or "utf-8",
                        errors="replace")


class Session:
    """一个 CTF 题的可交互会话：工作目录 + 命令历史 + 产物索引。

    典型用法（赛道 A 抽象，不接活环境）：
        s = Session("/tmp/ctf/real_crypto_x")
        s.run("file challenge.bin")
        s.run("python3 solve.py")
        print(s.transcript())          # 喂给上层 planner/executor 的上下文
        flag = s.grep_output(r"flag\\{.*?\\}")
    """

    def __init__(self, cwd: str, session_id: str = "default") -> None:
        self.cwd = os.path.abspath(cwd)
        os.makedirs(self.cwd, exist_ok=True)
        self.session_id = session_id
        self.history: list[CommandRecord] = []
        self.artifacts: dict[str, str] = {}  # rel_path -> abs_path
        self.created = time.strftime("%Y-%m-%d %H:%M:%S")
        self._lock = threading.Lock()
        self._refresh_artifacts()

    # ── 执行 ────────────────────────────────────────────────
    def run(self, cmd: str, timeout: int = 60, note: str = "") -> CommandRecord:
        """在会话 cwd 执行命令，记录到历史，刷新产物索引。"""
        with self._lock:
            rec = self._exec(cmd, timeout, note)
            self.history.append(rec)
            self._refresh_artifacts()
            return rec

    def _exec(self, cmd: str, timeout: int, note: str) -> CommandRecord:
        """实际执行（子类可替换为 Docker/远程后端）。

        输出解码见模块级 `_decode_out`：必须拿 bytes 自行解码，不能用 `text=True`
        （中文 Windows 上会把 GBK 输出解崩成 None，表现为「命令成功但无输出」）。
        """
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                cwd=self.cwd,
                capture_output=True,      # 拿 bytes，解码交给 _decode_out
                timeout=timeout,
            )
            return CommandRecord(
                cmd=cmd,
                cwd=self.cwd,
                stdout=_decode_out(proc.stdout),
                stderr=_decode_out(proc.stderr),
                returncode=proc.returncode,
                ts=time.strftime("%Y-%m-%d %H:%M:%S"),
                note=note,
            )
        except subprocess.TimeoutExpired as e:
            return CommandRecord(
                cmd=cmd,
                cwd=self.cwd,
                stdout=_decode_out(e.stdout),
                stderr=_decode_out(e.stderr) + "\n[TIMEOUT]",
                returncode=-1,
                ts=time.strftime("%Y-%m-%d %H:%M:%S"),
                note=note,
            )
        except Exception as e:  # noqa: BLE001 - 执行层兜底，不向上抛
            return CommandRecord(
                cmd=cmd,
                cwd=self.cwd,
                stdout="",
                stderr=f"[EXEC_ERROR] {e!r}",
                returncode=-2,
                ts=time.strftime("%Y-%m-%d %H:%M:%S"),
                note=note,
            )

    # ── 产物索引 ───────────────────────────────────────────
    def _refresh_artifacts(self) -> None:
        """索引 cwd 下的产物文件（相对路径 -> 绝对路径）。"""
        self.artifacts.clear()
        for root, _dirs, files in os.walk(self.cwd):
            for f in files:
                abs_p = os.path.join(root, f)
                rel = os.path.relpath(abs_p, self.cwd)
                self.artifacts[rel] = abs_p

    # ── 跨步记忆（喂给上层 LLM/planner 的上下文）─────────────
    def transcript(self, max_chars_per_step: int = 2000) -> str:
        """生成可喂给上层 planner/executor 的紧凑会话摘要。

        这是 G1 的核心：让"下一步"能看到"上一步跑了什么、输出了什么"，
        跨步状态得以保留（EnIGMA scratchpad / CAI /memory 同类能力）。
        """
        lines = [f"# Session {self.session_id} @ {self.cwd} (steps={len(self.history)})"]
        for i, r in enumerate(self.history, 1):
            lines.append(f"## step {i} $ {r.cmd}  (rc={r.returncode})")
            out = (r.stdout or "") + (r.stderr or "")
            if len(out) > max_chars_per_step:
                out = "...[truncated]...\n" + out[-max_chars_per_step:]
            lines.append(out.rstrip())
        return "\n".join(lines)

    def last_output(self) -> str:
        return self.history[-1].stdout if self.history else ""

    def grep_output(self, pattern: str) -> Optional[str]:
        """在全部历史输出里搜首个匹配（如 flag）。"""
        import re

        rx = re.compile(pattern)
        for r in self.history:
            m = rx.search((r.stdout or "") + (r.stderr or ""))
            if m:
                return m.group(0)
        return None

    def step_count(self) -> int:
        return len(self.history)
