"""受信 RCE 通道（Trusted RCE Channel）。

设计目的
--------
让 agent 在「已确认获得 RCE」的前提下，能够执行**受信的后渗透命令**，从而自动解
RCE 类 web 题（典型如 SSTI RCE）。这是默认沙盒 `SubprocessExecutor`（禁
`os.popen` / `__import__` / `subprocess` 等）的**有意例外**——默认沙盒仍对所有
AI 生成代码全量拦截，本通道是独立的、显式 opt-in 内部能力。

安全边界（缺一不可，否则本通道形同后门）
----------------------------------------
1. 显式门控：仅当 `CTF_AGENT_TRUSTED_RCE == "1"` 时 `execute_trusted` 才真正执行
   命令；否则直接抛 RuntimeError。默认**关闭**。
2. 仅用于**自研、回环（127.0.0.1）训练靶机**：本模块只被
   `agents/web_toolkit.py` 的 `_FALLBACK_SSTI_RCE` 调用，而该 fallback 仅在题目
   description 含 "rce" 时由 `build_fallback_script` 选入，对应
   `self_authored_training` 靶机。
3. 全量审计：每次调用把 时间戳 / 命令 / 结果摘要 / 拒绝原因 写入
   `sandbox/trusted_rce_audit.log`，可追溯、可复盘。
4. 最小破坏性兜底（防御纵深，非主门禁）：拒绝明显破坏性 token（rm/del/format/
   mkfs/shutdown/管道到 shell 等）。
5. 不削弱默认沙盒：`validate_python_code` 仍对所有普通 AI 生成代码拦截；本通道
   的真实命令执行发生在 `execute_trusted` 内部（不经过 `_check_bash_command`），
   由 env 门控 + 审计兜底。

重要说明
--------
这是 CTF 训练工具的能力扩展，**不是通用 RCE 工具**。生产 / 决赛环境须配合 Docker
隔离（`subprocess_executor` 文档已注明），且受信通道应仅在受控训练会话中开启。
开启后任何经 `import sandbox.trusted_rce` 的脚本都能调用本通道——这是设计内的
"操作员显式授权"语义，开启即代表你认可该训练会话的命令执行风险。
"""
from __future__ import annotations

import logging
import os
import subprocess
from datetime import datetime

logger = logging.getLogger(__name__)

# 复用默认沙盒的敏感环境剥离，避免命令子进程继承 API key / token
try:
    from sandbox.subprocess_executor import sanitized_env
except Exception:  # noqa: BLE001 - 退化到内联实现（sandbox 未被加入 sys.path 时）
    def sanitized_env() -> dict:
        env = dict(os.environ)
        for k in [k for k in env if any(
            p in k.upper() for p in ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD")
        )]:
            env.pop(k, None)
        return env


_AUDIT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trusted_rce_audit.log")

# 最小破坏性兜底（防御纵深，非主门禁）。注意 `>` `>>` 也在内，防写重定向。
_FORBIDDEN_TOKENS = (
    "rm ", "rmdir ", "del ", "format ", "mkfs", "shutdown", ":(){",
    "curl ", "wget ", "powershell ", "cmd.exe", "certutil",
    "| sh", "|bash", "| sh ", "| bash ", ">", ">>",
)


def _log(entry: str) -> None:
    try:
        with open(_AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} {entry}\n")
    except Exception:  # noqa: BLE001 - 审计失败不阻断解题
        pass


def execute_trusted(cmd: str) -> str:
    """受信后渗透命令执行（gated）。

    Args:
        cmd: 要执行的 shell 命令（针对回环训练靶机的后渗透读取等）。

    Returns:
        命令 stdout（截断到 4KB）。

    Raises:
        RuntimeError: 未开启受信通道、命令空、或命中破坏性兜底 token。
    """
    if os.environ.get("CTF_AGENT_TRUSTED_RCE") != "1":
        raise RuntimeError(
            "受信 RCE 通道未开启：请设置 CTF_AGENT_TRUSTED_RCE=1 "
            "（仅限自研回环训练靶机，且全程审计）"
        )
    if not cmd or not cmd.strip():
        raise RuntimeError("空命令")
    low = cmd.lower()
    for tok in _FORBIDDEN_TOKENS:
        if tok in low:
            _log(f"DENIED cmd={cmd!r} reason=forbidden_token({tok!r})")
            raise RuntimeError(f"受信通道兜底拒绝危险 token: {tok!r}")
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=30, env=sanitized_env(),
        )
        out = (proc.stdout or "")[:4096]
        _log(f"OK cmd={cmd!r} rc={proc.returncode} out={out[:200]!r}")
        return out
    except subprocess.TimeoutExpired:
        _log(f"TIMEOUT cmd={cmd!r}")
        raise RuntimeError("受信通道命令超时（>30s）")
    except Exception as exc:  # noqa: BLE001
        _log(f"ERR cmd={cmd!r} err={exc!r}")
        raise RuntimeError(f"受信通道执行异常: {exc}")
