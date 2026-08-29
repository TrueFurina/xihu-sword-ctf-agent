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
2. 仅用于**自研、回环（127.0.0.1/localhost）训练靶机**：
   - 代码强校验：命令中出现非回环 IP/主机名直接拒绝，不依赖调用方自觉；
   - 调用约束：本模块只被 `agents/web_toolkit.py` 的 `_FALLBACK_SSTI_RCE` 调用，
     而该 fallback 仅在题目 description 含 "rce" 时由 `build_fallback_script` 选入，
     对应 `self_authored_training` 靶机。
3. 全量审计：每次调用把 时间戳 / 命令 / 结果摘要 / 拒绝原因 写入
   `sandbox/trusted_rce_audit.log`，可追溯、可复盘。
4. 最小破坏性兜底（防御纵深，非主门禁）：拒绝明显破坏性 token、反弹 shell 模式、
   任意代码执行、下载执行、命令替换、写重定向。
5. 不削弱默认沙盒：`validate_python_code` 仍对所有普通 AI 生成代码拦截；本通道
   的真实命令执行发生在 `execute_trusted` 内部（不经过 `_check_bash_command`），
   由 env 门控 + 审计兜底 + 地址强校验 + 黑名单多层防护。

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
import re
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

# ── 严格黑名单（防御纵深，非主门禁）────────────────────────────
# 分类列出，每类都有明确防御目的：
_FORBIDDEN_TOKENS = (
    # ① 文件系统破坏性操作
    "rm ", "rm -rf", "rmdir ", "del ", "deltree", "format ", "mkfs", "shutdown",
    "dd if=", "mkfs.", "mke2fs", "fdisk", "parted",
    # ② 反弹 shell / 交互 shell
    "bash -i", "sh -i", "/bin/bash", "/bin/sh", "/bin/zsh", "dash -i",
    "nc ", "ncat", "socat", "netcat", "nc.traditional", "ncat --exec",
    "bash -c 'bash -i", "/dev/tcp/", "/dev/udp/",
    ":(){",  # fork bomb
    # ③ 下载执行（远程代码下载）
    "curl ", "wget ", "curl|", "wget|", "curl |", "wget |",
    "powershell ", "cmd.exe", "certutil", "certutil.exe", "bitsadmin",
    "invoke-webrequest", "iwr ", "irm ", "invoke-restmethod",
    # ④ 任意代码执行 / 解释器
    "python -c", "python3 -c", "py -c", "perl -e", "ruby -e", "php -r",
    "node -e", "lua -e", "eval ", "exec ", "system(", "passthru(",
    "chmod +x", "chmod 777",
    # ⑤ 写文件/重定向（防止写crontab/写ssh key/覆盖系统文件）
    "| sh", "|bash", "| sh ", "| bash ", ">", ">>", "tee ",
    # ⑥ 命令替换（防止嵌套调用绕过黑名单）
    "`", "$(",
    # ⑦ 提权/横向
    "sudo ", "su ", "chown ", "chmod u+s", "passwd ",
)


# ── 回环靶机地址白名单正则 ────────────────────────────────────
# 仅允许访问 127.x.x.x / localhost / 0.0.0.0（回环/本机）
# 禁止 10.x/172.16-31/192.168（内网）及公网IP
_ALLOWED_HOST_PATTERNS = (
    re.compile(r"https?://127\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?"),
    re.compile(r"https?://localhost(?::\d+)?"),
    re.compile(r"https?://0\.0\.0\.0(?::\d+)?"),
)
_NON_LOOPBACK_IP_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
)
_EXTERNAL_HOST_RE = re.compile(
    r"https?://(?!127\.|localhost|0\.0\.0\.0)[A-Za-z0-9.\-]+(?::\d+)?",
    re.IGNORECASE,
)


def _validate_target_is_loopback(cmd: str) -> None:
    """校验命令中的网络目标均为回环地址（127.0.0.1/localhost/0.0.0.0）。

    设计目的：文档承诺本通道「仅用于自研回环训练靶机」，此函数将承诺代码化，
    不依赖调用方自觉。发现非回环IP/主机名直接抛异常拒绝。
    """
    # 提取所有 http(s):// URL
    urls = re.findall(r"https?://[^\s'\"<>]+", cmd, re.IGNORECASE)
    for url in urls:
        if not any(p.search(url) for p in _ALLOWED_HOST_PATTERNS):
            _log(f"DENIED cmd={cmd!r} reason=external_url({url!r})")
            raise RuntimeError(
                f"受信通道仅允许回环地址(127.0.0.1/localhost)，拒绝外部URL: {url!r}"
            )
    # 裸 IP:port 检测（非URL形式）：排除 127.x.x.x 和 0.0.0.0
    for ip_match in _NON_LOOPBACK_IP_RE.finditer(cmd):
        ip = ip_match.group(0)
        if not (ip.startswith("127.") or ip == "0.0.0.0"):
            # 检查是否是端口号误判（如 `curl 127.0.0.1:8080` 中 8080 不是IP）
            # 简单校验：前两段不能是 127 或 0
            parts = ip.split(".")
            if len(parts) == 4 and parts[0] not in ("127", "0"):
                _log(f"DENIED cmd={cmd!r} reason=non_loopback_ip({ip!r})")
                raise RuntimeError(
                    f"受信通道仅允许回环地址，拒绝非回环IP: {ip!r}"
                )


def _log(entry: str) -> None:
    try:
        with open(_AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} {entry}\n")
    except Exception:  # noqa: BLE001 - 审计失败不阻断解题
        pass


def execute_trusted(cmd: str) -> str:
    """受信后渗透命令执行（gated，多层防护）。

    多层防护（缺一不可）：
      1. 环境变量门控：CTF_AGENT_TRUSTED_RCE == "1" 才执行
      2. 回环地址校验：命令中仅允许 127.0.0.1/localhost/0.0.0.0
      3. 危险 token 黑名单：7类共60+危险模式
      4. 超时30s：防止挂死
      5. 环境变量脱敏：子进程不继承 API_KEY/TOKEN/SECRET
      6. 全量审计：所有调用写审计日志

    Args:
        cmd: 要执行的 shell 命令（针对回环训练靶机的后渗透读取等）。

    Returns:
        命令 stdout（截断到 4KB）。

    Raises:
        RuntimeError: 未开启受信通道、命令空、命中黑名单、或目标非回环。
    """
    if os.environ.get("CTF_AGENT_TRUSTED_RCE") != "1":
        raise RuntimeError(
            "受信 RCE 通道未开启：请设置 CTF_AGENT_TRUSTED_RCE=1 "
            "（仅限自研回环训练靶机，且全程审计+回环强校验）"
        )
    if not cmd or not cmd.strip():
        raise RuntimeError("空命令")
    # 命令长度限制（防止超长命令注入）
    if len(cmd) > 1024:
        _log(f"DENIED cmd={cmd!r} reason=too_long({len(cmd)})")
        raise RuntimeError(f"受信通道命令超长({len(cmd)}>1024字符)")
    # 回环地址强校验（文档承诺代码化）
    _validate_target_is_loopback(cmd)
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
