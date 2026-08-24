"""子进程隔离执行器（本机/MVP 用，Docker 决赛前补充）。

安全设计（v2.0 加固，参考 CoRedteam-CTF Validator）：
- 30 秒超时强制 kill（asyncio.wait_for + 进程组终止）
- AST 前置校验：Python 代码执行前解析，拦截危险导入（os/subprocess 等）
  与危险调用（os.system/__import__/eval/exec 等），防 AI 生成恶意代码执行
- 输出捕获 stdout/stderr，超时标记 timed_out
- 单进程执行，避免恶意代码卡死主进程
- 完全满足 Web/Crypto/Misc 题型开发与本地题库测试（对齐降级方案）

注意：子进程隔离不如 Docker 严格；决赛前修复 WSL 后切换 docker_executor。
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time

logger = logging.getLogger(__name__)

from sandbox.executor import ExecResult, Executor

# ── 敏感环境变量剥离（架构 A3 缓解：沙盒非隔离下，AI 生成代码/题面诱导
#    可读 os.environ 拿到 API key——子进程启动时剥离，解题不受影响）──
_SENSITIVE_ENV_PATTERNS = (
    "API_KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL",
)


def sanitized_env() -> dict:
    """返回剥离了敏感密钥的环境变量副本（供子进程执行用）。"""
    env = dict(os.environ)
    for k in [k for k in env if any(p in k.upper() for p in _SENSITIVE_ENV_PATTERNS)]:
        env.pop(k, None)
    return env

# ── AST 校验规则（参考 CoRedteam Validator）─────────────────
# 允许的导入白名单（CTF 解题常用安全库）
# 2026-08-21 增补：os/sys/pathlib/glob/fnmatch——仅导入无 RCE 风险，
# 危险调用由 _FORBIDDEN_CALLS 在 AST 调用层拦截（os.system/popen/eval/exec 仍禁）；
# 此前全禁导致 agent 无法用 script 读附件（Prompt 第21条 vs 沙盒自相矛盾，实测 0/10）。
_ALLOWED_IMPORTS = {
    "math", "random", "re", "base64", "struct", "binascii", "json", "hashlib",
    "zipfile", "string", "itertools", "collections", "functools", "datetime",
    "codecs", "urllib.parse", "urllib", "time", "io", "tempfile", "zlib", "gzip",
    "httpx",  # web 题型发包（超时+进程隔离已兜底）
    "os", "sys", "pathlib", "glob", "fnmatch",
    "ast",  # 2026-08-21 增补：crypto 兜底嗅探用 ast.literal_eval 解析列表字面量（仅字面量，安全）
    # 2026-08-21 攻坚：reverse 反汇编 / 7z、rar 解压工具链（纯库无 RCE 原语）
    "capstone", "py7zr", "rarfile",
}
# 允许导入的子模块前缀（如 Crypto.* / PIL.* 等解题工具）
# "skills" 于 2026-08-21 P0-C 整改加入：crypto/misc fallback 脚本需
# `from skills.rsa_fermat_factor import run` 复用确定性攻击脚本（沙盒 cwd=项目根）。
_ALLOWED_IMPORT_PREFIXES = ("Crypto", "PIL", "pwn", "gmpy2", "sympy", "numpy", "skills")
# 禁止导入的模块（危险）：os/sys 已于 2026-08-21 解除（见 _ALLOWED_IMPORTS 注释），
# 其余保持全禁——subprocess/shutil/socket/ctypes 等一旦可导入配合调用层仍具逃逸面。
_FORBIDDEN_IMPORTS = {
    "subprocess", "shutil", "socket", "ctypes", "multiprocessing",
    "pty", "signal", "resource", "fcntl", "winreg", "win32api", "win32process",
}
# 禁止的调用（危险函数）
_FORBIDDEN_CALLS = {
    "system", "popen", "spawn", "Popen", "run", "call", "check_output",
    "check_call", "eval", "exec", "compile", "input", "breakpoint",
    "remove", "unlink", "rmdir", "chmod", "chown", "kill", "terminate",
    # P0 安全加固（2026-08-21）：动态属性访问绕过防护——
    # getattr(__import__("os"),"system")("id") 实测可逃逸 AST 校验
    # （__import__ 原只在 Attribute.attr 检查，Name 直接调用未拦截；
    #   getattr 动态取属性绕过 Attribute.attr 检查）。
    "__import__", "getattr", "setattr", "delattr", "vars", "globals", "locals",
}
# 禁止的属性访问（模块名.危险函数）
_FORBIDDEN_ATTRS = {"__import__", "__builtins__", "__subclasses__", "__globals__"}
# 字符串常量中的危险模式（P0-4 加固 2026-08-21）：
# 绕过者常把危险调用拼进字符串，再经 eval/exec 落地；这里对源码常量里
# 出现的关键组合直接判危险。只覆盖"组合特征"，不拦普通含 os 字样脚本。
_FORBIDDEN_STR_PATTERNS = (
    "os.system", "os.popen", "os.spawn", "subprocess", "os.exec",
    "pty.spawn", "shutil.rmtree", "__import__(", "getattr(__import__",
)


class _SecurityError(Exception):
    """代码未通过安全校验。"""


def validate_python_code(code: str) -> None:
    """AST 前置校验：不通过则抛 _SecurityError。

    拦截：危险导入（os/subprocess/socket/ctypes 等）、危险调用
    （system/popen/eval/exec/__import__ 等）、危险属性访问。
    """
    import ast

    tree = ast.parse(code)

    # 收集导入
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0]
                if name in _FORBIDDEN_IMPORTS:
                    raise _SecurityError(f"禁止导入危险模块: {alias.name}")
                if name not in _ALLOWED_IMPORTS and not any(
                    name.startswith(p) for p in _ALLOWED_IMPORT_PREFIXES
                ):
                    raise _SecurityError(f"未在白名单的导入: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in _FORBIDDEN_IMPORTS:
                raise _SecurityError(f"禁止从危险模块导入: {node.module}")
            if root not in _ALLOWED_IMPORTS and not any(
                root.startswith(p) for p in _ALLOWED_IMPORT_PREFIXES
            ):
                raise _SecurityError(f"未在白名单的 from-import: {node.module}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in _FORBIDDEN_CALLS:
                    raise _SecurityError(f"禁止调用危险函数: {node.func.id}")
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in _FORBIDDEN_CALLS:
                    raise _SecurityError(f"禁止调用危险方法: {node.func.attr}")
                if node.func.attr in _FORBIDDEN_ATTRS:
                    raise _SecurityError(f"禁止访问危险属性: {node.func.attr}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # 字符串常量中若出现危险关键字组合（如 os.system / subprocess.run），
            # 说明可能在经 eval/exec 落地前把命令藏进字符串，直接判危险。
            if any(p in node.value for p in _FORBIDDEN_STR_PATTERNS):
                raise _SecurityError(
                    f"字符串常量含危险关键字组合（疑似命令/导入注入）: {node.value[:60]!r}"
                )


class SubprocessExecutor(Executor):
    """子进程执行器：隔离运行 AI 生成的 Python 代码或 shell 命令。

    内置 watchdog（参考 hydra 边车设计）：
    - bash 重复检测：同一命令前缀连续出现 ≥ max_bash_repeats 次 → 判死循环
    - idle 检测：距上次执行超过 idle_timeout 秒仍无新命令 → 判空闲
    """

    def __init__(
        self,
        default_timeout: int = 30,
        max_bash_repeats: int = 3,
        idle_timeout: int = 120,
    ) -> None:
        self.default_timeout = default_timeout
        self.max_bash_repeats = max_bash_repeats
        self.idle_timeout = idle_timeout
        # {task_id: 最近命令列表}（用于重复检测）
        self._cmd_history: dict[str, list[str]] = {}
        # {task_id: 最后活动时间戳}
        self._last_active: dict[str, float] = {}

    # ── watchdog 接口 ───────────────────────────────────

    def watch_run(self, task_id: str, command: str) -> Optional[str]:
        """执行前调用：检测死循环/空闲，返回错误描述（None=放行）。"""
        now = time.monotonic()
        hist = self._cmd_history.setdefault(task_id, [])

        # idle 检测：距离上次执行超过阈值（且已有历史）
        if hist:
            last = self._last_active.get(task_id, now)
            if now - last > self.idle_timeout:
                return f"idle_timeout: {self.idle_timeout}s 无活动"

        # 重复检测：同一命令前缀连续出现 ≥ N 次
        prefix = command[:60]
        hist.append(prefix)
        if len(hist) >= self.max_bash_repeats:
            if len(set(hist[-self.max_bash_repeats:])) == 1:
                return f"bash_repeat: 相同命令连续执行 {self.max_bash_repeats} 次"

        self._last_active[task_id] = now
        return None

    def watch_reset(self, task_id: str) -> None:
        """任务结束后清理该任务的 watchdog 状态。"""
        self._cmd_history.pop(task_id, None)
        self._last_active.pop(task_id, None)

    async def run(self, code: str, timeout: int | None = None,
                  task_id: str = "") -> ExecResult:
        """执行代码。

        支持两种输入：
        - 以 `python: ` 或 `python3: ` 开头 → 作为 Python 源码执行
        - 其他 → 作为 shell 命令执行（走 bash -c）

        Args:
            code: Python 源码或 shell 命令
            timeout: 超时秒数（默认 30）
            task_id: 任务标识（watchdog 用；空则跳过 watchdog）

        Returns:
            ExecResult（stdout/stderr/exit_code/timed_out）
        """
        if not code or not code.strip():
            return ExecResult(stderr="空代码", exit_code=-1)

        # watchdog：死循环/空闲检测（仅当提供了 task_id 时）
        if task_id:
            block = self.watch_run(task_id, code)
            if block:
                return ExecResult(stderr=f"[watchdog] {block}", exit_code=-3)

        timeout = timeout or self.default_timeout
        code_stripped = code.strip()
        # P0修复（2026-08-21）：自动识别Python代码（无python:前缀时），
        # Windows无bash环境，避免LLM忘写前缀导致FileNotFoundError
        if code_stripped.startswith(("python: ", "python3: ")):
            python_src = code_stripped.split(":", 1)[1].strip()
        elif _looks_like_python(code_stripped):
            python_src = code_stripped
        else:
            python_src = None

        if python_src is not None:
            # AST 前置校验：危险导入/危险调用直接拒绝（防 AI 生成恶意代码）
            try:
                validate_python_code(python_src)
            except _SecurityError as exc:
                logger.warning("沙盒安全校验拦截: %s", exc)
                return ExecResult(stderr=f"[安全拦截] {exc}", exit_code=-2)
            argv = [sys.executable, "-c", python_src]
            stdin_data = None
        else:
            # 支持 shell 命令（含 heredoc 风格脚本）
            bash_err = _check_bash_command(code)
            if bash_err:
                logger.warning("沙盒安全校验拦截: %s", bash_err)
                return ExecResult(stderr=f"[安全拦截] {bash_err}", exit_code=-2)
            # P0修复（2026-08-21）：跨平台shell——Windows用cmd，类Unix用bash
            import platform as _pf
            if _pf.system() == "Windows":
                # P0 安全（2026-08-21 审计）：cmd.exe 分隔符/转义符校验——
                # `&` 已由 _check_bash_command 兜底；`^`（转义）、`%`（变量展开）、
                # `<`（输入重定向）为 cmd 特有面，执行前强制拦截。
                cmd_err = _check_cmd_command(code)
                if cmd_err:
                    logger.warning("沙盒安全校验拦截: %s", cmd_err)
                    return ExecResult(stderr=f"[安全拦截] {cmd_err}", exit_code=-2)
                argv = ["cmd.exe", "/c", code]
            else:
                argv = ["bash", "-c", code]
            stdin_data = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                env=sanitized_env(),  # A3：剥离 API key/token，防 AI 代码/附件读敏感环境变量
                stdin=asyncio.subprocess.DEVNULL if stdin_data is None else asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(input=stdin_data), timeout=timeout
                )
            except asyncio.TimeoutError:
                self._kill(proc)
                return ExecResult(
                    stderr=f"执行超时（>{timeout}s），已强制终止",
                    exit_code=-9,
                    timed_out=True,
                )
            except asyncio.CancelledError:
                # P0-2 修复（2026-08-21 赛后）：墙钟/竞速取消时同样必须杀掉子进程，
                # 否则 communicate 被取消后子进程继续在后台空转烧额度/挂资源。
                self._kill(proc)
                raise
            return ExecResult(
                stdout=_decode_bytes(stdout_b),
                stderr=_decode_bytes(stderr_b),
                exit_code=proc.returncode if proc.returncode is not None else -1,
            )
        except FileNotFoundError:
            return ExecResult(stderr="命令不存在（FileNotFoundError）", exit_code=-1)
        except Exception as exc:  # noqa: BLE001 - 执行异常兜底
            logger.warning("子进程执行异常: %s", exc)
            return ExecResult(stderr=f"执行异常: {exc}", exit_code=-1)

    @staticmethod
    def _kill(proc) -> None:
        """强制终止进程（P0-2 修复 2026-08-21：Windows 杀整棵进程树）。

        Windows：`cmd.exe /c` 会衍生孙进程，只 kill 直接子进程会残留
        后台进程（P2 目录卫生项）。用 taskkill /T /F 杀整树（stdlib，
        无新依赖）；随后 proc.kill() 兜底直接子进程。
        其他平台：kill 直接子进程（未设 start_new_session，不能 killpg
        以免误杀父进程组）。
        """
        if proc is None:
            return
        try:
            if sys.platform == "win32" and getattr(proc, "pid", None):
                try:
                    import subprocess as _sp

                    _sp.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        capture_output=True,
                        timeout=5,
                    )
                except Exception:  # noqa: BLE001 - taskkill 失败退回 proc.kill()
                    pass
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            pass


def _looks_like_python(code: str) -> bool:
    """启发式判断代码是否是Python代码（LLM可能忘写python:前缀）。"""
    if not code:
        return False
    # 明显Python特征
    py_signals = (
        "import ", "from ", "def ", "class ", "print(", "print (",
        "#!/usr/bin/env python", "if __name__", "async def ",
        "with open", "for ", "while ", "try:", "except ", "return ",
        "sys.", "os.", "len(", "range(", "str(", "int(", "bytes(",
        ".encode(", ".decode(", "open(", "__name__",
    )
    # 明显shell特征（排除）
    sh_signals = (
        "#!/bin/bash", "curl ", "wget ", "chmod ", "./", "apt ", "yum ",
        "ls -", "cat ", "grep ", "sed ", "awk ", "echo $", "export ",
    )
    code_lower = code.lower()
    # 先排除明显shell
    for sig in sh_signals:
        if sig in code_lower:
            return False
    # 再判定Python特征：前200字符含至少一个Python特征
    head = code[:200]
    py_count = sum(1 for sig in py_signals if sig in head)
    # 或含大量Python语法特征（缩进/冒号结尾）
    colon_lines = sum(1 for line in code.split("\n")[:10] if line.rstrip().endswith(":"))
    return py_count >= 1 or colon_lines >= 1


def _check_bash_command(command: str) -> Optional[str]:
    """bash 裸命令安全校验：返回错误描述（None=放行）。

    P0-4 加固（2026-08-21）+ P1-1 深化（2026-08-21 第五轮锐评）：
    原版仅拦 `;`/`&&`/`||`/`|` 四个拼接符，实测可被轻易绕过——
    `cat /etc/passwd`（单命令）、`echo $(cat /flag)`（$() 替换）、
    反引号、换行分隔多命令、`reg query`（读注册表 API key）全部漏过。
    现分层拦截：
      1. 拼接元字符（`;` `&&` `||` `|`）
      2. 命令替换（`$(` / 反引号）
      3. 换行/回车（多命令分隔）
      4. 写文件重定向 `>`（`<<` heredoc 不含 `>`，不受影响）
      5. 敏感目标：系统口令文件 / 注册表 / 环境密钥文件
    覆盖场景：openssl 适配器（单命令 + 参数白名单）与 heredoc（`cat << EOF`）
    均不含上述特征，继续放行。
    """
    if not command:
        return None
    # 1. 拼接元字符（`&` 兜底 bash 后台符与 cmd 无条件分隔符，2026-08-21 审计补）
    for meta in (";", "&&", "||", "|", "&"):
        if meta in command:
            return f"bash 命令含拼接元字符 {meta!r}（已拦截命令注入面）"
    # 2. 命令替换 / 反引号
    if "$(" in command or "`" in command:
        return "bash 命令含命令替换（$()/反引号，已拦截）"
    # 3. 换行分隔多命令
    if "\n" in command or "\r" in command:
        return "bash 命令含换行（多命令分隔，已拦截）"
    # 4. 写文件重定向（`<<` heredoc 不含 `>`，不误伤）
    if ">" in command:
        return "bash 命令含写重定向 `>`（已拦截）"
    # 5. 敏感目标：系统口令文件 / 注册表 / 密钥文件（读本地敏感信息）
    _low = command.lower()
    for _sens in (
        "/etc/passwd", "/etc/shadow", "reg query", "winreg", "hklm\\", "hkcu\\",
        ".env", "id_rsa", "authorized_keys", "known_hosts",
        "deepseek_api_key", "dasctf_token", "platform_token", "api_key",
    ):
        if _sens in _low:
            return f"bash 命令含敏感目标 {_sens!r}（已拦截本地敏感信息读取）"
    return None


def _check_cmd_command(command: str) -> Optional[str]:
    """Windows cmd 裸命令安全校验：返回错误描述（None=放行）。

    背景（2026-08-21 安全审计 P0）：`_check_bash_command` 覆盖 bash 拼接符
    （`;` `&&` `||` `|`，`&` 已补入），但 `cmd /c` 的语法差异未覆盖——
      - `^`：cmd 转义符（`d^ir` 混淆敏感命令，可绕过字符串关键字匹配）
      - `%`：变量展开（`%COMSPEC%` 拼任意命令 / `%PATH%` 读环境）
      - `<`：输入重定向（cmd 无 heredoc，正常解题命令几乎不用）
    这些字符在正常 CTF 解题 shell 命令中极少出现（web 发包走 http_request
    适配器；openssl 参数经 _sanitize 白名单），故一律拦截；仅 Windows 分支调用，
    不影响 Unix heredoc（`cat << EOF`）。
    """
    if not command:
        return None
    # 1. `^`：cmd 转义符（可混淆敏感命令绕过字符串匹配）
    if "^" in command:
        return "cmd 命令含 `^` 转义符（已拦截混淆面）"
    # 2. `%`：变量展开（%COMSPEC% 等拼任意命令 / 读环境）
    if "%" in command:
        return "cmd 命令含 `%` 变量展开（已拦截环境读取面）"
    # 3. `<`：输入重定向
    if "<" in command:
        return "cmd 命令含 `<` 输入重定向（已拦截）"
    return None


def _decode_bytes(data: bytes) -> str:
    """防御性解码：UTF-8 优先，检测到 UTF-16 特征时按 UTF-16 解码。

    Windows 下部分原生工具（如 mingw openssl）经管道输出 UTF-16LE，
    直接按 UTF-8 解码会产生乱码并污染 LLM 上下文。
    支持两种情况：带 BOM（\\xff\\xfe）与无 BOM 但 \x00 间隔密集（UTF-16LE 特征）。
    """
    if not data:
        return ""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    # 无 BOM 但 UTF-16LE 特征：偶数长度且 \x00 占比高（如每 2 字节 1 个 \x00）
    if len(data) >= 8 and len(data) % 2 == 0:
        zero_ratio = data.count(b"\x00") / len(data)
        if zero_ratio > 0.25:
            return data.decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # 兜底：latin-1 无损解码（保留原始字节可读形态）
        return data.decode("latin-1", errors="replace")
