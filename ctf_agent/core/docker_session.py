"""容器内执行的持久会话（Session 的 Docker 后端，轨道 B）。

为什么单独一个文件而不是改 core/session.py
──────────────────────────────────────────
`core/session.py` 的 `_exec` 早在 G1 抽象阶段就留了口子（docstring 明写
「子类可替换为 Docker/远程后端，接口不变」）。但那个**预留接口直到今天都没被
接上过**，反倒让「本机跑不了 Linux 工具」被记成了永久结论。

本模块是第一次真正把后端换掉。单独成文件是刻意的：
- 不碰 `session.py`（Windows 本地后端仍是被 used 的默认路径，改动面需最小化）；
- 让「换了后端」这件事有独立的可 review 单元 + 独立测套。

唯一的硬约束：绝不静默降级
──────────────────────────
本机 Docker daemon 是 **间歇性可用** 的（Docker Desktop `AutoStart=false`，
daemon 闲置会自退；实测同一会话内先用还好、几十秒后 npipe 就断了）。

于是最危险的不是「docker 起不来」，而是**后端悄悄退回本机 Windows shell**：
命令照样返回 rc=0、`file` 照样有输出——只不过跑的是 Windows 版工具、
路径语义全不同，跑出来的东西一个都用不了。上层看到的是「工具执行成功」，
实际是**在错误的机器上完成了任务**，这类假绿比报错难查一个量级。

因此本模块：**任何** docker 侧失败都返回 `UNAVAILABLE_RC` 并带
`[DOCKER_UNAVAILABLE]` 标记，绝不 try 完再 fallback 到 subprocess 跑本地。

用法
────
    s = DockerSession(cwd="E:/.../work", image="ctf-tools:1")
    ok, reason = s.start()          # docker run -d ... sleep infinity
    if not ok: 处理不可用，别硬跑
    rec = s.run("bkcrack --version")
    s.stop()

零 LLM 依赖、零网络（除 docker CLI 本身）。
"""

from __future__ import annotations

import subprocess
import time
from typing import Optional

from .session import CommandRecord, Session, _decode_out

#: docker 后端不可用时的专用返回码（区别于 -1 超时 / -2 通用执行错误）。
#: 上层必须能靠这个码区分「命令在容器里返回值非零」和「命令压根没进容器」。
UNAVAILABLE_RC = -3

#: 不可用标记串。compat/统计逻辑按它识别本类失败。
UNAVAILABLE_TAG = "[DOCKER_UNAVAILABLE]"

# docker CLI 单次调用的额外宽限（覆盖容器调度、镜像加载等 CLI 自身开销）。
# 命令本身的耗时由 `timeout` 控制，这里只是给 docker 加一点余量，
# 免得 daemon 稍慢一点就被误判成命令超时——两者含义完全不同。
_CLI_GRACE_SECONDS = 10


class DockerSession(Session):
    """把命令丢进 **长驻容器** 执行的 Session。

    与本地 `Session` 的差别只有 `_exec` 的实现，其余（历史 / 产物索引 /
    transcript / grep_output）完全复用父类——这是 G1 抽象该有的形状。

    Args:
        cwd: 宿主机工作目录。它会被挂载进容器，因此两边看到同一批文件，
             `Session._refresh_artifacts()`（宿主机扫描）依旧成立。
        image: 工具镜像，默认 `ctf-tools:1`（见 `docker/Dockerfile`）。
        container: 容器名/ID。不传则由 `start()` 按会话生成一个。
        workdir: 容器内工作目录，`cwd` 的挂载点。
        docker_bin: docker 可执行文件名，可被同为 stub/差异版本覆盖。
    """

    def __init__(
        self,
        cwd: str,
        image: str = "ctf-tools:1",
        container: Optional[str] = None,
        workdir: str = "/work",
        docker_bin: str = "docker",
        session_id: str = "docker",
    ) -> None:
        super().__init__(cwd, session_id=session_id)
        self.image = image
        self.container = container or f"ctf-session-{session_id}"
        self.workdir = workdir
        self.docker_bin = docker_bin

    # ── 生命周期 ─────────────────────────────────────────────
    def start(self, timeout: int = 120, readonly: bool = False) -> tuple[bool, str]:
        """起长驻容器并挂载工作目录。返回 (是否成功, 原因)。

        失败必须被调用方处理。这里**不会**退化成「那就用本地跑吧」——
        那是本模块存在的唯一理由所要防的事。
        """
        if self._container_is_running():
            return True, f"container {self.container} already running"

        mount = f"{self.cwd}:{self.workdir}" + (":ro" if readonly else "")
        argv = [
            self.docker_bin, "run", "-d", "--rm",
            "--name", self.container,
            "-v", mount,
            "-w", self.workdir,
            self.image,
            "sleep", "infinity",
        ]
        try:
            proc = subprocess.run(argv, shell=False, capture_output=True, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - 启动层不向上抛
            return False, f"{UNAVAILABLE_TAG} docker run 启动失败: {e!r}"
        if proc.returncode != 0:
            return False, f"{UNAVAILABLE_TAG} docker run rc={proc.returncode}: {_decode_out(proc.stderr).strip()[:300]}"
        return True, f"started {self.container} ({self.image})"

    def stop(self, timeout: int = 60) -> tuple[bool, str]:
        """停掉容器。已经是「不存在」状态也算成功（幂等，方便清理逻辑复用）。"""
        argv = [self.docker_bin, "rm", "-f", self.container]
        try:
            proc = subprocess.run(argv, shell=False, capture_output=True, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            return False, f"{UNAVAILABLE_TAG} docker rm 失败: {e!r}"
        if proc.returncode != 0:
            return False, f"{UNAVAILABLE_TAG} docker rm rc={proc.returncode}: {_decode_out(proc.stderr).strip()[:300]}"
        return True, f"removed {self.container}"

    # ── 可用性 ──────────────────────────────────────────────
    def _container_is_running(self) -> bool:
        """探测容器是否在跑。任何异常一律按「不在」处理（fail-closed）。"""
        argv = [self.docker_bin, "inspect", "-f", "{{.State.Running}}", self.container]
        try:
            proc = subprocess.run(argv, shell=False, capture_output=True, timeout=30)
        except Exception:  # noqa: BLE001 - daemon 掉了也是「不在」
            return False
        if proc.returncode != 0:
            return False
        return _decode_out(proc.stdout).strip().lower() == "true"

    def availability_reason(self) -> Optional[str]:
        """不可用则返回原因串，可用则返回 None（便于 `if s.availability_reason():`）。"""
        if not self.container:
            return f"{UNAVAILABLE_TAG} 未指定容器名"
        if not self._container_is_running():
            return (f"{UNAVAILABLE_TAG} 容器 {self.container} 未在运行——"
                    f"先调用 start()；daemon 可能也已退出"
                    f"（Docker Desktop AutoStart=false 时闲置会自退）")
        return None

    # ── 执行后端 ─────────────────────────────────────────────
    def _exec_argv(self, cmd: str) -> list[str]:
        """构造 `docker exec` 参数。**不用 shell=True**（这是本机后端的做法）：
        命令是被发给容器里自带的 sh 去解析的，宿主机 shell 不能参与——
        否则引号/管道会被 Windows 的 cmd.exe 先吃掉一层。
        """
        return [
            self.docker_bin, "exec",
            "-w", self.workdir,
            self.container,
            "sh", "-c", cmd,
        ]

    def _exec(self, cmd: str, timeout: int, note: str) -> CommandRecord:
        """在容器里执行。**任何** docker 侧失败都返回 UNAVAILABLE_RC，不降级。"""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")

        reason = self.availability_reason()
        if reason is not None:
            return CommandRecord(
                cmd=cmd, cwd=self.cwd, stdout="", stderr=reason,
                returncode=UNAVAILABLE_RC, ts=ts, note=note,
            )

        try:
            proc = subprocess.run(
                self._exec_argv(cmd),
                shell=False,              # ← 绝不让宿主机 shell 参与
                capture_output=True,      # 拿 bytes，解码交给 _decode_out
                timeout=timeout + _CLI_GRACE_SECONDS,
            )
            return CommandRecord(
                cmd=cmd,
                cwd=self.cwd,
                stdout=_decode_out(proc.stdout),
                stderr=_decode_out(proc.stderr),
                returncode=proc.returncode,
                ts=ts,
                note=note,
            )
        except subprocess.TimeoutExpired as e:
            return CommandRecord(
                cmd=cmd, cwd=self.cwd,
                stdout=_decode_out(e.stdout),
                stderr=_decode_out(e.stderr) + "\n[TIMEOUT]",
                returncode=-1, ts=ts, note=note,
            )
        except Exception as e:  # noqa: BLE001 - 执行层兜底，不向上抛
            # 这里是最后一道口子：即便 docker 抛 FileNotFoundError/OSError，
            # 也只能报 UNAVAILABLE，**不许**顺手用 subprocess 在本机再跑一次。
            return CommandRecord(
                cmd=cmd, cwd=self.cwd, stdout="",
                stderr=f"{UNAVAILABLE_TAG} exec 异常: {e!r}",
                returncode=UNAVAILABLE_RC, ts=ts, note=note,
            )
