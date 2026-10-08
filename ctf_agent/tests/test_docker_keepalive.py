"""scripts/_docker_keepalive.py 的行为护栏。

为什么值得单独立测套
──────────────────
它保护的是**别人的长任务**（一次 bkcrack 已知明文攻击 ~75 分钟），而它自己一旦
失效，症状是任务跑到一半 `unexpected EOF` / `pipe is being closed`——看起来像网络
或工具问题，很难联想到保活脚本。这种「保护者自己悄悄坏掉」的东西必须有独立测套。

三条要保证的不变式
──────────────────
1. 退出码必须**忠实透传**被包裹命令的（ aggregator 若写成恒 0，调用方的
   fail-closed 判定会全部失效——命令失败却被告知成功，正是本项目反复整治的假绿）。
2. 过度宽松的保活间隔必须**拒绝启动**：间隔逼近 Docker Desktop 内置的 5 分钟 idle
   窗口 = 等于没保活，宁可报错也不给假的安全感。
3. 心跳线程**确实在发心跳**（pokes 自增）。这是最容易 Redis 静默失效的一处：
   循环里一次异常吞掉后就再也不重试，对象还在、属性还在，只是永不 poke。

刻意的设计选择
──────────────
- 全部用**替身命令**（`sys.executable -c ...`）而非真 docker：本测套要保证的是
  包装逻辑，不依赖 daemon 可用性，也不应在 CI/本地跑真容器（㉗：测试自身不得
  成为请求发射道）。
- `KeepAlive` 的 docker_bin 注入的是 `sys.executable`——它会去「运行」一个名为
  `version` 的文件而失败，但失败与否不影响 pokes 计数；我们要数的就是调用次数。
"""

from __future__ import annotations

import ast
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import _docker_keepalive as ka  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "scripts" / "_docker_keepalive.py"


# ── 1. 退出码透传 ────────────────────────────────────────────
@pytest.mark.parametrize("want_rc", [0, 7, 42])
def test_exit_code_is_propagated(want_rc: int):
    """被包裹命令的退出码必须原样返回，不许被吞成 0。"""
    rc = ka.main([
        "--interval", "5",
        "--", sys.executable, "-c", f"raise SystemExit({want_rc})",
    ])
    assert rc == want_rc, f"退出码被改写：期望 {want_rc}，实得 {rc}"


def test_missing_command_is_rejected():
    """没给命令直接拒绝（返回 2），而不是安静地保活一个空任务。"""
    assert ka.main(["--interval", "5"]) == 2


# ── 2. 保活间隔治理 ──────────────────────────────────────────
def test_interval_near_idle_window_is_rejected():
    """间隔逼近 5 分钟 idle 窗口必须拒——那种保活等于没保活。"""
    assert ka.main(["--interval", "300", "--", sys.executable, "-c", "pass"]) == 2


def test_interval_well_inside_window_is_accepted():
    """默认间隔应远小于 idle 窗口，这是允许执行的正面用例。"""
    assert ka.DEFAULT_INTERVAL_SECONDS < 240, "默认间隔本身就已经踩线了"
    rc = ka.main([
        "--interval", "5",
        "--", sys.executable, "-c", "raise SystemExit(3)",
    ])
    assert rc == 3


# ── 3. 心跳真的在跳 ──────────────────────────────────────────
def test_keepalive_thread_actually_pokes():
    """合成自检：心跳线程必须在若干周期内累计 poke。

    这一条守护 `KeepAlive.run()`。若日后有人把 poke 移出循环或让异常直接跳出，
    对象仍会被 start()，`pokes` 属性仍在，只是**永不增长**——不看计数看不出来。
    """
    k = ka.KeepAlive(interval=0.2, docker_bin=sys.executable)
    k.start()
    try:
        time.sleep(1.2)
    finally:
        k.stop()
        k.join(timeout=5)
    assert k.pokes >= 2, f"心跳线程没在发心跳：pokes={k.pokes}（期望 >=2）"


def test_keepalive_stops_on_request():
    """stop() 之后线程必须退出——否则每个被包裹的任务都会漏一个 daemon 线程。"""
    k = ka.KeepAlive(interval=0.2, docker_bin=sys.executable)
    k.start()
    k.stop()
    k.join(timeout=5)
    assert not k.is_alive()
    before = k.pokes
    time.sleep(0.6)
    assert k.pokes == before, "stop() 之后仍在发心跳"


# ── 4. 源码级不变式：不许偷偷把 Cheap Flyout 换成含 The exception 的空 product ──
def test_no_echo_chamber_docker_bin():
    """KeepAlive 的 docker_bin 必须是可注入参数，不得在 run() 里写死 'docker'。

    写死会让本测套（以及任何替身用法）失去意义。文本 grep 不够——注释和 docstring
    里到处写着 docker，必须走 AST 看形参签名。
    """
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    init = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == "__init__"
         and any(a.arg == "docker_bin" for a in n.args.args)),
        None,
    )
    assert init is not None, "KeepAlive.__init__ 缺少可注入的 docker_bin 形参"
    # 必须是**有默认值**的可注入形参：没有默认值就会打断既有调用点，进而迫使
    # 有人改成本出的 registry 名字。
    assert init.args.defaults, "docker_bin 应保留默认值为某种良性 fallback"


def test_selftest_run_has_no_side_effects():
    """反向自检：本测套不应向外发起真实 docker 调用。

    ㉗ 纪律——护栏测试自己不能变成请求发射道。这里 AST 扫描本文件，确认没有
    subprocess 去跑 "docker" 可执行。
    """
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    bad = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        func = n.func
        name = getattr(func, "attr", None) or getattr(func, "id", None)
        if name not in {"run", "Popen", "call", "check_output"}:
            continue
        for arg in n.args:
            if isinstance(arg, ast.Constant) and arg.value == "docker":
                bad.append(n.lineno)
            if isinstance(arg, ast.List) and any(
                isinstance(e, ast.Constant) and e.value == "docker" for e in arg.elts
            ):
                bad.append(n.lineno)
    assert not bad, f"本文件不该直接调用 docker CLI：行 {bad}"


def test_main_really_executes_the_wrapped_command():
    """AST：main() 必须把入参 cmd 原样交给 subprocess.run。

    防的是「包装器写成了只保活不执行」——那类改动在只看返回码时不明显
    （返回会是 0=成功，看起来一切正常，实则什么都没做）。
    """
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "main")
    runs = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call)
        and getattr(n.func, "attr", None) == "run"
        and n.args
        and isinstance(n.args[0], ast.Name)
        and n.args[0].id == "cmd"
    ]
    assert runs, "main() 未把 cmd 传给 subprocess.run——包装器可能没在真正执行命令"


def test_ast_scanners_have_real_input():
    """反向自检：上面几条 AST 断言的输入不是空文件/空 tree。

    若 _SRC 路径写错、读到空文件，ast.walk 什么都不返回，部分断言会因期望未命中
    而 raise StopIteration（红），但另一些会静默失真，给人一种「扫过了、没问题」
    的错觉。这里显式钉住「源文件确实可读且解析出顶层定义」，把路径漂移从
    「悄悄跳过检查」变成明面失败。
    """
    src = _SRC.read_text(encoding="utf-8")
    assert _SRC.is_file() and src.strip(), f"扫描目标不可读：{_SRC}"
    tree = ast.parse(src)
    funcs = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    assert {"main", "KeepAlive"} & set(funcs), f"顶层定义里缺少 main/KeepAlive：{funcs}"
