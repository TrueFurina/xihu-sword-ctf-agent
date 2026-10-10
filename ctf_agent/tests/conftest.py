# -*- coding: utf-8 -*-
"""pytest 全局隔离（2026-09-03）。

背景：core/blackboard.py（9/2 引入的跨会话事实黑板）把 presolve 命中结果持久化到
data/results/blackboard.json。test_presolve_poller 等旧测试用通用 id（如 "q1"）构造
假题，命中后会把假 flag 写进生产黑板，导致同 id 的后续测试（含跨进程复跑）被缓存
短路——去重 / answers 不匹配 / 无附件契约全被击穿（曾以 3 连败暴露）。

处置：本 conftest 用 autouse fixture 把黑板路径指向每个测试独立的临时目录，并重置
模块级单例，使测试互不串扰、且永不污染生产黑板文件。生产运行（run.py / 真题跑批）
不加载 tests/conftest.py，黑板正常复用。
"""
import os
import sys

import pytest

_CTF_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _CTF_AGENT_ROOT not in sys.path:
    sys.path.insert(0, _CTF_AGENT_ROOT)


@pytest.fixture(autouse=True)
def _isolate_blackboard(tmp_path, monkeypatch):
    """每个测试独立黑板文件（tmp_path），互不串扰、不落生产 data/results。"""
    try:
        import core.blackboard as bb
    except Exception:  # noqa: BLE001 - core 包缺失时不阻断无关测试
        yield
        return
    # 注意：不能只改 bb._BLACKBOARD_PATH —— Blackboard.__init__ 的默认参数在定义时
    # 已绑定该字符串，运行期改模块属性不生效。直接替换模块级单例为指向 tmp 的实例。
    isolated = bb.Blackboard(path=str(tmp_path / "blackboard.json"))
    monkeypatch.setattr(bb, "_blackboard", isolated)
    yield
    bb._blackboard = None


# ─────────────────── 2026-10-11：临时仓库 subprocess 的 git 环境隔离 ───────────────────
# 缺陷（实锤，含受损证据）：pre-commit 钩子由真实 `git commit` 拉起时，git 会向钩子
# 及其**所有后代进程**导出一批"本地环境变量"（权威清单取自 `git rev-parse
# --local-env-vars`）。本车道实测导出：
#     GIT_DIR=E:/Program/西湖论剑/.git/worktrees/wt-denom-fix
#     GIT_INDEX_FILE=E:/Program/西湖论剑/.git/worktrees/wt-denom-fix/index
# ⑥ 快速回归里的 test_git_guard / test_git_snapshot 会在 tmp_path 里 `git init` 构造
# 临时仓库，继承到上述变量后所有对象都落到**主仓** gitdir 而不是 tmp：
#   - 假红：`git commit -m c1`、`git bundle create` 在 tmp 仓库里失败（3 个用例红）
#     → ⑥ 门禁每次真实提交都被拦死（假红，非本次改动引起）；
#   - 污染：测试用的 f.txt 进了主仓索引并落成垃圾提交（实测多出 `x`、`c1` 两个提交）。
# 因此这两份测试文件开头"绝不触碰真仓库的 .git"的承诺在真实提交上下文里是失效的。
#
# 修复（两层，fail-closed）：
#   ① 凡在临时目录里跑 git 的调用，一律显式传 env=clean_git_env()（本文件唯一实现）；
#   ② autouse fixture 抹掉这些变量，兜住"忘了传 env=" 的新用例 / 子进程。
# 作者身份类变量（GIT_AUTHOR_* / GIT_COMMITTER_*）**不抹**：tmp 仓库若未配 user.email，
# 提交身份依赖宿主身份兜底，抹掉会把 `Please tell me who you are` 变成新的假红。
_LOCAL_ENV_VARS = frozenset("""
GIT_ALTERNATE_OBJECT_DIRECTORIES
GIT_COMMON_DIR
GIT_CONFIG
GIT_CONFIG_COUNT
GIT_CONFIG_PARAMETERS
GIT_DIR
GIT_GRAFT_FILE
GIT_IMPLICIT_WORK_TREE
GIT_INDEX_FILE
GIT_NO_REPLACE_OBJECTS
GIT_OBJECT_DIRECTORY
GIT_PREFIX
GIT_REPLACE_REF_BASE
GIT_SHALLOW_FILE
GIT_WORK_TREE
""".split())


def clean_git_env(base=None):
    """返回剔除「仓库绑定」变量的 env 副本，供在 tmp 仓库里跑 git 的 subprocess 使用。

    清单对齐 `git rev-parse --local-env-vars`；作者身份类变量保留。
    """
    env = dict(os.environ if base is None else base)
    for k in list(env):
        if k in _LOCAL_ENV_VARS:
            del env[k]
    return env


@pytest.fixture(autouse=True)
def _isolate_git_local_env(monkeypatch):
    """兜底：抹掉 git 导出的仓库绑定变量，避免子进程误操作主仓（见上方背景）。"""
    for k in _LOCAL_ENV_VARS:
        monkeypatch.delenv(k, raising=False)
    yield
