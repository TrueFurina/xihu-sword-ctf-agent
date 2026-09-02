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
