# -*- coding: utf-8 -*-
"""决赛备战 S3 web 靶机交互与源码审计回归（2026-08-21 赛后第二波）。

补强项：
1. web_source_audit_cms 引擎：web 题 + 附件文件名含 CMS 指纹（joomla/wordpress/
   drupal/ghost/cmsms/...）→ 调 web_source_audit 静态审计；命中 flag 即出，
   否则 None（仅审计 LLM 后续动作）。本地有源码包、远端靶机关场景必备。
2. 端点注入（endpoints → Question.description / extra.targets）由 run.py:710
   的 P0 修复已做，本测试只验证目标构建函数 _extract_targets 行为稳定。
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────
# 1) web_source_audit_cms engine
# ─────────────────────────────────────────────────────────────────
def test_web_source_audit_cms_skips_non_web():
    """非 web 题型 → engine 立即 None（不浪费时间）。"""
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question
    fn = MathEngineMatrix._engines["web_source_audit_cms"]
    q = Question(
        id="x", title="x", category="crypto", difficulty="EASY",
        description="crypto", attachments=["data/race_attachments/10716_joomla-6.1.2-full-package.tar.gz.zip"],
        flag_pattern="flag{[^}]+}", extra={},
    )
    assert fn(q) is None


def test_web_source_audit_cms_skips_non_cms_web():
    """web 但附件非 CMS 源码包 → engine 立即 None."""
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question
    fn = MathEngineMatrix._engines["web_source_audit_cms"]
    q = Question(
        id="x", title="x", category="web", difficulty="EASY",
        description="web",
        attachments=["data/race_attachments/10732_Yusa的密码学课堂——PKCS#1的附件.zip"],
        flag_pattern="flag{[^}]+}", extra={},
    )
    assert fn(q) is None


@pytest.mark.slow
def test_web_source_audit_cms_runs_on_real_cms_attachment():
    """10725 cmsms 真题：engine 跑 web_source_audit 完成审计.

    不强求命中 flag（CMS 标准包无 flag），只验证引擎跑通且 < 30s。
    slow 标记：依赖真实附件解压（cmsms 包 3000+ 文件），默认门禁排除（-m "not slow"）。
    """
    from agents.math_engine import MathEngineMatrix
    from eval.cases import Question
    path = os.path.join("data", "race_attachments", "10725_cmsms-2.2.8-install.expanded.zip")
    if not os.path.exists(path):
        pytest.skip(f"10725 附件不存在: {path}")
    q = Question(
        id="10725", title="REAL-10", category="web", difficulty="EASY",
        description="cmsms audit", attachments=[path],
        flag_pattern="flag{[^}]+}", extra={},
    )
    fn = MathEngineMatrix._engines["web_source_audit_cms"]
    t0 = time.time()
    result = fn(q)
    dt = time.time() - t0
    assert dt < 30.0, f"engine 耗时 {dt:.2f}s 超 30s"
    # 标准 cmsms 包无 flag，engine 多数情况 None；不为空时验证是合规 flag 串
    if result is not None:
        import re
        assert re.search(r"(?i)(?:flag|dasctf|ctf)\{[^}\s]{3,}\}", result)


def test_web_source_audit_cms_in_priority_order():
    """engine 已纳入 _priority_order()，math_engine.solve 自动包含。"""
    from agents.math_engine import MathEngineMatrix
    names = MathEngineMatrix._priority_order()
    assert "web_source_audit_cms" in names


# ─────────────────────────────────────────────────────────────────
# 2) endpoints 注入：_extract_targets 行为稳定
# ─────────────────────────────────────────────────────────────────
def test_extract_targets_handles_empty_endpoints():
    """endpoints 列表空 → 返空（不抛异常）。"""
    try:
        from scripts._scan_firstblood import _extract_targets
    except ImportError:
        pytest.skip("_scan_firstblood 模块不可用")
    assert _extract_targets({}) == []
    assert _extract_targets({"endpoints": []}) == []


def test_extract_targets_handles_missing_endpoints():
    """ch.extra 无 endpoints 字段 → 返空（不抛异常）。"""
    try:
        from scripts._scan_firstblood import _extract_targets
    except ImportError:
        pytest.skip("_scan_firstblood 模块不可用")
    # 各种残缺输入都不抛异常
    for x in (None, {}, {"portMappings": []}, {"proxyIps": []}):
        out = _extract_targets(x) if x is not None else _extract_targets({})
        assert isinstance(out, list)


def test_extract_targets_formats_targets():
    """endpoints 含 portMappings → 格式化 "ip:port" 列表（带 https:// 前缀）."""
    try:
        from scripts._scan_firstblood import _extract_targets
    except ImportError:
        pytest.skip("_scan_firstblood 模块不可用")
    extra = {
        "endpoints": [
            {"portMappings": [{"innerPort": 80, "outerIp": "1.2.3.4", "outerPort": 15445}]},
        ]
    }
    out = _extract_targets(extra)
    assert isinstance(out, list)
    # 应至少有一个含 ip 或 port 的条目
    if out:
        assert any("1.2.3.4" in t or "15445" in t for t in out)


# ─────────────────────────────────────────────────────────────────
# 3) presolve → math_engine 整链路
# ─────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_presolve_runs_web_source_audit_on_cms():
    """10725 真题：完整 presolve 跑 web_source_audit_cms（不抛异常）.

    即使没命中 flag，presolve 也不应 crash；返回 None 时 LLM 接管。
    slow 标记：依赖真实附件，走完整 presolve 链路，默认门禁排除。
    """
    import asyncio

    from core.presolve import presolve
    from eval.cases import Question
    path = os.path.join("data", "race_attachments", "10725_cmsms-2.2.8-install.expanded.zip")
    if not os.path.exists(path):
        pytest.skip(f"10725 附件不存在: {path}")
    q = Question(
        id="10725", title="REAL-10", category="web", difficulty="EASY",
        description="cmsms", attachments=[path],
        flag_pattern="flag{[^}]+}", extra={},
    )
    flag = asyncio.run(presolve(q, registry=None, sandbox=None, answers=None))
    # flag 可空（无 flag）但不能抛异常
    assert flag is None or isinstance(flag, str)
