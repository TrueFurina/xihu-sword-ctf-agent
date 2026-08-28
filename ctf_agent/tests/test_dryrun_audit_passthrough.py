# -*- coding: utf-8 -*-
"""M2-AUDIT-INJECT 回归：presolve 写入的 web_audit_report 必须回写到 dryrun 共享 qdict。

修复前：run_presolve 用 `q = Question.from_dict(qdict)` 新建对象，presolve 把报告写进
q.extra，但 qdict 不变；run_llm_agent 又 `Question.from_dict(qdict)` 重建对象 →
LLM 阶段 extra 为空、prompts.py 读不到 web_audit_report。
修复后：run_presolve 结束前把 q.extra 合并回 qdict["extra"]，下游 from_dict 即可拿到。
"""
import asyncio
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts._dryrun_race import run_presolve  # noqa: E402


def test_run_presolve_passes_presolve_extra_back_to_qdict():
    """presolve 在 q.extra 写入 web_audit_report，run_presolve 应回写共享 qdict。"""
    qdict = {
        "id": "t_web_audit", "category": "web", "title": "t",
        "description": "web source audit", "attachments": [], "extra": {},
    }

    async def _fake_presolve(q, **kw):
        q.extra["web_audit_report"] = "FOUND backdoor eval() in upload.php"
        return None

    with patch("core.presolve.presolve", _fake_presolve):
        res = asyncio.run(run_presolve(qdict, SimpleNamespace(registry=None)))

    assert res["method"] == "presolve_miss"  # 没解出 flag，正常
    assert qdict.get("extra", {}).get("web_audit_report") == \
        "FOUND backdoor eval() in upload.php"


def test_run_presolve_flag_short_circuit_still_writes_extra():
    """即便 presolve 解出 flag 走短路返回，也应先回写 extra。"""
    qdict = {
        "id": "t2", "category": "web", "title": "t2",
        "description": "x", "attachments": [], "extra": {},
    }

    async def _fake_presolve(q, **kw):
        q.extra["web_audit_report"] = "report-2"
        return "flag{fake}"

    with patch("core.presolve.presolve", _fake_presolve):
        res = asyncio.run(run_presolve(qdict, SimpleNamespace(registry=None)))

    assert res["flag"] == "flag{fake}"
    assert qdict.get("extra", {}).get("web_audit_report") == "report-2"
