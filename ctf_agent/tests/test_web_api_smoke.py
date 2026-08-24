# -*- coding: utf-8 -*-
"""看板 API 冒烟测试（P1 补强，2026-08-21）。

背景：此前 web/server.py（217 行看板 API）零测试。本文件用 FastAPI TestClient 覆盖：
- GET  /api/tasks       列表字段完整性（task_id/status/title/category/flag/...）
- GET  /api/tasks/{id}  200 与 404
- GET  /api/metrics     total/solved/solve_rate/by_category 字段
- POST /api/tasks       200 + 返回体字段完整性 + 触发后台求解

若 fastapi/httpx TestClient 不可用则整文件 skip 并注明。TestClient 是同步入口，
不依赖 pytest-asyncio。
"""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastapi.testclient import TestClient
    from web import server as ws
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - 依赖缺失时整文件 skip
    TestClient = None
    ws = None
    _IMPORT_ERR = exc

pytestmark = pytest.mark.skipif(
    TestClient is None,
    reason=f"fastapi TestClient 不可用（{_IMPORT_ERR}），跳过看板 API 冒烟测试",
)


@pytest.fixture(autouse=True)
def _reset_state():
    """每用例重置看板内存状态（server 模块级单例）。"""
    ws._tasks = {}
    ws._results = []
    ws._coordinator = None
    yield


def _seed(task_id, status="solved", category="crypto", title="T", flag=None,
          need_human=False, human_reason=""):
    ws._tasks[task_id] = {
        "task_id": task_id, "category": category, "title": title, "status": status,
        "flag": flag, "duration_ms": 0, "retries": 0, "error": None,
        "need_human": need_human, "human_reason": human_reason,
    }


# ── GET /api/tasks ────────────────────────────────────────


def test_tasks_list_field_completeness():
    client = TestClient(ws.app)
    _seed("t1", status="solved", flag="flag{x}")
    _seed("t2", status="pending", category="web", title="W2")
    resp = client.get("/api/tasks")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2
    for item in items:
        for field in ("task_id", "category", "title", "status", "flag",
                      "duration_ms", "retries", "error", "need_human", "human_reason"):
            assert field in item, f"字段缺失: {field}"
    by_id = {it["task_id"]: it for it in items}
    assert by_id["t1"]["status"] == "solved"
    assert by_id["t2"]["status"] == "pending"


def test_task_detail_ok_and_404():
    client = TestClient(ws.app)
    _seed("t1", status="solved", flag="flag{x}")
    ok = client.get("/api/tasks/t1")
    assert ok.status_code == 200
    assert ok.json()["task_id"] == "t1"
    missing = client.get("/api/tasks/nope")
    assert missing.status_code == 404


# ── GET /api/metrics ──────────────────────────────────────


def test_metrics_empty():
    client = TestClient(ws.app)
    resp = client.get("/api/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["solved"] == 0
    assert body["solve_rate"] == 0.0
    assert body["by_category"] == {}


def test_metrics_field_completeness_with_solved():
    client = TestClient(ws.app)
    _seed("t1", status="solved", category="crypto")
    _seed("t2", status="pending", category="crypto")
    _seed("t3", status="failed", category="web")
    resp = client.get("/api/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert body["solved"] == 1
    assert body["solve_rate"] == round(1 / 3, 3)
    bc = body["by_category"]
    assert set(bc) == {"crypto", "web"}
    assert bc["crypto"] == {"total": 2, "solved": 1, "solve_rate": 0.5}
    assert bc["web"] == {"total": 1, "solved": 0, "solve_rate": 0.0}


# ── POST /api/tasks ───────────────────────────────────────


def _fake_loader():
    return [
        SimpleNamespace(id="q1", category="crypto", title="Q1"),
        SimpleNamespace(id="q2", category="web", title="Q2"),
    ]


async def _fake_solver(q, attempt, correction):
    return {"flag": "flag{ok}", "validated": True, "duration_ms": 1, "retries": 0}


def test_post_tasks_200_and_field_completeness():
    client = TestClient(ws.app)
    ws.configure(_fake_solver, _fake_loader)
    resp = client.post("/api/tasks", json={})
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) == 2
    for item in items:
        assert "task_id" in item
        assert "status" in item
        assert item["status"] in ("pending", "running", "solved", "failed")
    ids = {it["task_id"] for it in items}
    assert ids == {"q1", "q2"}


def test_post_tasks_filter_by_question_ids():
    client = TestClient(ws.app)
    ws.configure(_fake_solver, _fake_loader)
    resp = client.post("/api/tasks", json={"question_ids": ["q2"]})
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["task_id"] == "q2"
