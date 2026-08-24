"""单页看板后端：FastAPI 端点（进度/耗时/flag/报表）。

v2.0 精简方案：单页 HTML + 原生 JS 轮询，半天完成，演示效果足够。
- POST /api/tasks       批量导入赛题 → 触发并发解题
- GET  /api/tasks       任务列表 + 实时进度
- GET  /api/tasks/{id}  单题详情
- GET  /api/metrics     解出率报表
- GET  /                看板首页（内嵌 HTML）
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="CTF-Agent 看板", version="0.2.0")

# ── 任务状态（B-18 决赛加固：内存 + 文件持久化 + 运行锁）──
_tasks: dict[str, dict] = {}
_running = False               # 运行锁标志：防并发 POST 重复解题（双烧 LLM 额度）
_state_loaded = False
_STATE_FILE = Path("data/results/dashboard_tasks.json")


def _load_state() -> None:
    """启动/导入时从磁盘恢复任务状态（看板重启后可恢复进度）。"""
    global _state_loaded, _tasks
    if _state_loaded:
        return
    _state_loaded = True
    try:
        if _STATE_FILE.is_file():
            data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                _tasks = {k: v for k, v in data.items()
                          if isinstance(v, dict) and v.get("task_id")}
    except Exception as exc:  # noqa: BLE001 - 状态文件损坏不影响启动
        logger.warning("看板状态文件加载失败（忽略）: %s", exc)


def _save_state() -> None:
    """任务状态落盘（临时文件 + 原子替换，防写一半损坏）。"""
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _STATE_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(_tasks, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(_STATE_FILE)
    except Exception as exc:  # noqa: BLE001
        logger.warning("看板状态保存失败: %s", exc)
_solver_fn = None          # callable(question, attempt, correction)
_question_loader = None    # callable() -> list[Question]
_results: list[dict] = []
_coordinator = None        # core.intervention.InterventionCoordinator（可选）
_use_mock = False          # True=Mock 演示假解（不代表真实解题能力）；由 run.py 透传


class TaskIn(BaseModel):
    """批量导入赛题请求体。"""

    question_ids: Optional[list[str]] = None   # None=全部题库
    category: Optional[str] = None             # 仅某题型


class TaskOut(BaseModel):
    task_id: str
    category: str = ""
    title: str = ""
    status: str = "pending"    # pending/running/solved/failed
    flag: Optional[str] = None
    duration_ms: int = 0
    retries: int = 0
    error: Optional[str] = None
    need_human: bool = False   # 卡壳待人工介入
    human_reason: str = ""


class HintIn(BaseModel):
    hint: str   # 定向提示内容（非空）


def configure(solver_fn, question_loader, coordinator=None, use_mock: bool = False) -> None:
    """注入求解器与题库加载器（由 run.py 调用）。"""
    global _solver_fn, _question_loader, _coordinator, _use_mock
    _solver_fn = solver_fn
    _question_loader = question_loader
    _coordinator = coordinator
    _use_mock = use_mock


async def _run_all() -> None:
    """后台并发执行全部任务（TaskPool 思路的精简版）。

    B-18 加固：运行标志锁——_run_all 已在跑则直接返回，杜绝并发 POST
    触发重复解题双烧 LLM 额度；进入前从磁盘恢复历史状态。
    """
    global _running
    if _running:
        logger.info("_run_all 已在运行，忽略重复触发")
        return
    _running = True
    _load_state()
    try:
        await _run_all_inner()
    finally:
        _running = False


async def _run_all_inner() -> None:
    """后台并发执行全部任务（原逻辑，被 _run_all 锁保护）。"""
    global _tasks
    questions = _question_loader() if _question_loader else []
    sem = asyncio.Semaphore(8)
    pending = [t for t in _tasks.values() if t["status"] == "pending"]

    async def run_one(task: dict):
        async with sem:
            task["status"] = "running"
            q = next((q for q in questions if q.id == task["task_id"]), None)
            if q is None or _solver_fn is None:
                task["status"] = "failed"
                task["error"] = "题目不存在或求解器未配置"
                return
            try:
                out = await _solver_fn(q, 0, None)
                # P2-1 修复（2026-08-21）：solved 判定改为优先 validated（真实校验结果），
                # 而非 flag 非空——杜绝"未通过正确性校验的幻觉 flag"被标成 solved 虚高。
                # mock 模式（无 validated 字段）退化为 flag 非空（保持原有开发期行为）。
                _v = out.get("validated")
                task["status"] = "solved" if (_v if _v is not None else bool(out.get("flag"))) else "failed"
                task["flag"] = out.get("flag")
                task["duration_ms"] = out.get("duration_ms", 0)
                task["retries"] = out.get("retries", 0)
                task["error"] = (out.get("error") or {}).get("detail") if out.get("error") else None
                _results.append(out)
            except Exception as exc:  # noqa: BLE001
                task["status"] = "failed"
                task["error"] = str(exc)
            finally:
                # 同步人工干预状态（卡壳标记 → 看板展示）
                if _coordinator is not None:
                    st = _coordinator.status(task["task_id"])
                    task["need_human"] = st["need_human"]
                    task["human_reason"] = st["reason"]
                _save_state()  # B-18：每任务结束即落盘（重启可恢复）

    if pending:
        await asyncio.gather(*[run_one(t) for t in pending])


@app.post("/api/tasks", response_model=list[TaskOut])
async def create_tasks(payload: TaskIn) -> list[TaskOut]:
    """批量导入赛题并触发后台并发求解。"""
    _load_state()  # B-18：重启后先恢复历史状态再合并
    questions = _question_loader() if _question_loader else []
    selected = questions
    if payload.category:
        selected = [q for q in selected if q.category == payload.category]
    if payload.question_ids:
        selected = [q for q in selected if q.id in payload.question_ids]

    for q in selected:
        _tasks[q.id] = {
            "task_id": q.id,
            "category": q.category,
            "title": q.title,
            "status": "pending",
            "flag": None,
            "duration_ms": 0,
            "retries": 0,
            "error": None,
        }
    _save_state()  # B-18：导入即落盘
    asyncio.create_task(_run_all())
    return [_task_out(t) for t in _tasks.values()]


@app.get("/api/tasks", response_model=list[TaskOut])
async def list_tasks() -> list[TaskOut]:
    return [_task_out(t) for t in _tasks.values()]


@app.get("/api/tasks/{task_id}", response_model=TaskOut)
async def get_task(task_id: str) -> TaskOut:
    t = _tasks.get(task_id)
    if t is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return _task_out(t)


@app.get("/api/metrics")
async def metrics() -> dict:
    """解出率报表（评委打分用）。"""
    total = len(_tasks)
    solved = sum(1 for t in _tasks.values() if t["status"] == "solved")
    by_category: dict[str, dict] = {}
    for t in _tasks.values():
        b = by_category.setdefault(t["category"], {"total": 0, "solved": 0})
        b["total"] += 1
        b["solved"] += 1 if t["status"] == "solved" else 0
    for b in by_category.values():
        b["solve_rate"] = round(b["solved"] / b["total"], 3) if b["total"] else 0.0
    return {
        "total": total,
        "solved": solved,
        "solve_rate": round(solved / total, 3) if total else 0.0,
        "by_category": by_category,
    }


@app.get("/api/mode")
async def mode() -> dict:
    """运行模式自检：暴露 MOCK/真实 LLM、provider 与白名单强制状态。

    修复项 #4（看板 Mock 假解可见性）：让前端能显式警示"当前为假解演示"，
    杜绝锐评指出的演示自欺风险。
    """
    import os as _os

    from config import AppConfig

    try:
        _cfg = AppConfig.from_env()
        provider = _cfg.llm_provider
    except Exception:
        provider = _os.getenv("CTF_AGENT_LLM_PROVIDER", "deepseek")
    return {
        "mode": "MOCK（演示假解）" if _use_mock else "真实 LLM",
        "use_mock": _use_mock,
        "llm_provider": provider,
        "whitelist_enforced": _os.getenv("CTF_AGENT_ALLOW_OFF_WHITELIST", "0") != "1",
        "note": (
            "⚠️ 当前为 MOCK 演示模式，解出的 flag 为预置假解，不代表真实解题能力，"
            "切勿用于验收/评委演示！"
            if _use_mock else ""
        ),
    }


@app.get("/api/interventions")
async def list_interventions() -> list[dict]:
    """等待人工介入的任务列表（卡壳标记；初赛现场人工可实时介入）。"""
    if _coordinator is None:
        return []
    return _coordinator.pending_tasks()


@app.post("/api/tasks/{task_id}/hint", response_model=dict)
async def inject_hint(task_id: str, payload: HintIn) -> dict:
    """人工向运行中的任务注入定向提示（高优先级上下文，Agent 下步生效）。"""
    if _coordinator is None:
        raise HTTPException(status_code=503, detail="干预协调器未配置")
    ok = _coordinator.inject_hint(task_id, payload.hint)
    if not ok:
        raise HTTPException(status_code=422, detail="提示内容不能为空")
    return {"ok": True, "task_id": task_id}


@app.post("/api/tasks/{task_id}/resolve", response_model=dict)
async def resolve_task(task_id: str) -> dict:
    """人工介入完成，清除卡壳标记。"""
    if _coordinator is None:
        raise HTTPException(status_code=503, detail="干预协调器未配置")
    _coordinator.clear_human_flag(task_id)
    if task_id in _tasks:
        _tasks[task_id]["need_human"] = False
        _tasks[task_id]["human_reason"] = ""
    return {"ok": True, "task_id": task_id}


@app.get("/")
async def index():
    index_path = Path(__file__).parent / "static" / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    return {"msg": "看板页面缺失，请检查 web/static/index.html"}


def _task_out(t: dict) -> TaskOut:
    return TaskOut(
        task_id=t["task_id"],
        category=t.get("category", ""),
        title=t.get("title", ""),
        status=t["status"],
        flag=t.get("flag"),
        duration_ms=t.get("duration_ms", 0),
        retries=t.get("retries", 0),
        error=t.get("error"),
        need_human=t.get("need_human", False),
        human_reason=t.get("human_reason", ""),
    )
