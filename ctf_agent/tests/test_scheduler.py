# -*- coding: utf-8 -*-
"""scheduler/ 模块冒烟测试（BudgetTracker 熔断 + TaskPool）——锐评 P0 整改。

P1-4（2026-08-21 赛后）：RateLimiter/ModelRouter 生产链路零引用（分级降级
调度/熔断实际由 llm/client.py 的 BoundedSemaphore + _PROVIDER_CIRCUITS 承担），
已删除 scheduler/rate_limiter.py 与 scheduler/model_router.py；本文件同步移除
对应测试，保留 budget/task_pool 两处真实生效模块。
"""
import sys, os, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import AppConfig
from scheduler.budget import BudgetTracker, BUDGET_OK, BUDGET_STOP
from scheduler.task_pool import TaskPool

def test_budget_tracker():
    cfg = AppConfig.from_env()
    # 极小预算验证三态（注意 downgrade 阈值 = per_question × ratio）
    cfg.per_question_token_budget = 1000
    cfg.global_token_budget = 10000
    bt = BudgetTracker(cfg)
    assert bt.check("q1") == BUDGET_OK
    bt.record("q1", 300)  # 300 < 500（1000×0.5）→ OK
    assert bt.check("q1") == BUDGET_OK
    bt.record("q1", 400)  # 累计 700 >= 500 → DOWNGRADE
    from scheduler.budget import BUDGET_DOWNGRADE
    assert bt.check("q1") == BUDGET_DOWNGRADE
    bt.record("q1", 400)  # 累计 1100 >= 1000 → 单题熔断 STOP
    assert bt.check("q1") == BUDGET_STOP
    # 全局熔断（global=10000）
    bt2 = BudgetTracker(cfg)
    bt2.record("g1", 6000)
    bt2.record("g2", 6000)  # 全局 12000 >= 10000
    assert bt2.check("q1") == BUDGET_STOP
    print("✓ test_budget_tracker")

def test_task_pool():
    pool = TaskPool()
    assert pool.max_concurrency >= 1
    # 并发跑 3 个假 solver，验证结果顺序与输入一致
    async def solver(q, attempt, correction=None):
        return {"task_id": q, "flag": f"flag{{{q}}}"}
    async def main():
        results = await pool.run_all(["a", "b", "c"], solver)
        return results
    results = asyncio.run(main())
    assert [r["task_id"] for r in results] == ["a", "b", "c"]
    assert all(r["flag"] for r in results)
    print("✓ test_task_pool")

if __name__ == "__main__":
    test_budget_tracker()
    test_task_pool()
    print("=== scheduler 冒烟测试全部通过 ===")
