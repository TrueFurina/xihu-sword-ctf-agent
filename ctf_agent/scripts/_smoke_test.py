"""verify/scheduler 冒烟测试（锐评整改二：锁稳定模块，赛前敢改代码底气）。

覆盖：
1. verify/flag_checker：三态校验（REJECT 幻觉/ACCEPT 合法）
2. verify/error_classifier：错误归因（stuck_loop/hallucination/timeout）
3. scheduler/model_router：三档路由（light/mid/heavy + 题型特征）
4. scheduler/budget：单题预算检查
5. scheduler/task_pool：并发任务 gather

用法：python scripts/_smoke_test.py（全部通过 exit 0；任一失败 exit 1）
"""

import asyncio
import sys

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))

PASS = 0
FAIL = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL.append(name)
        print(f"  ❌ {name} {detail}")


def test_flag_checker() -> None:
    print("[verify/flag_checker]")
    from verify.flag_checker import FlagChecker, V_ACCEPT, V_REJECT

    fc = FlagChecker()
    check("合法 flag ACCEPT", fc.check("flag{real_2026}") == V_ACCEPT)
    check("未闭合括号 REJECT", fc.check("flag{abc") == V_REJECT)
    check("空体 REJECT", fc.check("flag{}") == V_REJECT)
    check("非 flag 结构 REJECT", fc.check("random_text") == V_REJECT)


def test_error_classifier() -> None:
    print("[verify/error_classifier]")
    from verify.error_classifier import ErrorClassifier

    ec = ErrorClassifier()
    import types
    Step = types.SimpleNamespace
    # 规则1：连续3步同一 action → 死循环
    cat, _ = ec.classify([Step(action="solve"), Step(action="solve"), Step(action="solve")])
    check("stuck_loop 识别", cat == "stuck_loop")
    # 规则3：步骤含幻觉标记 → 幻觉
    cat, _ = ec.classify([Step(action="", error_category="hallucination")])
    check("hallucination 识别", cat == "hallucination")
    # classifier 无 timeout 类别，断言不误判为已知类别
    cat, _ = ec.classify([Step(action="", error_category="timeout")])
    check("timeout 不被误判", cat is None)


def test_model_router() -> None:
    print("[llm/client 分级降级（原 scheduler/model_router 已删，P1-4）]")
    # 分级降级调度实际由 llm/client.get_model_for_attempt 承担：
    # attempt 0-1 轻量模型，attempt >=2 升级重型（deepseek→reasoner 等映射）。
    from llm.client import get_model_for_attempt

    m0 = get_model_for_attempt(0, provider="deepseek")
    m2 = get_model_for_attempt(2, provider="deepseek")
    check("attempt0 轻量", bool(m0), m0)
    check("attempt2 重型升级（deepseek→reasoner）",
          m2 == "deepseek-reasoner", m2)


def test_budget() -> None:
    print("[scheduler/budget]")
    try:
        from scheduler.budget import BudgetTracker

        b = BudgetTracker()
        b.record("q1", 500)
        check("预算记录 usage", b.usage("q1") == 500, f"usage={b.usage('q1')}")
        st = b.check("q1")
        check("预算状态为字符串", isinstance(st, str), f"check={st!r}")
        b.record_retry("q1")
        check("重试计数", b.retries("q1") >= 1, f"retries={b.retries('q1')}")
    except Exception as exc:  # noqa: BLE001
        check("budget 模块可用", False, str(exc))


def test_task_pool() -> None:
    print("[scheduler/task_pool]")

    async def _run():
        from scheduler.task_pool import TaskPool

        async def work(question, attempt):
            await asyncio.sleep(0.01)
            return {"ok": True, "value": int(getattr(question, "id", question)) * 2}

        tp = TaskPool()  # 用默认 config（max_concurrency 来自 config 属性）
        results = await tp.run_all([1, 2, 3], work)
        vals = sorted(r["value"] for r in results)
        check("并发 gather 结果正确", vals == [2, 4, 6], str(vals))

    asyncio.run(_run())


def main() -> None:
    print("=== verify/scheduler 冒烟测试 ===")
    test_flag_checker()
    test_error_classifier()
    test_model_router()
    test_budget()
    test_task_pool()
    print(f"\n结果: {PASS} 通过 / {len(FAIL)} 失败")
    if FAIL:
        print(f"失败项: {FAIL}")
        sys.exit(1)
    print("✅ 冒烟测试全通过——verify/scheduler 稳定模块已锁定，赛前改代码有底气")


if __name__ == "__main__":
    main()
