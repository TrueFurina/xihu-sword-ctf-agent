"""阶段 2 集成验证脚本：
1. 5 题并发执行不阻塞（TaskPool + mock 求解器，含部分失败题）
2. 失败题触发监督裁决（MainAgent + SupervisorAgent 集成）

用法：python scripts/_verify_stage2.py
"""

import asyncio
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


async def demo_concurrent() -> None:
    """验证 1：TaskPool 5 题并发（3 题有答案、2 题失败）。"""
    from eval.cases import load_questions, preset_answers
    from llm.mock import set_preset_answers
    from scheduler.task_pool import TaskPool

    questions = load_questions("data/questions")[:5]
    set_preset_answers(preset_answers(questions))

    pool = TaskPool()
    results = await pool.run_all(
        questions,
        lambda q, a: _async_mock_solve(q),
    )
    solved = sum(1 for r in results if r.get("flag"))
    print(f"[并发] 5 题并发完成，解出 {solved}/5")
    for r in results:
        print(f"  {r['task_id']}: flag={r.get('flag')} 耗时={r.get('duration_ms')}ms")
    assert solved >= 3, "并发场景应有 3 题解出（预置答案）"
    assert all(isinstance(r.get("duration_ms"), int) for r in results), "应有耗时记录"


async def _async_mock_solve(q):
    from llm.mock import mock_solve

    return mock_solve(q.id, q.to_prompt_text(), q.category)


async def demo_supervision() -> None:
    """验证 2：失败题经 MainAgent 触发监督裁决（确定性规则兜底 → upgrade_model）。"""
    from eval.cases import load_questions
    from core.main_agent import MainAgent
    from core.supervisor_agent import SupervisorAgent

    # 取一道题，注入一个"永远失败"的 llm_client
    q = load_questions("data/questions")[0]

    class AlwaysFailLLM:
        """模拟 LLM 一直返回空推理结果（触发监督裁决升级路径）。

        返回空 finding → 主 Agent 观察为空 → 归类 hallucination →
        stuck_count 累计 → 监督规则触发升级。
        """

        async def __call__(self, system, user, attempt):
            return {"finding": ""}

    class ControlledSupervisor(SupervisorAgent):
        """受控监督：规则不命中时返回升级裁决（避免测试依赖真实 API）。"""

        async def review(self, ctx):
            verdict = self._rule_based_review(ctx)
            if verdict is not None:
                return verdict
            # 无规则命中但已有多步无进展 → 升级（模拟轻量模型裁决）
            if len(ctx.steps) >= 2 and ctx.stuck_count >= 1:
                from core.main_agent import SupervisionVerdict, VERDICT_UPGRADE

                return SupervisionVerdict(
                    action=VERDICT_UPGRADE,
                    reason="受控监督：多步无进展，升级重型模型",
                    suggestion="升级到重型模型重试",
                )
            from core.main_agent import SupervisionVerdict, VERDICT_CONTINUE

            return SupervisionVerdict(action=VERDICT_CONTINUE, reason="继续")

    agent = MainAgent(
        llm_client=AlwaysFailLLM(),
        supervisor=ControlledSupervisor(),
    )
    output = await agent.solve(q, attempt=0)
    print(f"[监督] 题目 {q.id}: flag={output.get('flag')} error={output.get('error')}")
    print(f"[监督] provider={output.get('provider')} retries={output.get('retries')}")
    # 永远失败的题：不应解出 flag，且最终 provider 应为重型模型（触发升级）
    assert output.get("flag") is None, "失败题不应解出 flag"
    assert output.get("provider") == "deepseek-v4-pro", "连续失败应升级到重型模型"


async def main() -> None:
    print("=== 阶段 2 集成验证 ===")
    await demo_concurrent()
    print()
    await demo_supervision()
    print()
    print("STAGE2_OK")


if __name__ == "__main__":
    asyncio.run(main())
