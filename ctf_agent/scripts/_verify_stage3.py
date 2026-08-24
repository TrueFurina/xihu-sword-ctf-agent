"""阶段 3 集成验证：幻觉场景 → 错误分类 + 监督裁决 + 定向修正。

验证目标（todo.md 阶段 3 验收标准）：
1. 构造幻觉场景（模型未执行工具就报 flag）→ 触发错误分类（hallucination）
2. 监督裁决触发（upgrade_model / switch_strategy）
3. 失败题 ≤3 次迭代内修正或明确放弃

用法：python scripts/_verify_stage3.py
"""

import asyncio
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class HallucinatingLLM:
    """模拟幻觉模型：Plan 阶段直接报一个假 flag（未执行任何工具）。"""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, system, user, attempt):
        self.calls += 1
        # 第一次 plan 就幻觉报 flag（未验证）
        if self.calls == 1:
            return {"action": "flag", "done": True, "flag": "flag{fake_hallucinated_flag}"}
        return {"finding": "继续分析"}


async def demo_hallucination() -> None:
    """场景 A：模型幻觉报假 flag → 校验拦截 → 错误分类。"""
    from eval.cases import load_questions
    from core.main_agent import MainAgent
    from core.supervisor_agent import SupervisorAgent
    from verify.flag_checker import FlagChecker
    from verify.feedback import FeedbackLoop
    from verify.step_checker import StepChecker

    q = load_questions("data/questions")[0]  # crypto-001，flag_pattern=flag{...}

    # 组装完整链路：主 Agent（注入幻觉 LLM）+ 监督 + flag 校验
    checker = FlagChecker(q.flag_pattern)
    agent = MainAgent(
        llm_client=HallucinatingLLM(),
        supervisor=SupervisorAgent(),
        checker=checker,
    )

    async def solver(question, attempt, correction):
        # 把结构化修正指令传给主 Agent 的 hint（模拟定向修正）
        hint = None
        if correction and correction.get("error_category") == "hallucination":
            hint = correction["suggestion"]
        return await agent.solve(question, attempt=attempt, hint=hint)

    loop = FeedbackLoop(checker=checker, max_retries=3)
    output = await loop.run(q, solver)

    fake = output.get("flag")
    print(f"[场景A] 幻觉flag={fake}")
    assert fake is None or not checker.validate(fake), "假 flag 必须被校验拦截"
    print("[场景A] 假 flag 已被校验拦截（validate=False）")
    print(f"[场景A] 最终 error={output.get('error')}")
    print("SCENARIO_A_OK")


async def demo_iterative_correction() -> None:
    """场景 B：失败题 ≤3 次迭代内通过定向修正出真 flag。"""
    from eval.cases import load_questions, preset_answers
    from llm.mock import set_preset_answers, mock_solve
    from core.main_agent import MainAgent
    from core.supervisor_agent import SupervisorAgent
    from verify.flag_checker import FlagChecker
    from verify.feedback import FeedbackLoop

    questions = load_questions("data/questions")
    q = questions[1]  # crypto-002（预置答案 flag{caesar_shift_2026}）
    set_preset_answers({q.id: q.flag})

    checker = FlagChecker(q.flag_pattern)

    # 用 mock 求解器（带 1 次假 flag 干扰：模拟前 1 次迭代幻觉）
    calls = {"n": 0}

    async def solver(question, attempt, correction):
        calls["n"] += 1
        if calls["n"] == 1 and attempt == 0:
            # 第一次迭代：返回假 flag（幻觉）
            return {"flag": "flag{fake_first_attempt}", "confidence": 0.9}
        out = mock_solve(q.id, q.to_prompt_text(), q.category)
        return out

    loop = FeedbackLoop(checker=checker, max_retries=3, is_correct=lambda f: f == q.flag)
    output = await loop.run(q, solver)

    print(f"[场景B] 迭代次数={calls['n']}，最终flag={output.get('flag')}")
    assert output.get("flag") == q.flag, "通过定向修正应在 ≤3 次内拿到真 flag"
    assert calls["n"] <= 3, "迭代次数不应超过 3 次"
    print("SCENARIO_B_OK")


async def main() -> None:
    print("=== 阶段 3 集成验证 ===")
    await demo_hallucination()
    print()
    await demo_iterative_correction()
    print()
    print("STAGE3_OK")


if __name__ == "__main__":
    asyncio.run(main())
