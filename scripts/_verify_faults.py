"""全场景故障演练：模拟真实赛场故障，验证系统容错能力。

对齐专家锐评「全场景故障演练」：模拟 API 限流、模型超时、工具执行失败、
flag 格式异常、环境连接失败等真实赛场故障，验证系统容错。
不要等到正式比赛第一次遇到故障才手忙脚乱。

演练场景（每个场景输出 PASS/FAIL）：
1. LLM 超时/无响应 → fail-open 返回 None，主 Agent 不死循环
2. API 限流（429）→ RateLimiter 熔断 + 备用 provider
3. 工具执行失败 → 错误分类 tool_failure + 监督 switch_strategy
4. flag 格式异常 → FlagChecker 拦截，反馈循环重试
5. 环境连接失败（网络不通）→ 沙盒返回错误，不拖垮整体
6. 单题死循环 → 预算熔断终止该题

用法：python scripts/_verify_faults.py
"""

import asyncio
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((name, passed, detail))
    mark = "✅ PASS" if passed else "❌ FAIL"
    print(f"  {mark} {name}  {detail}")


# ── 场景 1：LLM 超时/无响应 → fail-open ─────────────────

async def fault_llm_timeout() -> None:
    from llm.client import ai_chat

    # 指向不可达端点模拟超时/失败（fail-open 应返回 None 不抛异常）
    r = ai_chat([{"role": "user", "content": "hi"}],
                max_tokens=5)
    # 无法强制真实超时（本机网络通），改为验证异常注入路径
    from core.main_agent import MainAgent
    from core.supervisor_agent import SupervisorAgent

    class TimeoutLLM:
        async def __call__(self, system, user, attempt):
            raise TimeoutError("模拟 LLM 超时")

    q = _fake_question()
    agent = MainAgent(llm_client=TimeoutLLM(), supervisor=SupervisorAgent())
    out = await agent.solve(q, attempt=0)
    ok = out.get("flag") is None and out.get("error") is not None
    record("LLM 超时 fail-open", ok, f"error={out.get('error')}")


# ── 场景 2：API 限流 → 熔断 + 备用 provider ─────────────

async def fault_rate_limit() -> None:
    # P1-4（2026-08-21 赛后）：scheduler/rate_limiter 已删除——限流/熔断实际由
    # llm/client.py 的 BoundedSemaphore + _PROVIDER_CIRCUITS 承担。此处直接验证
    # llm.client 的熔断器行为（连续 401/402/403 → provider_circuit_open=True）。
    from llm.client import provider_circuit_open, reset_circuits, _circuit_record_failure

    reset_circuits()
    # 模拟 3 次永久故障触发熔断
    _circuit_record_failure("deepseek", 402)
    _circuit_record_failure("deepseek", 402)
    _circuit_record_failure("deepseek", 402)
    ok = provider_circuit_open("deepseek")
    record("API 永久故障熔断", ok, f"deepseek open={ok}")
    reset_circuits()
    record("熔断恢复", not provider_circuit_open("deepseek"))


# ── 场景 3：工具执行失败 → 错误分类 + 监督裁决 ──────────

async def fault_tool_failure() -> None:
    from core.main_agent import MainAgent, StepRecord, ERR_TOOL_FAILURE
    from core.supervisor_agent import SupervisorAgent
    from verify.error_classifier import ErrorClassifier

    # 错误分类
    ec = ErrorClassifier()
    steps = [StepRecord(action="tool:x", observation="ERROR: boom", error_category=ERR_TOOL_FAILURE)] * 2
    cat, _ = ec.classify(steps)
    ok1 = cat == "tool_failure"
    # 监督裁决（工具失败 2 次 → switch_strategy）
    from core.main_agent import AgentContext
    ctx = AgentContext()
    for s in steps:
        ctx.steps.append(s)
    s = SupervisorAgent()
    v = await s.review(ctx)
    ok2 = v.action == "switch_strategy"
    record("工具失败分类+监督裁决", ok1 and ok2,
           f"category={cat} verdict={v.action}")


# ── 场景 4：flag 格式异常 → 拦截 + 重试 ─────────────────

async def fault_flag_format() -> None:
    from verify.flag_checker import FlagChecker
    from verify.feedback import FeedbackLoop
    from eval.cases import load_questions

    q = [x for x in load_questions("data/questions") if x.id == "web-001"][0]
    fc = FlagChecker(q.flag_pattern)

    # 格式异常 flag 应被拦截
    ok1 = not fc.validate("not-a-flag")
    ok2 = fc.validate("flag{sqli_waf_bypass_2026}")

    # 反馈循环：第一次返回格式错误 flag，第二次返回正确
    calls = {"n": 0}
    async def solver(question, attempt, correction=None):
        calls["n"] += 1
        if attempt == 0:
            return {"flag": "wrong_format_without_braces"}
        return {"flag": "flag{sqli_waf_bypass_2026}"}

    loop = FeedbackLoop(checker=fc)
    out = await loop.run(q, solver, max_retries=3)
    ok3 = out.get("flag") == "flag{sqli_waf_bypass_2026}" and calls["n"] == 2
    record("flag 格式拦截+重试", ok1 and ok2 and ok3,
           f"validate_ok={ok2} 重试次数={calls['n']}")


# ── 场景 5：环境连接失败 → 沙盒兜底 ─────────────────────

async def fault_env_failure() -> None:
    from sandbox.subprocess_executor import SubprocessExecutor

    ex = SubprocessExecutor(default_timeout=3)
    # 命令不存在
    r1 = await ex.run("nonexistent_cmd_xyz")
    ok1 = not r1.ok and r1.exit_code != 0
    # 网络不通模拟（无法强制，验证超时兜底）
    r2 = await ex.run("python: import time; time.sleep(10)")
    ok2 = r2.timed_out
    record("环境失败/超时兜底", ok1 and ok2,
           f"cmd_exit={r1.exit_code} timeout={r2.timed_out}")


# ── 场景 6：单题死循环 → 预算熔断 ───────────────────────

async def fault_budget_loop() -> None:
    from scheduler.budget import BudgetTracker, BUDGET_STOP
    from config import AppConfig

    # 小预算模拟死循环
    cfg = AppConfig(per_question_token_budget=100, global_token_budget=1000)
    bt = BudgetTracker(cfg)
    bt.record("q-loop", 60)
    assert bt.check("q-loop") != BUDGET_STOP
    bt.record("q-loop", 60)  # 累计 120 > 100
    ok = bt.check("q-loop") == BUDGET_STOP
    record("死循环预算熔断", ok, f"usage=120 limit=100 -> stop")


def _fake_question():
    from eval.cases import Question

    return Question(
        id="fault-test", title="故障演练题", category="misc",
        description="故障演练用", flag="flag{fault_test_2026}",
    )


async def main() -> None:
    print("=== 全场景故障演练 ===")
    await fault_llm_timeout()
    await fault_rate_limit()
    await fault_tool_failure()
    await fault_flag_format()
    await fault_env_failure()
    await fault_budget_loop()

    failed = [r for r in RESULTS if not r[1]]
    print(f"\n结果: {len(RESULTS) - len(failed)}/{len(RESULTS)} 场景通过")
    if failed:
        for name, _, detail in failed:
            print(f"  ❌ {name}: {detail}")
        print("FAULT_DRILL_FAIL")
        sys.exit(1)
    print("FAULT_DRILL_OK")


if __name__ == "__main__":
    asyncio.run(main())
