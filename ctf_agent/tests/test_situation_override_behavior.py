"""态势接管闸门 行为级集成测试（确定性 mock，零 LLM）。

锁定的行为契约：
- CTF_AGENT_SITUATION_OVERRIDE=1 时，低信心(<0.3)+过半预算的振荡题会**提前**
  咨询既有监督（_supervise）换策略并解出，空转步数 < 关闭态。
- 默认关闭(=0)时，该闸门完全不介入：振荡低信心（每步换动作但不报错→旧
  stuck_count>=2 不触发）会空转到预算耗尽，从不咨询监督 → 失败。

这是对 race-intelligence 闸门在真实 solve 控制流内**接线与触发时序**的回归保护，
区别于 core/confidence.should_early_switch 的纯函数单测。
"""
import asyncio
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts._bench_situation_override import run_scenario, _assertions  # noqa: E402


def test_override_on_solves_early_via_supervisor():
    on = asyncio.run(run_scenario(True))
    assert on["solved"] is True, f"OVERRIDE=ON 应解出，得到 flag={on['flag']}"
    # 闸门把常规 CONTINUE 监督强制推成纠正性 SWITCH（override 的真实贡献）
    assert on["corrective_calls"] >= 1, "OVERRIDE=ON 应产生纠正性 SWITCH"
    assert on["first_corrective_step"] is not None
    assert on["first_corrective_step"] <= on["budget"] // 2, (
        f"纠正触发过晚：步 {on['first_corrective_step']} > 预算半 {on['budget'] // 2}")
    # 解出发生在控制流内（下一步产出 flag），无需烧完整预算
    assert on["total_steps"] < on["budget"]


def test_override_off_never_forces_switch_and_fails():
    off = asyncio.run(run_scenario(False))
    assert off["solved"] is False, "OVERRIDE=OFF 应空转到预算耗尽失败"
    # 默认关：常规每2步监督咨询全部 CONTINUE，不产生纠正性 SWITCH（零回归）
    assert off["corrective_calls"] == 0, "OVERRIDE=OFF 不应产生纠正性 SWITCH"
    # 旧 stuck_count>=2 逻辑对"换动作但不报错"的振荡无效 → 烧满预算
    assert off["total_steps"] == off["budget"]


def test_override_reduces_idle_steps():
    on = asyncio.run(run_scenario(True))
    off = asyncio.run(run_scenario(False))
    problems = _assertions(on, off)
    assert not problems, "A/B 断言失败:\n  " + "\n  ".join(problems)
    assert on["idle_steps"] < off["idle_steps"], (
        f"OVERRIDE=ON 空转步应更少：{on['idle_steps']} vs {off['idle_steps']}")


def teardown_module(module):
    # 还原默认（关闭），避免污染其它测试的环境
    os.environ["CTF_AGENT_SITUATION_OVERRIDE"] = "0"
