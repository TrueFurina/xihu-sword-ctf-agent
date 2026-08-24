"""verify_discipline：验证纪律机制（2026-08-22——最大风险「写了≠解出」的解决）。

反思总结的最大风险：模板/增强写了但没真实解出题（正式赛 0 解出/整改无效/
增强无效都是它）。本模块固化为可执行检查：
- 任何新模板/增强——必须用真实题（或标准样例）验证解出数提升——才算通过
- 提供 validate_improvement()——跑旧/新解出对比——解出数不提升 = 不通过

用法：
    from tools.verify_discipline import validate_improvement
    ok, old_n, new_n = validate_improvement("新模板名", extra_solve_fn)
    # ok=False 且 new_n <= old_n → 该增强无效——不得声称有效
"""

import time


def validate_improvement(name: str, baseline_solved: int, new_solved: int,
                         sample_size: int, detail: str = "") -> dict:
    """验证增强是否带来真实解出数提升。

    Args:
        name: 增强/模板名
        baseline_solved: 增强前真实解出数
        new_solved: 增强后真实解出数
        sample_size: 题库规模
        detail: 说明
    Returns:
        {"ok": 是否通过, "delta": 增量, "verdict": 结论}
    """
    delta = new_solved - baseline_solved
    ok = delta > 0  # 唯一标准：解出数必须提升
    verdict = (
        f"✅ {name}: {baseline_solved}→{new_solved}（+{delta}/{sample_size}）"
        f"——真实提升——通过" if ok else
        f"❌ {name}: {baseline_solved}→{new_solved}（+{delta}/{sample_size}）"
        f"——无提升——不通过（写了≠解出）"
    )
    print(verdict, flush=True)
    if detail:
        print(f"   说明: {detail}", flush=True)
    return {"ok": ok, "delta": delta, "verdict": verdict}


def require_proof(baseline_solved: int, sample_size: int) -> callable:
    """生成「解出数提升才算数」的检查器（防信誓旦旦无证据）。"""
    def checker(name: str, new_solved: int, detail: str = "") -> dict:
        return validate_improvement(name, baseline_solved, new_solved,
                                    sample_size, detail)
    return checker


if __name__ == "__main__":
    # 自测：验证纪律
    print("— 验证纪律自测 —", flush=True)
    validate_improvement("示例有效增强", 13, 15, 60, "附件题扫描 +2")
    validate_improvement("示例无效增强", 13, 13, 60, "只写了模板没解出新题")
