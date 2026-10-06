"""P1 墙钟对齐回归（2026-10-06）。

根因：Agent 内部墙钟默认 300s（config.per_question_wallclock），评测层
``asyncio.wait_for(_out, timeout=args.wallclock)`` 在 180s 处取消整题 →
Agent 永远等不到自己收尾被外部杀（glm 三题 180s/0token 即此因）。

修复：评测 ``--wallclock`` 经 ``build_solver(wallclock=...)`` 下传到
``MainAgent(per_question_wallclock=, hard_wallclock=)``，两分支（普通/HARD）均
收敛到 ``min(默认, 评测墙钟-30s 余量)``，保证 Agent 优雅自止于评测 wait_for 之前。

本文件测核心纯函数 ``run._align_wallclock_to_eval`` 的契约，含变异验证
（变异后测试必变红，见 test 运行时的 mutation 检查步骤）。
"""
from run import _align_wallclock_to_eval, build_solver


def test_align_below_default_shrinks_both_branches():
    """评测 180 < 默认(300/480) → 两分支收敛到 150（180-30 余量）。"""
    per_q, hard = _align_wallclock_to_eval(180, 300, 480)
    assert per_q == 150.0, per_q
    assert hard == 150.0, hard


def test_align_above_default_preserves_config():
    """评测 600 ≥ 默认(300/480) → 原样保留，不误伤长窗口真跑。"""
    per_q, hard = _align_wallclock_to_eval(600, 300, 480)
    assert per_q == 300.0
    assert hard == 480.0


def test_align_equal_default_shrinks_by_margin():
    """评测 300 == 默认 per_q → 收敛到 270（留 30s 余量）。"""
    per_q, hard = _align_wallclock_to_eval(300, 300, 480)
    assert per_q == 270.0
    assert hard == 270.0


def test_align_missing_eval_returns_default():
    """评测墙钟缺失(None) → 原样保留默认（其余调用方不受影响）。"""
    per_q, hard = _align_wallclock_to_eval(None, 300, 480)
    assert (per_q, hard) == (300, 480)


def test_align_zero_eval_returns_default():
    """评测墙钟=0（非法）→ 原样保留默认。"""
    per_q, hard = _align_wallclock_to_eval(0, 300, 480)
    assert (per_q, hard) == (300, 480)


def test_align_small_eval_floors_at_30():
    """评测 120 → 余量 max(30, 90)=90 → 两分支收敛到 90。"""
    per_q, hard = _align_wallclock_to_eval(120, 300, 480)
    assert per_q == 90.0
    assert hard == 90.0


def test_align_never_exceeds_eval_cap():
    """对齐后两分支严格 ≤ 评测墙钟-30（留余量，保证 Agent 先于评测 wait_for 自止）。"""
    for eval_wc in (60, 100, 180, 240, 300, 600):
        per_q, hard = _align_wallclock_to_eval(eval_wc, 300, 480)
        cap = max(30.0, eval_wc - 30.0)
        assert per_q <= cap, (eval_wc, per_q, cap)
        assert hard <= cap, (eval_wc, hard, cap)


def test_build_solver_passes_aligned_wallclock_to_agent(monkeypatch):
    """集成验证（零 LLM 调用）：eval 传 --wallclock 180 → build_solver → MainAgent
    收到对齐后墙钟(150,150)；HARD 分支(默认480)同样被收敛。构造真实工具层但不触发 LLM。"""
    import core.main_agent as _ma_mod
    _Real = _ma_mod.MainAgent
    _captured = {}

    class _Recorder(_Real):
        def __init__(self, *a, **kw):
            _captured.update(kw)
            super().__init__(*a, **kw)

    monkeypatch.setattr(_ma_mod, "MainAgent", _Recorder)
    # build_solver(use_mock=False) 构造完整工具层/监督/校验闭环，但本测试只验证构造参数，
    # 不发起任何 LLM 调用（test_benchmark_real_chain 已验证该构造离线可跑）。
    build_solver(use_mock=False, wallclock=180)
    assert _captured.get("per_question_wallclock") == 150.0, _captured
    assert _captured.get("hard_wallclock") == 150.0, _captured


def test_build_solver_without_wallclock_keeps_config_default(monkeypatch):
    """回归保护：未传 wallclock（其余调用方）→ Agent 用 config 默认(300/480)，不被收紧。"""
    import core.main_agent as _ma_mod
    _Real = _ma_mod.MainAgent
    _captured = {}

    class _Recorder(_Real):
        def __init__(self, *a, **kw):
            _captured.update(kw)
            super().__init__(*a, **kw)

    monkeypatch.setattr(_ma_mod, "MainAgent", _Recorder)
    build_solver(use_mock=False)  # 不传 wallclock
    assert _captured.get("per_question_wallclock") == 300, _captured
    assert _captured.get("hard_wallclock") == 480, _captured

