"""共享解题进度（兼容入口——薄封装转发 core.solve_progress）。

⚠️ 结构债合并：本文件原为独立实现（ChallengeState 内存态），现统一到
core.solve_progress.SolveProgress（文件态 + 线程锁 + 原子写 + 跨求解器 attempts 共享）。
保留本文件名仅为兼容旧引用方（ctfplatform/poller.py、scripts/_dry_run.py、
scripts/_race_final.py、scripts/_verify_imports.py 均 import core.progress）。

用法不变：
    from core.progress import get_progress
    prog = get_progress()
    prog.is_solved(id) / mark_solved(id, flag=...) / mark_attempted(id, title=...)
    prog.get_flag(id) / solved_count() / summary()
"""

from core.solve_progress import SolveProgress

# 向后兼容别名：_dry_run.py / _verify_imports.py 等脚本仍导入旧名 SharedProgress
SharedProgress = SolveProgress

__all__ = ["get_progress", "SolveProgress", "SharedProgress"]


def get_progress():
    """返回共享进度中心单例（转发 solve_progress 实现）。"""
    from core.solve_progress import get_progress as _real

    return _real()
