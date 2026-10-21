"""benchmarks/ —— 机器真值目录 + 外部基准适配器（如 Cybench）。

本目录下的 JSON 绝大多数是机器真值（基准清单/健康基线/provider 档案），须走
scripts/_truth_guard.py 守卫；逐题载荷（questions/**/*.json）由 _build_external_benchmark.py
--check 负责。本 __init__.py 仅把 benchmarks 标记为显式包，便于 benchmarks.cybench
等适配器以绝对导入接入 eval.benchmark 全链路。
"""
