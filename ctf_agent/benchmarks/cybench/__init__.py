"""Cybench 适配器包（T2 阶段 A 脚手架，2026-10-22）。

把 Cybench 形态的题目 JSON 接入仓库统一的 eval.benchmark 全链路。
真实 Cybench 任务需 Docker 容器化评测；本脚手架的 dry-run 不依赖 Docker/密钥/网络，
只验证「加载→求解→评分→报告」数据通路。见 adapter.py / runner.py。
"""
