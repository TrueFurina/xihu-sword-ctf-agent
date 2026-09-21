---
name: project-context
description: 西湖论剑 CTF-Agent 项目上下文与铁律入口；触发词：西湖论剑、ctf_agent、项目上下文、这个项目是什么
---
# 项目上下文 — 西湖论剑 CTF-Agent

## 项目是什么
CTF 解题智能体（presolve 静态分析 49 技能优先，miss 才升级 LLM），双仓库模型（内部作战仓 + 公开仓 truefurina/xihu-sword-ctf-agent）。

## 必读文件（按序，先读后写）
1. `AGENTS.md`（根）— 目录法规 + 白名单机器校验
2. `ctf_agent/AGENTS.md` — 三铁律（工件可信/裁判分离/启动即门禁）+ KPI
3. `docs/ARCHITECTURE.md` — 架构图与关键链路
4. `plans/current.md` — 当前进度

## 关键命令
- 会话启动门禁: `python scripts/_session_boot.py`（在 ctf_agent/ 内，四查 fail-closed）
- KPI 真值: `python scripts/_merge_gate.py count_offline_verified`（当前 = 14）
- 真实链路: `python -m eval.benchmark --questions-dir data/questions_real --provider baidu,qwen`
- 测试: 全量 pytest（merge 闸门强制）

## 禁区（本项目特有）
- 根目录只允许白名单文件（`_structure_guard.py:ROOT_ALLOW` 校验），产出必须进对应子目录
- 日志/产物只留项目内，绝不写 C 盘用户目录
- 9 月起发布流冻结，禁止手工整理发布树，只走 `scripts/release_export.py`
- 自产题/本地靶场不计 KPI，唯一 KPI = 真题解出数
