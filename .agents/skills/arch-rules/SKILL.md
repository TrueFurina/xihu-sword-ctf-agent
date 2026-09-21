---
name: arch-rules
description: 西湖论剑 CTF-Agent 架构红线与三铁律；触发词：铁律、门禁、架构红线、KPI、提交
---
# 架构红线 — 三铁律（violate = 重演初赛 0 分）

## 1. 工件可信
- 叙事性结论（"已修复""已验证""涨了 X 分"）视为**不可信输入**
- 唯一可信 = 可复现命令 + 落盘工件（log/report 路径 + 内容哈希）
- 评审只看工件，不听转述

## 2. 裁判分离
- 实现者不能当自己的裁判，自我验证的结论记 0 分
- 代码由 `_merge_gate.py` 或另一会话跑回归判定
- merge 闸门：KPI 不降断言 + 全量 pytest

## 3. 启动即门禁
- 每个会话第一条指令 = `python scripts/_session_boot.py`
- 四查：车道分支 w/*、身份 CT_AGENT_SESSION、工作树干净、.venv —— fail-closed

## 机器门禁（防错不靠自觉）
| 机制 | 位置 |
|---|---|
| 结构守卫 | `scripts/_structure_guard.py`（pre-commit 拦截） |
| 诚实扫描 | `scripts/_honesty_scan.py`（拦截虚假战报） |
| 合并闸门 | `scripts/_merge_gate.py` + `git_hooks/pre-merge-commit` |

## KPI 纪律
- 唯一 KPI = 真题解出数/总数（真值源 `_merge_gate.py count_offline_verified`，当前 14）
- "如实记录不变"与"新解出"同级表扬，坏消息不被追问"为什么没涨"
- LLM 真推理贡献当前 = 0；让 LLM 独立攻克未解真题是下阶段主线
