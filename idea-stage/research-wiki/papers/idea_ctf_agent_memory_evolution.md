---
type: idea
node_id: idea:ctf_agent_memory_evolution
title: "跨任务经验记忆 + 失败教训沉淀的自演化 CTF-Agent"
authors: ["糖露星霜•暖霞拾光"]
year: 2026
venue: "西湖论剑 AI-CTF 赛道"
external_ids:
  arxiv: null
  doi: null
  s2: null
tags: ["AI-CTF", "agent", "memory", "self-evolution", "lesson-learning"]
added: 2026-08-27T00:00:00Z
status: "BACKUP"
---

# 跨任务经验记忆 + 失败教训沉淀的自演化 CTF-Agent

## One-line thesis
将每道题的失败教训结构化沉淀为「禁止事项」记忆库，下次遇到同类题型自动注入提示，实现跨任务自演化。

## Problem / Gap
现有 CTF-Agent 每道题独立求解，失败教训不跨任务传递，同类题型重复犯相同错误。

## Method
1. **Consolidator 复盘机制** — 每道题结束后由监督 Agent 生成结构化教训
2. **记忆库 + 注入** — 失败教训 → lessons.json，下次同题型自动注入 Prompt
3. **渐进式知识积累** — 随着解题数增加，Agent 能力螺旋上升

## Key Results
_待实验验证。_

## Novelty Verification
**最接近**: CoRedteam 的 Consolidator
**差异化**: 每题结束后均触发（非仅预算耗尽）；记忆注入 Prompt 而非仅存储
**判定**: CONFIRMED WITH CAUTION

## Status
BACKUP — 可与 IDEA-1 组合使用

## Connections
- 基于 CoRedteam 的 Consolidator 永久记忆机制
- 基于 SageCTF 的层级记忆/RAG 思想
