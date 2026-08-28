---
type: idea
node_id: idea:ctf_agent_adaptive_routing
title: "CTF 题型自适应路由 + 多模型分级调度"
authors: ["糖露星霜•暖霞拾光"]
year: 2026
venue: "西湖论剑 AI-CTF 赛道"
external_ids:
  arxiv: null
  doi: null
  s2: null
tags: ["AI-CTF", "agent", "adaptive-routing", "model-selection", "challenge-classification"]
added: 2026-08-27T00:00:00Z
status: "BACKUP"
---

# CTF 题型自适应路由 + 多模型分级调度

## One-line thesis
基于题型三维分类（附件后缀/描述关键词/连接信息）自动路由到最优工具链和模型组合，可在不增加成本的前提下提升单题解出率。

## Problem / Gap
现有 CTF-Agent 对所有题型采用统一处理流程，未根据题型特征自动选择最优工具链和模型组合。

## Method
1. **三维题型分类器** — 附件后缀 60+ 种、描述关键词 80+ 种、连接信息特征
2. **自适应路由** — 根据题型自动选择工具组合、Prompt 模板、模型等级
3. **分级模型调度** — 简单题轻量模型（省成本）、难题重型模型（保解出率）

## Key Results
_待实验验证。_

## Novelty Verification
**最接近**: LLM-CTF-Solver 的 challenge_classifier
**差异化**: 分类→路由→调度全链路整合
**判定**: CONFIRMED WITH CAUTION

## Status
BACKUP — 若 IDEA-1 实验效果不佳，可作为替代方案

## Connections
- 基于 LLM-CTF-Solver 的 challenge_classifier 三维分类
- 基于 verialabs/ctf-agent 的多模型竞速路由思想
