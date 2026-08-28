---
type: idea
node_id: idea:ctf_agent_budget_reflection_concurrent
title: "分层预算熔断 + 结构化错误归因的并发 CTF-Agent 架构"
authors: ["糖露星霜•暖霞拾光"]
year: 2026
venue: "西湖论剑 AI-CTF 赛道"
external_ids:
  arxiv: null
  doi: null
  s2: null
tags: ["AI-CTF", "agent", "budget-breaker", "error-attribution", "concurrency", "LLM"]
added: 2026-08-27T00:00:00Z
status: "RECOMMENDED"
---

# 分层预算熔断 + 结构化错误归因的并发 CTF-Agent 架构

## One-line thesis
将分层预算熔断（单题/全局/重试）与结构化错误归因（5 类分类 + 定向修正反馈）结合并发调度，可在 3 小时赛时内以可控成本显著提升多题解出率。

## Problem / Gap
在 3 小时限时 CTF 竞赛中，现有 AI-CTF Agent 存在 5 大结构性空白：
1. **并发调度空白** — 仅 2/11 开源项目做到真并发，无优先级/资源隔离调度
2. **成本管控空白** — 多数无预算熔断，竞速成本翻 2-3 倍无护栏
3. **幻觉抑制空白** — 盲目重试 vs 结构化错误归因，差距巨大
4. **国内题型适配空白** — 所有项目偏国外考点（picoCTF/CSAW/HTB）
5. **Windows 兼容性空白** — 100% 依赖 Docker/Linux

## Method
### 三级预算熔断
- 一级: 单题 token 上限（防死循环烧钱）
- 二级: 全局预算上限（防整场击穿）
- 三级: 重试硬上限（兜底）+ 降级阈值（强制轻量模型）

### 结构化错误归因
- 5 类错误分类: 僵局/方向错/幻觉/工具失败/环境
- 定向修正反馈: error_category + key_info + suggestion
- 监督 Agent 裁决: 确定性规则兜底 + 轻量模型 AI 裁决

### 并发调度
- asyncio 信号量 ≤8 并发
- 优先级队列调度（按题型分值/解题耗时）
- 失败任务重入调度

## Key Results
_待实验验证。预期指标:_
- 解出率提升 +20% vs 基线
- Token 消耗降低 40% vs 无熔断
- 并发吞吐提升 3x vs 串行
- 重试成功率提升 +30% vs 无归因

## Assumptions
- LLM API 在赛时稳定可用（需备用 API 切换）
- 40 道真题评测体系可代表赛事难度分布
- Windows 子进程沙盒可满足资源隔离需求

## Limitations / Failure Modes
- 学术新颖性有限（工程优化非算法创新）
- 仅在西湖论剑赛制下测试，泛化性待验证
- 并发数过高可能导致资源竞争

## Reusable Ingredients
1. 三级预算熔断机制 — 可复用于任何 LLM Agent 场景
2. 5 类错误分类器 — 可复用于任何需要错误归因的 Agent
3. 监督裁决双引擎 — 确定性规则 + 轻量模型的混合裁决
4. 子进程沙盒 — Windows 无 Docker 的通用沙盒方案

## Open Questions
- 最优并发数是多少？（需实验验证 1/4/8/12）
- 三级熔断的阈值如何动态调整？
- 错误分类器的准确率如何提升？
- 如何泛化到其他 CTF 赛制？

## Claims
1. 三级预算熔断可将 Token 消耗降低 40%+ 而不显著损失解出率
2. 结构化错误归因可将重试成功率提升 30%+
3. 并发调度可在不损失单题解出率的前提下提升总吞吐量 2x+

## Connections
- 基于 verialabs/ctf-agent 的并发模型思想
- 基于 hydra 的 watchdog/flag_gate 设计
- 基于 LLM-CTF-Solver 的六维僵局检测
- 基于 CoRedteam 的 Consolidator 永久记忆
- 基于 NYU D-CIPHER 的 Planner-Executor 分工

## Relevance to This Project
本 idea 直接服务于西湖论剑 AI-CTF 赛道的自研 CTF-Agent 项目：
- 已有 4 阶段代码基础（异步调度/1主1监/工具适配器/子进程沙盒）
- 8 天工期可完成增量改造
- 40 道真题评测体系提供可量化验证
- 完全适配西湖论剑赛制（dasctf API/国内题型/Windows 环境）

## Novelty Verification
**最接近已有工作**: hydra (cost-cap + watchdog), LLM-CTF-Solver (双熔断 + 六维僵局), CoRedteam (Consolidator)
**差异化**: 无已发表论文同时覆盖「三级熔断 + 结构化归因 + 并发调度 + 国内适配」
**判定**: CONFIRMED

## External Review Score
7.5/10 — 工程价值明确，需通过消融实验证明每个组件的独立贡献

## Status
RECOMMENDED — 进入实验阶段

## Related Ideas
- [[idea:ctf_agent_adaptive_routing]] — CTF 题型自适应路由
- [[idea:ctf_agent_memory_evolution]] — 跨任务经验记忆的自演化
