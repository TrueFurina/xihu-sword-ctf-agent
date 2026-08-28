---
idea_id: ctf_agent_race_intelligence
title: "竞赛态势感知 + 动态资源分配的赛智 CTF-Agent"
date: 2026-08-27
status: DEEPENED
novelty: CONFIRMED
review_score: TBD
deepened_proposal: idea-stage/refine-logs/FINAL_PROPOSAL_RACE_INTELLIGENCE.md
tags: [race-intelligence, dynamic-allocation, situational-awareness, competition-strategy, MAB, optimal-stopping]
---

# IDEA-4: 竞赛态势感知 + 动态资源分配的赛智 CTF-Agent

## 一句话假说

在 3 小时限时 CTF 竞赛中，通过实时态势感知（解题进度、剩余时间、资源消耗率）动态调整资源分配策略（模型等级、并发数、单题预算），可在固定总预算下最大化解出数。

## Problem Anchor

当前所有 AI-CTF 项目的资源分配都是**静态的**：
- hydra 的 cost-cap 是固定阈值（不会根据剩余时间调整）
- 本项目的 race_strategy.py 有先易后难排序，但**不感知竞赛进程**
- 没有任何项目考虑「还剩 30 分钟，还有 5 题未解，预算还剩 40%」这种态势

人类选手在比赛中会动态调整策略：
- 发现某题卡住 → 立即换题，不浪费时间
- 剩余时间紧迫 → 只做有把握的题
- 预算紧张 → 降级到轻量模型

**AI-CTF 领域的空白**：没有项目将竞赛态势感知与资源分配联动。

## Method Thesis

构建三层态势感知引擎：

### 第一层：微观态势（单题级）
- **解题信心分数**：基于当前步骤历史、工具输出质量、与已知模式的匹配度
- **进展速度**：单位时间内新发现的线索数（线索密度）
- **资源消耗率**：当前 token/时间 消耗与预期的比值

### 第二层：中观态势（全局级）
- **解题进度**：已解/总数、各题状态（进行中/卡住/已放弃）
- **资源预算**：已消耗/剩余、消耗速率、预计耗尽时间
- **时间窗口**：剩余时间、各题预计所需时间

### 第三层：宏观态势（竞赛级）
- **难度分布**：根据已解题的难度推断未解题的难度
- **边际收益**：投入额外 1 单位资源的预期收益（解出概率 × 分值）
- **机会成本**：继续当前题 vs 换题的期望收益差

### 动态资源分配策略

```python
# 伪代码
def allocate_resources(state: RaceState) -> Allocation:
    remaining_time = state.deadline - now()
    remaining_budget = state.global_budget - state.consumed
    
    # 态势评估
    for q in state.active_questions:
        q.confidence = estimate_confidence(q.step_history)
        q.estimated_time = estimate_remaining_time(q)
        q.marginal_value = q.score * q.confidence / q.estimated_time
    
    # 动态调整
    if remaining_time < TIGHT_THRESHOLD:
        # 时间紧迫：只做高信心题，降级模型
        return Allocation(
            model=LIGHT_MODEL,
            concurrency=MAX_CONCURRENCY,  # 最大并发抢时间
            focus=sorted(questions, key=lambda q: q.marginal_value, reverse=True)[:3]
        )
    elif remaining_budget < BUDGET_TIGHT:
        # 预算紧张：降级模型，减少并发
        return Allocation(
            model=LIGHT_MODEL,
            concurrency=max(1, state.concurrency - 2),
            focus=questions_sorted_by_confidence[:2]
        )
    else:
        # 正常模式：平衡攻难与扫易
        return Allocation(
            model=select_model_by_difficulty(questions),
            concurrency=state.concurrency,
            focus=questions_sorted_by_marginal_value
        )
```

## 核心创新点

1. **三维态势感知** — 微观（单题信心）+ 中观（全局进度）+ 宏观（竞赛策略）
2. **动态资源分配** — 根据态势实时调整模型等级、并发数、单题预算
3. **边际收益决策** — 用「每单位资源的预期收益」驱动换题/降级/放弃决策
4. **沉溺保护升级** — 从「超时换题」升级到「信心低于阈值换题」

## 差异化对标

| 维度 | 现有最佳 | 本 idea |
|------|----------|---------|
| 资源分配 | hydra 固定 cost-cap | 动态分配（根据态势实时调整） |
| 竞赛策略 | 本项目 race_strategy 先易后难 | 态势感知驱动的动态策略 |
| 换题决策 | 超时换题（时间维度） | 信心+时间+预算三维度决策 |
| 模型选择 | 固定升级规则 | 边际收益驱动的动态选择 |

## 与已有 Idea 的差异化

- **vs IDEA-1 (预算熔断)**：IDEA-1 是被动保护（超限熔断），本 idea 是主动优化（在预算内最大化收益）
- **vs IDEA-2 (题型路由)**：IDEA-2 是静态路由（开赛时分类），本 idea 是动态调整（赛中实时重路由）
- **vs IDEA-3 (记忆进化)**：IDEA-3 是赛后积累，本 idea 是赛中实时决策

## 可行性

⭐⭐⭐⭐ — 已有 race_strategy.py 和 budget.py 基础，增量改造约 4-5 天

### 改造点
1. `core/race_strategy.py` — 新增 `RaceState` 和态势评估函数
2. `scheduler/budget.py` — 新增动态分配逻辑
3. `core/main_agent.py` — 集成态势感知循环（每 N 步评估一次）
4. 新增 `core/race_intelligence.py` — 态势感知引擎

## Must-run Experiments

1. **消融实验**：固定预算下对比 (a) 静态分配 vs (b) 动态分配的解出数
2. **换题策略**：对比 (a) 超时换题 vs (b) 信心换题的解出率
3. **紧急模式**：模拟「最后 30 分钟」场景，对比有/无态势感知的表现
4. **成本效率**：相同解出数下的 token 消耗对比

## 核心公式

### 微观：单题信心
$$C_i(t) = 0.4 \cdot H_i(t) + 0.35 \cdot P_i(t) + 0.25 \cdot D_i(t)$$
- $H_i$：最近 5 步中新线索比例（规则计算，零 LLM 成本）
- $P_i$：基于 error_classifier 5 类分类的模式匹配分数
- $D_i$：$\exp(-2 \cdot b_i/b_{\text{expected}})$，资源消耗的指数衰减

### 中观：资源压力指数
$$\text{RPI}(t) = \frac{\text{budget\_rate} \times \text{time\_remaining}}{\text{budget\_remaining}}$$
- RPI > 1：预算将在比赛结束前耗尽 → 触发降级

### 宏观：边际收益（MAB 理论支撑）
$$\text{MV}_i(t) = \frac{s_i \cdot \hat{p}_i(t)}{\hat{t}_i(t)} + \sqrt{\frac{2 \ln N}{n_i}}$$
- 利用项：分值 × 估计解出概率 / 估计剩余耗时
- 探索项：UCB1 鼓励尝试未充分探索的题

### 三态决策规则
| 状态 | 触发条件 | 模型 | 并发 | 策略 |
|------|----------|------|------|------|
| 正常态 | RPI < 1 且 time > 30min | 按难度分级 | 4-8 | 全部按 MV 排序 |
| 时间紧急 | time < 30min | 全部 light | 8（最大） | 只做 confidence > 0.3 |
| 预算紧急 | RPI > 1 或 budget < 25% | 全部 tiny | 1-3 | 只做 MV 前 30% |
| 双重紧急 | 同时触发 | 全部 tiny | 1 | 只做 MV 最高的 1-2 题 |

## 理论基础

- **Multi-Armed Bandit**：每道题 = 一个臂，$\text{MV}_i = \hat{\mu}_i / c_i$ 正是 UCB1-Tuned 的利用项
- **最优停止理论**：前 37% 时间为探索期（Secretary Problem），之后只做超过阈值的题

## 深化提案

完整提案见：[`idea-stage/refine-logs/FINAL_PROPOSAL_RACE_INTELLIGENCE.md`](../../idea-stage/refine-logs/FINAL_PROPOSAL_RACE_INTELLIGENCE.md)

包含：Problem Anchor / Method Thesis / Core Claims / Architecture Design / Differentiation / Experiment Plan / Implementation Plan

## 参考文献

1. Auer et al. (2002). Finite-time analysis of the multiarmed bandit problem. *Machine Learning*.
2. Ferguson (1989). Who solved the secretary problem? *Statistical Science*.
3. hydra — 华沙大学批量求解框架，cost-cap 实现（2025）
4. LLM-CTF-Solver — 六维僵局检测 + 双熔断（2024）
5. CoRedteam — 微软 Consolidator 永久记忆（2025）
6. SageCTF — DEF CON 前 5%，自生成拓扑（2026）
7. 本项目 `core/race_strategy.py` — 先易后难基础
8. 本项目 `scheduler/budget.py` — 三级熔断基础
