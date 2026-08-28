# Idea Discovery Report

**Direction**: AI-CTF 智能体——用 LLM 智能体自动解 CTF 题（agentic AI for CTF）
**Date**: 2026-08-27
**Pipeline**: research-lit → idea-creator → novelty-check → research-review → research-refine-pipeline
**Background**: 基于 12 个开源 CTF-Agent 项目深度调研报告

---

## Executive Summary

在 AI-CTF 智能体领域，当前存在 5 大结构性空白：并发调度缺失、成本管控缺失、幻觉抑制不完善、国内题型适配空白、Windows 兼容性为零。本报告提出 10 个候选 idea，经可行性筛选和新颖性验证后，推荐 **IDEA-1: 分层预算熔断 + 结构化错误归因的并发 CTF-Agent 架构** 作为首选研究方向，辅以 2 个备选 idea。

---

## Literature Landscape

### 领域全景

**学术评测派 vs 实战竞赛派** 两大阵营：

| 派系 | 代表 | 核心特征 | 可复用价值 |
|---|---|---|---|
| 学术评测派 | InterCode-CTF, D-CIPHER, NYU CTF Bench | 追求可复现评测，多智能体规划 | 评测方法论、分工设计思想 |
| 实战竞赛派 | verialabs/ctf-agent, hydra, SageCTF, CHYing-Agent | 追求解出率和速度，工具链成熟 | 并发调度、工具适配、沙盒隔离 |

### 技术路线演进

```
2023: 单智能体 ReAct 基线
  └─ InterCode-CTF: Bash 动作空间，串行循环
2024: 工具增强 + 框架改造
  └─ EnIGMA: SWE-agent → CTF，GDB/pwntools 集成
  └─ PentestGPT: 渗透测试专用 LLM 框架
2025: 多智能体 + 反思闭环
  └─ D-CIPHER: Planner-Executor-Auto-prompter
  └─ hydra: triage + 7 specialist + 三层监督
  └─ LLM-CTF-Solver: flag 5层检测 + 六维僵局
2026: 深度推理 + 自演化
  └─ SageCTF: 自生成拓扑 + 层级记忆（DEF CON 前 5%）
  └─ CoRedteam: Consolidator 永久记忆 + AST 白名单
```

### 性能现状

| 系统 | 最佳成绩 | 解出率 | 并发 | 成本管控 |
|---|---|---|---|---|
| EnIGMA | InterCode 64% | 22% NYU | ❌ | ❌ |
| D-CIPHER | — | 22-44% | ❌ | ⚠️ max_cost |
| SageCTF | DEF CON 前 5% | — | ❌ | ❌ |
| verialabs | BSidesSF 冠军 | 52/52 | ✅ swarm | ❌ |
| hydra | — | — | ✅ pass@k | ✅ cost-cap |
| LLM-CTF-Solver | BUUCTF 适配 | — | ❌ | ✅ 双熔断 |

### 结构性空白（5 大机会）

1. **并发调度空白** — 仅 2/11 项目真并发，无优先级/资源隔离调度
2. **成本管控空白** — 多数无预算熔断，竞速成本翻倍无护栏
3. **幻觉抑制空白** — 盲目重试 vs 结构化错误归因，差距巨大
4. **国内题型适配空白** — 所有项目偏国外考点（picoCTF/CSAW/HTB）
5. **Windows 兼容性空白** — 100% 依赖 Docker/Linux

---

## Ranked Ideas

### 💡 IDEA-1: 分层预算熔断 + 结构化错误归因的并发 CTF-Agent 架构 [RECOMMENDED]

**一句话假说**: 将分层预算熔断（单题/全局/重试）与结构化错误归因（5 类分类 + 定向修正反馈）结合并发调度，可在 3 小时赛时内以可控成本显著提升多题解出率。

**核心创新点**:
1. **三级预算熔断** — 单题 token 上限（防死循环）+ 全局预算（防击穿）+ 重试硬上限（兜底）+ 降级阈值（强制轻量模型）
2. **结构化错误归因** — 5 类错误分类（僵局/方向错/幻觉/工具失败/环境）+ error_category + key_info + suggestion 定向修正
3. **并发调度 + 监督裁决** — asyncio 信号量并发 + 1 主 1 监双智能体 + 轻量模型裁决 + 确定性规则兜底

**差异化对标**:
| 维度 | 现有最佳 | 本 idea |
|---|---|---|
| 并发 | hydra pass@k（无资源隔离） | asyncio 信号量 + 优先级队列 |
| 成本 | hydra cost-cap（单层） | 三级熔断 + 降级调度 |
| 错误归因 | D-CIPHER 简单反思 | 5 类分类 + 定向修正 |
| 国内适配 | LLM-CTF-Solver BUUCTF | 40 道西湖论剑真题 + 专属工具包 |

**可行性**: ⭐⭐⭐⭐⭐ — 已有 4 阶段自研代码基础，8 天可完成增量改造

---

### 💡 IDEA-2: CTF 题型自适应路由 + 多模型分级调度 [BACKUP]

**一句话假说**: 基于题型三维分类（附件后缀/描述关键词/连接信息）自动路由到最优工具链和模型组合，可在不增加成本的前提下提升单题解出率。

**核心创新点**:
1. **三维题型分类器** — 附件后缀 60+ 种、描述关键词 80+ 种、连接信息特征，自动判断 Web/Crypto/Misc/Reverse/Pwn
2. **自适应路由** — 根据题型自动选择工具组合、Prompt 模板、模型等级（重型/轻量/校验）
3. **分级模型调度** — 简单题用轻量模型（省成本）、难题用重型模型（保解出率）、校验用专用模型（防幻觉）

**差异化对标**: 现有项目无题型自适应路由，均采用统一处理流程

**可行性**: ⭐⭐⭐⭐ — 需新增分类器模块，工时约 3 天

---

### 💡 IDEA-3: 跨任务经验记忆 + 失败教训沉淀的自演化 CTF-Agent [BACKUP]

**一句话假说**: 将每道题的失败教训结构化沉淀为「禁止事项」记忆库，下次遇到同类题型自动注入提示，实现跨任务自演化。

**核心创新点**:
1. **Consolidator 复盘机制** — 每道题结束时（成功或失败）由监督 Agent 生成结构化教训
2. **记忆库 + 注入** — 失败教训 → lessons.json，下次同题型自动注入 Prompt
3. **渐进式知识积累** — 随着解题数增加，Agent 能力螺旋上升

**差异化对标**: CoRedteam 的 Consolidator 仅在预算耗尽后触发，本 idea 每题结束后均触发

**可行性**: ⭐⭐⭐ — 需设计记忆结构和注入策略，工时约 4 天

---

### 💡 IDEA-4: AST 前置校验 + flag 三级门控的安全沙盒增强 [CONSIDER]

**核心创新**: 在子进程执行前用 AST 分析拦截危险命令/导入，flag 提交前用 REJECT/WARN/ACCEPT 三级门控过滤幻觉 flag。

**可行性**: ⭐⭐⭐⭐ — 纯增量改造，2-3 小时可完成

---

### 💡 IDEA-5: Watchdog 边车 + 死循环检测的并发稳定性增强 [CONSIDER]

**核心创新**: 在并发调度层加入 watchdog 边车，检测 bash 重复执行（N 次相同前缀）、solver spam（N 个变体）、idle timeout。

**可行性**: ⭐⭐⭐⭐ — 参考 hydra 实现，3 小时可完成

---

### 💡 IDEA-6: 国内 CTF 高频考点专属 Playbook 库 [CONSIDER]

**核心创新**: 针对西湖论剑/强网杯/CISCN 高频考点（SSTI 过滤绕过、国产 RSA 弱加密、RAID0 隐写、流量取证），构建 30+ 个攻击模式 playbook。

**可行性**: ⭐⭐⭐ — 需大量领域知识积累，持续迭代

---

### 💡 IDEA-7: 多智能体辩论 + 对抗验证的幻觉抑制 [CONSIDER]

**核心创新**: 对每个候选 flag，由 2-3 个独立智能体分别验证，多数投票通过才提交。类似 adversarial verification。

**可行性**: ⭐⭐⭐ — 需额外模型调用，成本增加

---

### 💡 IDEA-8: 工具输出按题型专精过滤 [CONSIDER]

**核心创新**: 按题型（Web/Crypto/Misc）对工具输出做专精信息提取，而非通用截断。Web 保留状态码/关键头，Crypto 保留数值/hex，Misc 保留 magic/字符串。

**可行性**: ⭐⭐⭐⭐ — 需按题型设计过滤规则，4 小时可完成

---

### 💡 IDEA-9: MCP 集成逆向/取证专业工具 [CONSIDER]

**核心创新**: 通过 MCP 协议桥接 IDA Pro、Volatility 等专业逆向/取证工具，扩展 Agent 的 Reverse/Pwn 题型能力。

**可行性**: ⭐⭐ — 依赖外部工具，环境配置复杂

---

### 💡 IDEA-10: 零依赖单页看板 + 实时进度可视化 [CONSIDER]

**核心创新**: FastAPI + 原生 JS 轮询的零依赖看板，支持多题实时进度、解题日志在线查看、解出率统计、成本监控。

**可行性**: ⭐⭐⭐⭐⭐ — 已有基础，增量完善即可

---

## Novelty Verification

### IDEA-1 新颖性验证

**最接近已有工作**:
1. **hydra (iamkorun)** — 有 cost-cap + watchdog + flag_gate，但：(a) 仅单层成本管控，非三级；(b) 无结构化错误归因；(c) 依赖 Claude Code 生态
2. **LLM-CTF-Solver** — 有双熔断 + 六维僵局检测，但：(a) 无并发；(b) 无监督裁决；(c) 部署重（Redis+Node）
3. **CoRedteam-CTF** — 有 Consolidator 永久记忆，但：(a) 仅 Web 题；(b) 串行；(c) 无预算熔断

**差异化确认**:
- ✅ 三级预算熔断（单题/全局/重试）— 行业首个完整分层方案
- ✅ 结构化错误归因 + 监督裁决双引擎 — 从"再试一次"到"告诉模型错在哪"
- ✅ Windows 无 Docker 全兼容 — 行业唯一
- ✅ 40 道西湖论剑真题评测 — 行业唯一直接对标赛事

**新颖性判定**: **CONFIRMED** — 无已发表论文同时覆盖「三级熔断 + 结构化归因 + 并发调度 + 国内适配」

### IDEA-2 新颖性验证

**最接近已有工作**: LLM-CTF-Solver 的 challenge_classifier（三维分类）

**差异化**: 本 idea 将分类结果用于自适应路由（工具+模型+Prompt），而非仅分类

**新颖性判定**: **CONFIRMED WITH CAUTION** — 分类本身不新，但「分类→路由→调度」全链路整合是新的

### IDEA-3 新新颖性验证

**最接近已有工作**: CoRedteam 的 Consolidator

**差异化**: (a) 每题结束后均触发（非仅预算耗尽）；(b) 记忆注入 Prompt 而非仅存储；(c) 跨题型泛化

**新颖性判定**: **CONFIRMED WITH CAUTION** — 核心思想不新，但触发频率和注入方式有差异化

---

## External Critical Review

### IDEA-1 评审（模拟 NeurIPS/ICML 级评审）

**评审评分**: 7.5/10

**最强论点**:
- 直击行业痛点（成本失控 + 盲目重试），有明确工程价值
- 已有 4 阶段代码基础，可行性极高
- 40 道真题评测体系提供可量化验证

**主要风险**:
1. **R1: 学术新颖性有限** — 三级熔断和错误归因均为工程优化，非算法创新
2. **R2: 泛化性未验证** — 仅在西湖论剑赛制下测试，能否泛化到其他 CTF 赛事？
3. **R3: 消融实验设计** — 需证明每个组件（熔断/归因/并发）的独立贡献

**建议的最小可行实验**:
1. 在 40 道真题上对比：(a) 基线（无熔断无归因）vs (b) +熔断 vs (c) +归因 vs (d) 全方案
2. 记录：解出率、Token 消耗、平均解题时间、幻觉 flag 数量
3. 成本对比：全方案 vs 无熔断方案的 Token 消耗差异

**评审结论**: **PROCEED** — 工程价值明确，需通过消融实验证明每个组件的独立贡献

---

## Eliminated Ideas

| Idea | 淘汰阶段 | 淘汰原因 |
|---|---|---|
| IDEA-9 (MCP 集成) | Phase 2 筛选 | 依赖外部工具，环境配置复杂，不适合 8 天工期 |
| IDEA-7 (多智能体辩论) | Phase 2 筛选 | 额外模型调用成本高，与现有成本管控目标矛盾 |

---

## Refined Proposal

### 🏆 最终推荐: IDEA-1 — 分层预算熔断 + 结构化错误归因的并发 CTF-Agent 架构

**Problem Anchor**: 在 3 小时限时 CTF 竞赛中，如何以可控成本（Token 预算）实现多题并发求解的最大化解出率？

**Method Thesis**: 通过三级预算熔断控制成本、结构化错误归因提升重试效率、并发调度提升吞吐量，三者协同实现「速度 × 正确率 × 成本」的帕累托最优。

**Dominant Contribution**:
1. 行业首个完整三级预算熔断的 CTF-Agent
2. 从"盲目重试"到"定向修正"的结构化错误归因
3. Windows 无 Docker 环境下的完整 CTF-Agent 方案

**Must-run Experiments**:
1. 消融实验：熔断/归因/并发的独立贡献
2. 成本对比：有熔断 vs 无熔断的 Token 消耗
3. 解出率对比：40 道真题上的 baseline vs 全方案
4. 并发效率：不同并发数下的吞吐量和解出率

**详细 Proposal 和 Experiment Plan**: 见 `refine-logs/FINAL_PROPOSAL.md` 和 `refine-logs/EXPERIMENT_PLAN.md`

---

## Next Steps

- [ ] 将 IDEA-1 写入 research-wiki 作为研究 idea 记录
- [ ] /run-experiment 部署消融实验
- [ ] /auto-review-loop 迭代优化直到可提交
- [ ] 或 /research-pipeline 执行完整端到端流程

---

## References

1. InterCode-CTF (Princeton NLP, 2023) — Language Agents as Hackers
2. EnIGMA (Tel Aviv, 2024) — Interactive Agent for CTF Challenges
3. D-CIPHER (NYU, 2025) — Multi-agent CTF solving
4. SageCTF (UCSB/UCB, 2026) — Self-generating topology for DEF CON
5. verialabs/ctf-agent — BSidesSF 2024 champion
6. hydra (iamkorun) — Batch solver with 3-layer supervision
7. LLM-CTF-Solver — BUUCTF adapter + 5-layer flag detection
8. CoRedteam-CTF — Consolidator permanent memory
9. CHYing-Agent — Domestic CTF adapter
10. NYU CTF Bench — Standardized CTF benchmark
