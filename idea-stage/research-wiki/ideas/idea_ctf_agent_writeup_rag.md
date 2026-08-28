---
idea_id: ctf_agent_writeup_rag
title: "多源知识融合 + Writeup RAG 的知识增强 CTF-Agent"
date: 2026-08-27
status: RECOMMENDED
novelty: CONFIRMED
review_score: TBD
tags: [rag, knowledge-augmentation, writeup-retrieval, tool-output-grounding]
---

# IDEA-5: 多源知识融合 + Writeup RAG 的知识增强 CTF-Agent

## 一句话假说

在解题过程中，实时检索历史 writeup/漏洞数据库/工具手册，将检索结果注入 LLM 上下文，可在不增加模型参数量的前提下显著提升解题能力（类似 RAG 对通用 LLM 的增强效果）。

## Problem Anchor

当前所有 AI-CTF 项目的知识来源**仅有 LLM 内部知识**：
- LLM 的知识截止日期之后的漏洞/技巧无法使用
- 国内 CTF 特有技巧（如 SSTI 过滤绕过的骚操作）在英文训练数据中稀缺
- 工具的高级用法（如 pwntools 的 ret2dlresolve）LLM 可能记错或不知道

**人类选手的优势**：解题时会搜索历史 writeup、查工具手册、看 CTF Wiki。AI-CTF 项目完全没有这个能力。

## Method Thesis

构建三层知识融合引擎：

### 第一层：实时 Writeup 检索（RAG）
- **知识库构建**：离线爬取 BUUCTF/攻防世界/CTFHub 等平台的公开 writeup
- **向量化存储**：将 writeup 按题目类型/解法/工具 分块向量化
- **实时检索**：解题过程中，根据当前题目特征（类型、关键词、工具输出）检索最相关的 writeup 片段
- **上下文注入**：将检索结果作为「参考知识」注入 LLM prompt

### 第二层：工具手册检索（Tool-Augmented RAG）
- **工具文档库**：将 55+ skill 的文档/示例/常见错误 向量化
- **实时查询**：当 LLM 准备调用某工具时，自动检索该工具的高级用法和注意事项
- **错误修正**：当工具执行失败时，检索该工具的常见错误和解决方案

### 第三层：漏洞模式库（Vulnerability Pattern RAG）
- **模式库**：将 CVE/PoC/CTF 题解中的漏洞模式结构化存储
- **模式匹配**：根据题目特征（代码片段、网络行为、文件格式）匹配已知漏洞模式
- **攻击链推荐**：基于匹配到的模式推荐攻击链

### 架构设计

```
[题目输入]
    |
    v
[特征提取器] --> 题型/关键词/代码片段/工具输出
    |
    v
[知识检索引擎]
    ├─ Writeup RAG: 检索历史解法
    ├─ Tool RAG: 检索工具高级用法
    └─ Vuln Pattern RAG: 检索漏洞模式
    |
    v
[知识融合器] -- 合并检索结果 + 去重 + 排序
    |
    v
[Prompt 注入器] -- 将知识注入 LLM 上下文
    |
    v
[LLM 推理] -- 带知识的推理
    |
    v
[工具执行] -- 执行 LLM 生成的命令
```

## 核心创新点

1. **三层知识融合** — Writeup + 工具手册 + 漏洞模式，覆盖不同知识维度
2. **实时检索增强** — 不是离线预处理，而是解题过程中动态检索
3. **工具输出接地** — 当工具输出包含专业术语/错误码时，自动检索解释
4. **国内 CTF 知识库** — 专门收录西湖论剑/强网杯/CISCN 的解题技巧

## 差异化对标

| 维度 | 现有最佳 | 本 idea |
|------|----------|---------|
| 知识来源 | 仅 LLM 内部知识 | LLM + Writeup RAG + 工具手册 + 漏洞模式 |
| 知识更新 | 离线训练截止 | 实时检索（知识库可热更新） |
| 工具使用 | LLM 记忆（可能记错） | 工具手册实时查询 |
| 国内适配 | 无 | 专门收录国内 CTF 解题技巧 |

## 与已有 Idea 的差异化

- **vs IDEA-1 (预算熔断)**：完全正交，本 idea 关注知识增强而非成本控制
- **vs IDEA-2 (题型路由)**：IDEA-2 是静态分类，本 idea 是动态知识注入
- **vs IDEA-3 (记忆进化)**：IDEA-3 是赛后经验积累，本 idea 是赛中实时知识检索
- **vs IDEA-4 (态势感知)**：IDEA-4 关注资源分配，本 idea 关注知识增强

## 可行性

⭐⭐⭐ — 需要构建知识库和向量检索引擎，工时约 5-6 天

### 改造点
1. 新增 `knowledge/` 模块 — 知识库管理
2. 新增 `knowledge/writeup_rag.py` — Writeup 检索
3. 新增 `knowledge/tool_rag.py` — 工具手册检索
4. 新增 `knowledge/vuln_pattern.py` — 漏洞模式匹配
5. `core/main_agent.py` — 集成知识检索循环
6. `core/prompts.py` — 新增知识注入 prompt 模板

### 技术选型
- 向量数据库：FAISS（轻量级，无需外部服务）
- 嵌入模型：bge-small-zh-v1.5（中文优化，512 维）
- 检索策略：混合检索（向量 + 关键词 BM25）

## Must-run Experiments

1. **消融实验**：对比 (a) 无 RAG vs (b) 仅 Writeup RAG vs (c) 三层 RAG 的解出率
2. **检索质量**：评估检索结果的相关性（人工标注 100 个查询）
3. **知识库规模**：测试知识库大小对检索质量的影响（100/500/1000/5000 篇 writeup）
4. **延迟开销**：测量检索延迟对总解题时间的影响
5. **国内题型**：在西湖论剑真题上对比有/无国内知识库的解出率

## 参考文献

1. RAG (Retrieval-Augmented Generation) — Lewis et al., 2020
2. SWE-agent — 代码理解 Agent（但无知识检索）
3. CTF Wiki — 国内 CTF 知识库
4. 本项目 `skills/` — 55+ 工具的文档基础
5. 本项目 `core/presolve.py` — 静态分析基础
