---
idea_id: ctf_agent_context_compression
title: "工具输出专精过滤 + 上下文压缩的高效 CTF-Agent"
date: 2026-08-27
status: BACKUP
novelty: CONFIRMED
review_score: TBD
tags: [context-compression, tool-output-filtering, token-efficiency, domain-specific]
---

# IDEA-6: 工具输出专精过滤 + 上下文压缩的高效 CTF-Agent

## 一句话假说

按题型（Web/Crypto/Misc/Rev/Pwn）对工具输出做专精信息提取，结合上下文压缩（摘要+去重+关键信息保留），可在不损失关键信息的前提下将 token 消耗降低 40%+，等效于在固定预算下多解 2-3 题。

## Problem Anchor

当前所有 AI-CTF 项目对工具输出的处理方式：
- **全量保留**：将完整输出塞入 LLM 上下文（浪费 token）
- **简单截断**：保留前 N 行（可能丢失关键信息）
- **通用压缩**：用 LLM 摘要（额外 token 消耗 + 延迟）

**问题**：
1. Web 题的 HTTP 响应包含大量无关的 HTML/CSS/JS，关键信息（状态码、Set-Cookie、重定向 URL）占比 < 5%
2. Crypto 题的数值输出可能有 1000+ 行，关键信息（模数、指数、密文）占比 < 10%
3. Misc 题的文件分析输出包含大量元数据，关键信息（magic bytes、隐藏数据）占比 < 15%

## Method Thesis

构建题型感知的工具输出过滤引擎：

### Web 题过滤器
```python
def filter_web_output(raw: str) -> str:
    """保留：状态码、关键头(Set-Cookie/Location/X-Powered-By)、
    响应体中的 flag/注释/隐藏字段、表单结构。丢弃：CSS/JS/图片引用。"""
    lines = raw.split('\n')
    filtered = []
    for line in lines:
        if any(k in line.lower() for k in ['set-cookie', 'location:', 'x-powered-by', 
                                             'flag{', '<!--', '<form', '<input', '<script']):
            filtered.append(line)
        elif re.match(r'^HTTP/\d', line):  # 状态行
            filtered.append(line)
    return '\n'.join(filtered[-50:])  # 最多保留 50 行
```

### Crypto 题过滤器
```python
def filter_crypto_output(raw: str) -> str:
    """保留：数值(n/e/c/p/q)、hex 串、base64 串、flag 格式串。
    丢弃：调试信息、重复格式、无关数值。"""
    patterns = [
        r'[necpq]\s*=\s*\d+',  # RSA 参数
        r'[0-9a-f]{32,}',  # 长 hex 串
        r'[A-Za-z0-9+/]{20,}={0,2}',  # base64
        r'flag\{[^}]+\}',  # flag
    ]
    # 提取匹配行 + 上下文
    ...
```

### Misc 题过滤器
```python
def filter_misc_output(raw: str) -> str:
    """保留：magic bytes、文件类型、隐藏数据、异常编码。
    丢弃：标准元数据、重复格式。"""
    ...
```

### 上下文压缩引擎

```python
class ContextCompressor:
    """上下文压缩器：摘要+去重+关键信息保留。"""
    
    def compress(self, history: list[StepRecord]) -> str:
        # 1. 去重：连续相同动作合并
        deduped = self._deduplicate(history)
        # 2. 摘要：每 5 步生成一句话摘要
        summarized = self._summarize_blocks(deduped, block_size=5)
        # 3. 关键信息提取：保留 flag/错误分类/工具输出关键行
        key_info = self._extract_key_info(summarized)
        # 4. 窗口：只保留最近 N 步的完整记录
        windowed = self._apply_window(key_info, window=10)
        return windowed
```

## 核心创新点

1. **题型感知过滤** — 不是通用截断，而是按题型保留关键信息
2. **零 LLM 开销** — 过滤规则是确定性的，不消耗额外 token
3. **上下文压缩** — 去重+摘要+窗口，将长历史压缩为关键信息
4. **等效增益** — token 节省 → 同预算下多解题（或单题多尝试）

## 差异化对标

| 维度 | 现有最佳 | 本 idea |
|------|----------|---------|
| 输出处理 | 全量保留/简单截断 | 题型感知专精过滤 |
| 上下文管理 | 无/简单窗口 | 去重+摘要+窗口三级压缩 |
| Token 效率 | 基线 | 预计 40%+ 节省 |
| LLM 开销 | — | 零（确定性规则） |

## 与已有 Idea 的差异化

- **vs IDEA-1 (预算熔断)**：IDEA-1 是被动保护，本 idea 是主动优化 token 效率
- **vs IDEA-2 (题型路由)**：IDEA-2 路由到不同工具，本 idea 过滤工具输出
- **vs IDEA-5 (Writeup RAG)**：IDEA-5 增加知识输入，本 idea 压缩工具输出
- **正交性**：本 idea 与所有已有 idea 正交，可独立实施也可组合

## 可行性

⭐⭐⭐⭐⭐ — 纯规则引擎，无需 LLM/向量库，工时约 2-3 天

### 改造点
1. 新增 `core/output_filter.py` — 题型感知过滤器
2. 新增 `core/context_compressor.py` — 上下文压缩引擎
3. `core/main_agent.py` — 集成过滤和压缩循环
4. `core/prompts.py` — 调整 prompt 适配压缩后的历史

## Must-run Experiments

1. **Token 节省率**：在 15 道真题上测量有/无过滤的 token 消耗差异
2. **信息损失率**：人工标注 50 个工具输出，对比过滤前后的关键信息保留率
3. **解出率影响**：对比 (a) 全量保留 vs (b) 过滤后的解出率（不能下降）
4. **压缩效率**：测量上下文压缩对长历史（20+ 步）的 token 节省效果

## 参考文献

1. 本项目 `skills/` — 55+ 工具的输出格式
2. 本项目 `verify/error_classifier.py` — 错误分类基础
3. LLM 上下文窗口管理 — 研究现状
4. 信息检索中的文档压缩 — 经典方法
