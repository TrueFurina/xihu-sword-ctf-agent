---
idea_id: ctf_agent_human_in_loop
title: "人类在环 + 渐进式自主的混合 CTF-Agent"
date: 2026-08-27
status: BACKUP
novelty: CONFIRMED
review_score: TBD
tags: [human-in-loop, progressive-autonomy, confidence-gated, hybrid-intelligence]
---

# IDEA-7: 人类在环 + 渐进式自主的混合 CTF-Agent

## 一句话假说

通过信心阈值门控实现「高信心自主执行 + 低信心求助人类」的渐进式自主模式，可在保持高自主率的同时显著降低幻觉 flag 提交和危险命令执行的风险。

## Problem Anchor

当前所有 AI-CTF 项目的人机协作模式是**二元的**：
- **全自主模式**：Agent 独立完成所有操作（容易幻觉/卡死/浪费预算）
- **全人工模式**：人类全程参与（失去 AI 效率优势）

**问题**：
1. 全自主模式下，Agent 可能在错误方向上浪费大量预算（幻觉 flag、死循环）
2. 全人工模式下，人类无法同时关注多道并发题
3. 没有中间态：「Agent 自主处理简单题，难题求助人类」

## Method Thesis

构建信心门控的渐进式自主引擎：

### 信心评估器

```python
class ConfidenceEstimator:
    """信心评估器：评估当前操作的信心分数。"""
    
    def estimate(self, action: str, context: dict) -> float:
        """返回 0.0-1.0 的信心分数。"""
        score = 1.0
        
        # 因子 1：历史成功率
        if action in self.action_history:
            success_rate = self.action_history[action].success_rate
            score *= success_rate
        
        # 因子 2：工具输出质量
        if context.get('tool_output'):
            if 'error' in context['tool_output'].lower():
                score *= 0.3
            elif 'flag{' in context['tool_output']:
                score *= 0.9  # 有 flag 但未验证
        
        # 因子 3：步骤历史一致性
        if self._is_stuck(context.get('step_history', [])):
            score *= 0.2
        
        # 因子 4：题目难度
        difficulty = context.get('difficulty', 'MEDIUM')
        score *= {'EASY': 1.0, 'MEDIUM': 0.8, 'HARD': 0.5, 'VERY_HARD': 0.3}[difficulty]
        
        return max(0.0, min(1.0, score))
```

### 门控决策器

```python
class AutonomyGate:
    """自主门控：根据信心分数决定自主/求助/降级。"""
    
    # 门控阈值
    FULL_AUTONOMY = 0.7    # ≥0.7：完全自主
    ASSISTED = 0.4         # 0.4-0.7：辅助模式（执行前确认）
    HUMAN_REQUIRED = 0.0   # <0.4：求助人类
    
    def decide(self, confidence: float, action_risk: str) -> str:
        if action_risk == 'high':  # 高风险操作（rm/dd/格式化）
            return 'human_required'  # 始终求助
        if confidence >= self.FULL_AUTONOMY:
            return 'autonomous'
        elif confidence >= self.ASSISTED:
            return 'assisted'  # 执行前向人类确认
        else:
            return 'human_required'
```

### 渐进式自主模式

```
模式 1：完全自主（信心 ≥ 0.7）
  → Agent 独立执行，无需人类干预
  → 适合：简单题、模板命中、已知模式

模式 2：辅助模式（信心 0.4-0.7）
  → Agent 生成方案，人类确认后执行
  → 适合：中等题、需要判断的步骤

模式 3：人类主导（信心 < 0.4）
  → Agent 提供分析，人类决策
  → 适合：难题、卡死状态、高风险操作

模式 4：人类接管（紧急）
  → Agent 暂停，人类完全接管
  → 触发：预算即将耗尽、连续失败、安全风险
```

## 核心创新点

1. **信心门控** — 基于多因子信心评估的自主/求助决策
2. **渐进式自主** — 不是二元的「自主/人工」，而是连续的自主度调节
3. **风险感知** — 高风险操作（删除/格式化）始终求助人类
4. **预算紧急模式** — 预算紧张时自动降级为辅助模式

## 差异化对标

| 维度 | 现有最佳 | 本 idea |
|------|----------|---------|
| 人机协作 | 全自主或全人工 | 渐进式自主（连续调节） |
| 风险控制 | 事后审计 | 事前门控（高风险操作求助） |
| 信心评估 | 无 | 多因子信心评估器 |
| 紧急模式 | 超时放弃 | 预算紧急降级 |

## 与已有 Idea 的差异化

- **vs IDEA-1 (预算熔断)**：IDEA-1 是被动保护，本 idea 是主动降级（在熔断前求助人类）
- **vs IDEA-4 (态势感知)**：IDEA-4 关注资源分配，本 idea 关注自主度调节
- **vs IDEA-6 (上下文压缩)**：IDEA-6 压缩输出，本 idea 控制决策权

## 可行性

⭐⭐⭐⭐ — 已有 `CTF_AGENT_ALLOW_HUMAN` 环境变量基础，工时约 3-4 天

### 改造点
1. 新增 `core/confidence.py` — 信心评估器
2. 新增 `core/autonomy_gate.py` — 自主门控
3. `core/main_agent.py` — 集成门控决策循环
4. `core/intervention.py` — 扩展现有干预机制
5. 新增 `core/human_interface.py` — 人类交互接口（CLI/Web）

## Must-run Experiments

1. **自主率**：测量不同阈值下的自主执行比例
2. **幻觉抑制**：对比有/无门控的幻觉 flag 提交率
3. **解出率影响**：对比全自主 vs 渐进式自主的解出率（不能下降）
4. **人类负担**：测量人类需要干预的频率和时间

## 参考文献

1. 本项目 `core/intervention.py` — 现有干预机制
2. 本项目 config 中 `CTF_AGENT_ALLOW_HUMAN` — 环境变量基础
3. Human-in-the-loop AI — 经典理论
4. 自主驾驶中的信心评估 — 工业实践
